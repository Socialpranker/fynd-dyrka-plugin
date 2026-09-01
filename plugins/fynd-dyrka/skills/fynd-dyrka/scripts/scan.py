#!/usr/bin/env python3
"""
fynd-dyrka security orchestrator.

Runs available security scanners across four layers and emits one unified JSON
report to stdout. Designed to degrade gracefully: a missing scanner is recorded
as "skipped", never a crash. The LLM layer (the skill) reads this JSON and does
triage, deduplication, attack-chain reasoning, and report writing on top.

Layers:
  sast       — static analysis of source (semgrep, bandit)
  secrets    — leaked credentials in the tree / git history (gitleaks)
  deps       — vulnerable dependencies / SBOM (osv-scanner, trivy fs)
  iac        — Dockerfile / IaC / container misconfig (trivy config, hadolint)
  dast       — live-target probing against a running service (nuclei)
  recon      — external recon of a live URL, no external CLI tools: exposed
               .git, secrets in prod JS, security headers / CORS, open ports &
               CVEs via Shodan InternetDB, email spoofability (SPF/DMARC)

DAST/recon safety model:
  - localhost / 127.0.0.1 / *.local / private IPs are always allowed.
  - Any other (public) target requires --authorized, else active probing is
    refused. This mirrors the authorization gate FYND_DYRKA used: you may only
    actively probe a host you are allowed to test.
  - recon splits by probe: active probes (git-exposure, js-secrets,
    security-headers) hit the target and honor the gate; passive probes
    (shodan-internetdb, email-spoofability) hit third parties / DNS, not the
    target, and run without the gate.

Usage:
  scan.py --target . --layers sast,secrets,deps,iac
  scan.py --target . --url http://localhost:3000 --layers all
  scan.py --url https://staging.example.com --authorized --layers dast,recon

Exit code is always 0 on a completed run (findings are data, not failure);
non-zero only on a usage/orchestration error, so CI can distinguish "scan
broke" from "scan found issues".
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

ALL_LAYERS = ["sast", "secrets", "deps", "iac", "dast", "recon", "platform"]

# Vendored / generated dirs we never want to scan as "your code" — they bury
# real findings under thousands of third-party ones (a bandit run over
# node_modules/venv produced ~4000 noise findings before this exclude existed).
VENDOR_DIRS = [
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".git",
    "dist",
    "build",
    ".next",
    ".cache",
    "vendor",
    "site-packages",
    ".tox",
    "coverage",
    ".mypy_cache",
    ".pytest_cache",
]


def _gitleaks_config(path: str) -> str:
    """gitleaks config that excludes vendored directories.

    WHY: `gitleaks dir` has no path-exclusion flag — only an allowlist in the
    config. Without it the layer does not merely get noisy, it SILENTLY STOPS
    WORKING: on a tree with 1 GB of node_modules the run did not fit in 300s and
    died on timeout, so no leak was returned at all. Measured on a real project:
    400s+ (timeout, 0 findings) -> 3.3s and 6 real keys.
    """
    escaped = [d.replace(".", r"\.") for d in VENDOR_DIRS if d != ".git"]
    paths = "\n".join(f"  '''(^|/){d}/'''," for d in escaped)
    body = (
        "[extend]\nuseDefault = true\n\n"
        "[[allowlists]]\n"
        'description = "vendored / generated dirs"\n'
        "targetRules = []\n"
        f"paths = [\n{paths}\n]\n"
    )
    with open(path, "w") as f:
        f.write(body)
    return path


# Severity ranked so we can sort/aggregate consistently across tools that each
# use their own vocabulary.
SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


@dataclass
class ToolResult:
    tool: str
    layer: str
    status: str  # ok | skipped | error
    reason: str = ""  # why skipped / error text
    duration_s: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_available: bool = False  # whether raw output was captured to a file


@dataclass
class ScanReport:
    target: str
    url: str | None
    layers_requested: list[str]
    started_at: str
    finished_at: str = ""
    tools: list[ToolResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def norm_severity(s: str | None) -> str:
    if not s:
        return "UNKNOWN"
    s = s.strip().upper()
    aliases = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "NOTE": "LOW",
        "MODERATE": "MEDIUM",
        "IMPORTANT": "HIGH",
        "NEGLIGIBLE": "INFO",
    }
    s = aliases.get(s, s)
    return s if s in SEVERITY_RANK else "UNKNOWN"


def finding(
    *,
    severity: str,
    title: str,
    location: str = "",
    description: str = "",
    identifier: str = "",
    tool: str = "",
) -> dict[str, Any]:
    """A normalized finding shared across every scanner."""
    return {
        "severity": norm_severity(severity),
        "title": title.strip()[:300],
        "location": location.strip()[:400],
        "identifier": identifier.strip()[:120],  # CVE / rule id / template id
        "description": description.strip()[:1000],
        "tool": tool,
    }


def run_cmd(
    cmd: list[str], timeout: int, cwd: str | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )


# --------------------------------------------------------------------------- #
# SAST
# --------------------------------------------------------------------------- #


# The custom semgrep rules live in assets/ next to the skill. Path from this
# file: scripts/scan.py -> ../assets/semgrep-rules.yml
_CUSTOM_RULES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets",
    "semgrep-rules.yml",
)


def _custom_semgrep_findings(
    target: str, timeout: int, raw_dir: str | None
) -> list[dict[str, Any]]:
    """Second semgrep pass with fynd-dyrka rules. Returns a list of findings
    (not a ToolResult): they merge into the overall semgrep result. Degrades
    softly: no rules file or a failed pass yields an empty list, and the sast
    layer is unaffected."""
    out: list[dict[str, Any]] = []
    if not os.path.exists(_CUSTOM_RULES):
        return out
    try:
        excludes = []
        for d in VENDOR_DIRS:
            excludes += ["--exclude", d]
        proc = run_cmd(
            [
                "semgrep",
                "scan",
                "--config",
                _CUSTOM_RULES,
                "--json",
                "--quiet",
                "--timeout",
                "0",
                *excludes,
                target,
            ],
            timeout=timeout,
        )
        data = json.loads(proc.stdout or "{}")
        _dump_raw(raw_dir, "semgrep-custom", proc.stdout)
        for res in data.get("results", []):
            extra = res.get("extra", {})
            meta = extra.get("metadata", {})
            cwe = meta.get("cwe", "")
            cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
            out.append(
                finding(
                    severity=extra.get("severity", "WARNING"),
                    title=extra.get("message", res.get("check_id", "fd rule")),
                    location=f"{res.get('path', '')}:{res.get('start', {}).get('line', '')}",
                    identifier=res.get("check_id", "").split(".")[-1],
                    description=str(cwe),
                    tool="semgrep-custom",
                )
            )
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return out  # the pass is not critical — the auto result is already in
    except Exception:  # noqa: BLE001
        return out
    return out


def scan_semgrep(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    r = ToolResult(tool="semgrep", layer="sast", status="skipped")
    if not have("semgrep"):
        r.reason = "semgrep not installed (brew install semgrep)"
        return r
    t0 = time.time()
    try:
        # p/auto picks rulesets by detected languages; --json for parsing.
        excludes = []
        for d in VENDOR_DIRS:
            excludes += ["--exclude", d]
        proc = run_cmd(
            [
                "semgrep",
                "scan",
                "--config",
                "auto",
                "--json",
                "--quiet",
                "--timeout",
                "0",
                *excludes,
                target,
            ],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        data = json.loads(proc.stdout or "{}")
        _dumped = _dump_raw(raw_dir, "semgrep", proc.stdout)
        r.raw_available = _dumped
        for res in data.get("results", []):
            extra = res.get("extra", {})
            r.findings.append(
                finding(
                    severity=extra.get("severity", "INFO"),
                    title=extra.get("message", res.get("check_id", "semgrep finding")),
                    location=f"{res.get('path', '')}:{res.get('start', {}).get('line', '')}",
                    identifier=res.get("check_id", ""),
                    description=extra.get("metadata", {}).get("shortlink", ""),
                    tool="semgrep",
                )
            )
        # Second pass: fynd-dyrka custom rules. Measurement showed --config
        # auto misses classes common to the Next.js/TS stack (DOM XSS through
        # dangerouslySetInnerHTML/innerHTML, NEXT_PUBLIC_ secret leakage, SQL
        # concatenation in route handlers, $queryRawUnsafe). These rules close
        # them. The pass is optional: with no rules file the auto result stands
        # and the layer does not fail.
        custom = _custom_semgrep_findings(target, timeout, raw_dir)
        r.findings.extend(custom)
        _errs = scanner_errors(data) if isinstance(locals().get("data"), dict) else []
        if _errs and not r.findings:
            r.status, r.reason = "error", "; ".join(_errs)[:300]
        else:
            if _errs:
                r.reason = "partial: " + "; ".join(_errs)[:200]
            r.status = "ok"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "could not parse semgrep JSON"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


def scan_bandit(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """Python-specific SAST; only meaningful if there's Python in the tree."""
    r = ToolResult(tool="bandit", layer="sast", status="skipped")
    if not have("bandit"):
        r.reason = "bandit not installed (pip install bandit)"
        return r
    if not _has_ext(target, {".py"}):
        r.reason = "no Python files in target"
        return r
    t0 = time.time()
    try:
        # bandit doesn't honor .gitignore; exclude vendored dirs explicitly or
        # it drowns real findings in third-party code.
        exclude_arg = ",".join(f"*/{d}/*" for d in VENDOR_DIRS)
        proc = run_cmd(
            ["bandit", "-r", target, "-f", "json", "-q", "-x", exclude_arg],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        data = json.loads(proc.stdout or "{}")
        _dumped = _dump_raw(raw_dir, "bandit", proc.stdout)
        r.raw_available = _dumped
        for res in data.get("results", []):
            r.findings.append(
                finding(
                    severity=res.get("issue_severity", "LOW"),
                    title=res.get("issue_text", "bandit finding"),
                    location=f"{res.get('filename', '')}:{res.get('line_number', '')}",
                    identifier=res.get("test_id", ""),
                    tool="bandit",
                )
            )
        _errs = scanner_errors(data) if isinstance(locals().get("data"), dict) else []
        if _errs and not r.findings:
            r.status, r.reason = "error", "; ".join(_errs)[:300]
        else:
            if _errs:
                r.reason = "partial: " + "; ".join(_errs)[:200]
            r.status = "ok"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "could not parse bandit JSON"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


def _nested_git_repos(target: str, max_depth: int = 3) -> list[str]:
    """Git repositories inside the target when the target itself is not one.

    WHY: a common layout is a project folder with the actual repository nested
    inside it (`project/service/.git`). Checking for `.git` only at the top level
    declared such a target "not a repo" and skipped the whole history: secrets
    removed from the working tree but still present in commits went unfound,
    while the layer reported `ok`.
    """
    found: list[str] = []
    base = target.rstrip("/").count("/")
    for root, dirs, _ in os.walk(target):
        if root.count("/") - base >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in VENDOR_DIRS]
        if ".git" in os.listdir(root) and os.path.isdir(os.path.join(root, ".git")):
            found.append(root)
            dirs[:] = []  # nested sub-repositories are their owner's concern
    return found


def scan_gitleaks(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    r = ToolResult(tool="gitleaks", layer="secrets", status="skipped")
    if not have("gitleaks"):
        r.reason = "gitleaks not installed (brew install gitleaks)"
        return r
    # A broken path must be an error, not an empty result: on a non-existent
    # target gitleaks prints FTL but exits 0 and writes no report — without this
    # check the layer reports `ok, findings: 0`, indistinguishable from "no
    # secrets". Exactly the silent zero the skill hunts for in other tools.
    if not os.path.exists(target):
        r.status, r.reason = "error", f"target does not exist: {target}"
        return r
    t0 = time.time()
    report_path = (
        os.path.join(raw_dir, "gitleaks.json") if raw_dir else _tmp("gitleaks.json")
    )
    is_git = os.path.isdir(os.path.join(target, ".git"))
    # 'git' mode scans history; 'dir' mode scans the working tree (non-repos).
    # IMPORTANT: dir mode does NOT read history — a secret deleted in the last
    # commit but alive in earlier ones is invisible to it. Repositories therefore
    # need both runs, not a choice between them (a repo nested inside the target
    # is not rare).
    mode = "git" if is_git else "dir"
    nested = [] if is_git else _nested_git_repos(target)
    cfg = _gitleaks_config(
        os.path.join(raw_dir, "gitleaks.toml") if raw_dir else _tmp("gitleaks.toml")
    )
    try:
        # gitleaks exits 1 when leaks are found — that's success for us.
        proc = run_cmd(
            [
                "gitleaks",
                mode,
                target,
                "-c",
                cfg,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-banner",
                "--exit-code",
                "0",
            ],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        leaks = []
        raw_text = ""
        if os.path.exists(report_path):
            with open(report_path) as f:
                raw_text = f.read()
            leaks = json.loads(raw_text or "[]") or []
        # gitleaks writes its report to a file rather than stdout — dump the file.
        r.raw_available = _dump_raw(raw_dir, "gitleaks", raw_text)
        for leak in leaks:
            r.findings.append(
                finding(
                    severity="HIGH",  # a real leaked secret is high by default
                    title=f"Secret: {leak.get('RuleID', leak.get('Description', ''))}",
                    location=f"{leak.get('File', '')}:{leak.get('StartLine', '')}",
                    identifier=leak.get("RuleID", ""),
                    description=leak.get("Description", ""),
                    tool="gitleaks",
                )
            )
        # `data` does not exist here — gitleaks writes to a file, not stdout, so
        # scanner_errors() does not apply. The failure signal is a non-zero exit
        # code under --exit-code 0 (which makes findings NOT produce a non-zero
        # code, so any !=0 means a real error rather than "secrets were found").
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            r.status, r.reason = "error", (err or f"exit {proc.returncode}")[:300]
        elif not os.path.exists(report_path):
            # Silent zero: exit 0 is not enough — no report means it did not run.
            r.status, r.reason = "error", "gitleaks produced no report file"
        else:
            r.status = "ok"

        # Second run: history of nested repositories (see _nested_git_repos).
        seen = {(f["title"], f["location"]) for f in r.findings}
        for repo in nested:
            hist_name = f"gitleaks-git-{os.path.basename(repo)}.json"
            hist = os.path.join(raw_dir, hist_name) if raw_dir else _tmp(hist_name)
            try:
                hp = run_cmd(
                    [
                        "gitleaks",
                        "git",
                        repo,
                        "-c",
                        cfg,
                        "--report-format",
                        "json",
                        "--report-path",
                        hist,
                        "--no-banner",
                        "--exit-code",
                        "0",
                    ],
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                r.reason = (r.reason + "; " if r.reason else "") + (
                    f"history scan of {repo} timed out after {timeout}s"
                )
                continue
            if hp.returncode != 0 or not os.path.exists(hist):
                r.reason = (r.reason + "; " if r.reason else "") + (
                    f"history scan of {repo} failed"
                )
                continue
            with open(hist) as f:
                htext = f.read()
            for leak in json.loads(htext or "[]") or []:
                title = f"Secret in git history: {leak.get('RuleID', '')}"
                loc = f"{repo}/{leak.get('File', '')}:{leak.get('StartLine', '')}"
                if (title, loc) in seen:
                    continue
                seen.add((title, loc))
                r.findings.append(
                    finding(
                        severity="HIGH",
                        title=title,
                        location=loc,
                        identifier=leak.get("RuleID", ""),
                        description=(
                            f"commit {str(leak.get('Commit', ''))[:12]} — "
                            "secret in history: deleting the file does NOT revoke it"
                        ),
                        tool="gitleaks",
                    )
                )
            if nested:
                r.reason = (r.reason + "; " if r.reason else "") + (
                    f"history scanned in {len(nested)} nested repo(s)"
                )
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "could not parse gitleaks report"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #


def scan_osv(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    r = ToolResult(tool="osv-scanner", layer="deps", status="skipped")
    if not have("osv-scanner"):
        r.reason = "osv-scanner not installed (brew install osv-scanner)"
        return r
    t0 = time.time()
    try:
        proc = run_cmd(
            ["osv-scanner", "scan", "--format", "json", "-r", target],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        data = json.loads(proc.stdout or "{}")
        _dumped = _dump_raw(raw_dir, "osv-scanner", proc.stdout)
        r.raw_available = _dumped
        for res in data.get("results", []):
            source = res.get("source", {}).get("path", "")
            for pkg in res.get("packages", []):
                name = pkg.get("package", {}).get("name", "")
                version = pkg.get("package", {}).get("version", "")
                for vuln in pkg.get("vulnerabilities", []):
                    sev = _osv_severity(vuln)
                    r.findings.append(
                        finding(
                            severity=sev,
                            title=f"{name}@{version}: {vuln.get('summary', vuln.get('id', ''))}",
                            location=source,
                            identifier=vuln.get("id", ""),
                            tool="osv-scanner",
                        )
                    )
        _errs = scanner_errors(data) if isinstance(locals().get("data"), dict) else []
        if _errs and not r.findings:
            r.status, r.reason = "error", "; ".join(_errs)[:300]
        else:
            if _errs:
                r.reason = "partial: " + "; ".join(_errs)[:200]
            r.status = "ok"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        # osv-scanner prints nothing / non-JSON when no lockfiles found
        r.status, r.reason = "ok", "no supported lockfiles found"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


def _osv_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        # CVSS vector or numeric; bucket by base score if present
        if isinstance(score, str) and score.replace(".", "").isdigit():
            v = float(score)
            if v >= 9:
                return "CRITICAL"
            if v >= 7:
                return "HIGH"
            if v >= 4:
                return "MEDIUM"
            return "LOW"
    db = (vuln.get("database_specific") or {}).get("severity")
    return norm_severity(db) if db else "MEDIUM"


def scan_trivy_fs(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """trivy filesystem: deps + secrets + misconfig in one pass, used as a
    second opinion on deps when osv finds nothing / isn't installed."""
    r = ToolResult(tool="trivy-fs", layer="deps", status="skipped")
    if not have("trivy"):
        r.reason = "trivy not installed (brew install trivy)"
        return r
    t0 = time.time()
    try:
        proc = run_cmd(
            [
                "trivy",
                "fs",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--quiet",
                target,
            ],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        data = json.loads(proc.stdout or "{}")
        _dumped = _dump_raw(raw_dir, "trivy-fs", proc.stdout)
        r.raw_available = _dumped
        for res in data.get("Results", []):
            where = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                r.findings.append(
                    finding(
                        severity=v.get("Severity", "UNKNOWN"),
                        title=f"{v.get('PkgName', '')}: {v.get('Title', v.get('VulnerabilityID', ''))}",
                        location=where,
                        identifier=v.get("VulnerabilityID", ""),
                        tool="trivy-fs",
                    )
                )
        _errs = scanner_errors(data) if isinstance(locals().get("data"), dict) else []
        if _errs and not r.findings:
            r.status, r.reason = "error", "; ".join(_errs)[:300]
        else:
            if _errs:
                r.reason = "partial: " + "; ".join(_errs)[:200]
            r.status = "ok"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "could not parse trivy JSON"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# --------------------------------------------------------------------------- #
# IaC / containers
# --------------------------------------------------------------------------- #


def scan_trivy_config(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    r = ToolResult(tool="trivy-config", layer="iac", status="skipped")
    if not have("trivy"):
        r.reason = "trivy not installed (brew install trivy)"
        return r
    t0 = time.time()
    try:
        proc = run_cmd(
            ["trivy", "config", "--format", "json", "--quiet", target],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        data = json.loads(proc.stdout or "{}")
        _dumped = _dump_raw(raw_dir, "trivy-config", proc.stdout)
        r.raw_available = _dumped
        for res in data.get("Results", []):
            where = res.get("Target", "")
            for m in res.get("Misconfigurations", []) or []:
                r.findings.append(
                    finding(
                        severity=m.get("Severity", "UNKNOWN"),
                        title=m.get("Title", m.get("ID", "misconfig")),
                        location=where,
                        identifier=m.get("ID", ""),
                        description=m.get("Resolution", ""),
                        tool="trivy-config",
                    )
                )
        _errs = scanner_errors(data) if isinstance(locals().get("data"), dict) else []
        if _errs and not r.findings:
            r.status, r.reason = "error", "; ".join(_errs)[:300]
        else:
            if _errs:
                r.reason = "partial: " + "; ".join(_errs)[:200]
            r.status = "ok"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "could not parse trivy JSON"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


def scan_hadolint(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    r = ToolResult(tool="hadolint", layer="iac", status="skipped")
    if not have("hadolint"):
        r.reason = "hadolint not installed (brew install hadolint)"
        return r
    dockerfiles = _find_dockerfiles(target)
    if not dockerfiles:
        r.reason = "no Dockerfile found"
        return r
    t0 = time.time()
    all_raw = []
    try:
        for df in dockerfiles:
            proc = run_cmd(["hadolint", "-f", "json", df], timeout=timeout)
            all_raw.append(proc.stdout)
            for issue in json.loads(proc.stdout or "[]"):
                r.findings.append(
                    finding(
                        severity=issue.get("level", "INFO"),
                        title=issue.get("message", "hadolint finding"),
                        location=f"{df}:{issue.get('line', '')}",
                        identifier=issue.get("code", ""),
                        tool="hadolint",
                    )
                )
        r.duration_s = round(time.time() - t0, 1)
        _dumped = _dump_raw(raw_dir, "hadolint", "\n".join(all_raw))
        r.raw_available = _dumped
        # `data` did not exist here — the branch was always empty, so there was
        # no error checking at all. hadolint: exit 1 = findings (normal), exit >1
        # = the tool itself broke.
        if proc.returncode > 1:
            err = (proc.stderr or "").strip()
            r.status, r.reason = "error", (err or f"exit {proc.returncode}")[:300]
        else:
            r.status = "ok"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "could not parse hadolint JSON"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# --------------------------------------------------------------------------- #
# DAST
# --------------------------------------------------------------------------- #


def is_local_target(url: str) -> bool:
    """localhost / loopback / private / *.local are always safe to probe."""
    host = (urlparse(url).hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.endswith(".local") or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def scan_nuclei(
    url: str, timeout: int, authorized: bool, raw_dir: str | None
) -> ToolResult:
    r = ToolResult(tool="nuclei", layer="dast", status="skipped")
    if not have("nuclei"):
        r.reason = "nuclei not installed (brew install nuclei)"
        return r
    local = is_local_target(url)
    if not local and not authorized:
        r.status = "skipped"
        r.reason = (
            f"refusing active scan of non-local target {url} without --authorized. "
            "Only scan hosts you are permitted to test."
        )
        return r
    t0 = time.time()
    out_path = (
        os.path.join(raw_dir, "nuclei.jsonl") if raw_dir else _tmp("nuclei.jsonl")
    )
    try:
        proc = run_cmd(
            [
                "nuclei",
                "-target",
                url,
                "-jsonl",
                "-o",
                out_path,
                "-silent",
                "-no-color",
                "-timeout",
                "10",
                "-rate-limit",
                "50",
            ],
            timeout=timeout,
        )
        r.duration_s = round(time.time() - t0, 1)
        # nuclei also writes to a file (JSONL) rather than stdout.
        _raw_nuclei = ""
        if os.path.exists(out_path):
            with open(out_path) as f:
                _raw_nuclei = f.read()
        r.raw_available = _dump_raw(raw_dir, "nuclei", _raw_nuclei)
        if os.path.exists(out_path):
            with open(out_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        res = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    info = res.get("info", {})
                    r.findings.append(
                        finding(
                            severity=info.get("severity", "INFO"),
                            title=info.get(
                                "name", res.get("template-id", "nuclei finding")
                            ),
                            location=res.get("matched-at", url),
                            identifier=res.get("template-id", ""),
                            description=info.get("description", ""),
                            tool="nuclei",
                        )
                    )
        # `data` did not exist here — error checking was effectively absent.
        # nuclei writes JSONL to a file; a missing file with exit code 0 is a
        # failure, not "clean": otherwise an unreachable host reads as "no
        # vulnerabilities".
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            r.status, r.reason = "error", (err or f"exit {proc.returncode}")[:300]
        elif not os.path.exists(out_path):
            r.status, r.reason = "error", "nuclei produced no output file"
        else:
            r.status = "ok"
            r.reason = "local target" if local else "authorized external target"
        _ = proc
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# --------------------------------------------------------------------------- #
# Recon (passive/active probing of a live target — no external CLI tools)
# --------------------------------------------------------------------------- #
#
# This layer covers surface that SAST/secrets/deps do not have: the live
# service from outside. Every probe is an ordinary HTTP/DNS request through the
# stdlib, with no external scanners, so the layer works on a bare machine. Active
# probes (git-exposure, js-secrets, headers) send real GETs at the target and
# therefore obey the same authorisation gate as nuclei: a local target is free, a
# public one requires --authorized. Passive probes (shodan, email-spoofability)
# hit third-party services and DNS, NOT the target, and need no gate.

import re as _re  # noqa: E402
import socket  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

_RECON_UA = "fynd-dyrka-recon/1.0"

# Ports that are dangerous when exposed (from the passive_internet engine). The
# value is a short description of the risk for the finding.
_RISKY_PORTS = {
    21: "FTP — often anonymous / cleartext",
    23: "Telnet — cleartext, obsolete",
    135: "MS RPC — internal service exposed",
    445: "SMB — internal service exposed (EternalBlue class)",
    1433: "MSSQL — database reachable from the internet",
    1521: "Oracle DB — database reachable from the internet",
    3306: "MySQL — database reachable from the internet",
    3389: "RDP — remote desktop exposed (brute force / CVE)",
    5432: "PostgreSQL — database reachable from the internet",
    5984: "CouchDB — often unauthenticated",
    6379: "Redis — unauthenticated by default, RCE class",
    9200: "Elasticsearch — often unauthenticated, data leak",
    11211: "Memcached — unauthenticated, amplification",
    27017: "MongoDB — historically unauthenticated, data leak",
}


def _http_get(
    url: str, timeout: int, max_bytes: int = 65536, origin: str | None = None
) -> tuple[int, dict, bytes]:
    """GET without following redirects. Returns (status, headers, body[:max_bytes]).

    Redirects are deliberately not followed: first, a redirect is itself a signal
    (open redirect / a private destination); second, blindly following Location
    is an SSRF pedal. status=-1 on a network error.
    """

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
            return None

    headers = {"User-Agent": _RECON_UA}
    if origin:
        headers["Origin"] = origin
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        # 3xx/4xx/5xx are valid answers here (403 on .git is a signal, not an error).
        try:
            body = e.read(max_bytes)
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, dict(e.headers or {}), body
    except Exception:  # noqa: BLE001
        return -1, {}, b""


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def scan_git_exposure(url: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """An exposed .git on a live server — sources and secrets from history.

    Classifies by CONTENT rather than status code: a custom 404 page returns 200
    with HTML, while a real `.git/config` returns 200 with `[core]`. We tell them
    apart by signature, otherwise an SPA with a catch-all route reads as exposed.
    """
    r = ToolResult(tool="git-exposure", layer="recon", status="ok")
    base = _base_url(url)
    probes = {
        "/.git/HEAD": (b"ref: refs/", "a working git HEAD"),
        "/.git/config": (b"[core]", "git config with a [core] section"),
        "/.git/index": (b"DIRC", "git index (magic DIRC)"),
        "/.git/logs/HEAD": (b"", "reflog — commit history"),
    }
    hits: dict[str, tuple[str, str]] = {}  # path -> (severity, why)
    raw_lines = []
    try:
        for path, (sig, desc) in probes.items():
            status, _hdr, body = _http_get(base + path, timeout)
            raw_lines.append(f"{status} {path} ({len(body)}b)")
            if status == 403:
                hits[path] = ("MEDIUM", f"403, but the path exists: {desc}")
                continue
            if status != 200 or not body:
                continue
            head = body.lstrip()
            html = b"<html" in body[:200].lower() or b"<!doctype" in body[:200].lower()
            if sig and sig in body[:64]:
                hits[path] = ("HIGH", f"200 + signature: {desc}")
            elif path == "/.git/logs/HEAD" and _re.match(rb"[0-9a-f]{40} ", head):
                hits[path] = ("HIGH", f"200 + reflog format: {desc}")
            elif not html:
                hits[path] = ("LOW", f"200 without HTML, possibly {desc}")
            # 200 + HTML with no signature = catch-all 404, not a finding
        if hits:
            # One finding at the highest severity, not four duplicates.
            best = max(hits.values(), key=lambda v: SEVERITY_RANK[v[0]])
            paths = ", ".join(sorted(hits))
            r.findings.append(
                finding(
                    severity=best[0],
                    title="Exposed .git on the live server",
                    location=base + "/.git/",
                    identifier="git-exposure",
                    description=f"{best[1]}. Responding: {paths}. "
                    "Pulling .git yields sources plus secrets in commit history.",
                    tool="git-exposure",
                )
            )
        _dump_raw(raw_dir, "git-exposure", "\n".join(raw_lines))
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


def scan_security_headers(url: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """Missing security headers plus reflective CORS with credentials."""
    r = ToolResult(tool="security-headers", layer="recon", status="ok")
    base = _base_url(url)
    try:
        status, hdr, _body = _http_get(base + "/", timeout)
        if status < 0:
            r.status, r.reason = "error", "target unreachable"
            return r
        h = {k.lower(): v for k, v in hdr.items()}
        checks = [
            ("strict-transport-security", "MEDIUM", "no HSTS — downgrade to HTTP"),
            ("content-security-policy", "MEDIUM", "no CSP — XSS unmitigated"),
            ("x-frame-options", "LOW", "no X-Frame-Options — clickjacking"),
            ("x-content-type-options", "LOW", "no X-Content-Type-Options"),
        ]
        for name, sev, why in checks:
            if name not in h:
                r.findings.append(
                    finding(
                        severity=sev,
                        title=f"Missing header: {name}",
                        location=base + "/",
                        identifier=f"header-{name}",
                        description=why,
                        tool="security-headers",
                    )
                )
        # CORS: does it reflect an arbitrary Origin together with credentials?
        _cs, chdr, _cb = _http_get(base + "/", timeout, origin="https://evil.example")
        ch = {k.lower(): v for k, v in chdr.items()}
        acao = ch.get("access-control-allow-origin", "")
        acac = ch.get("access-control-allow-credentials", "").lower()
        if acao == "https://evil.example" and acac == "true":
            r.findings.append(
                finding(
                    severity="HIGH",
                    title="CORS reflects an arbitrary Origin with credentials",
                    location=base + "/",
                    identifier="cors-reflect-credentials",
                    description="ACAO=<any Origin> + ACAC=true allows theft of "
                    "authenticated responses from a third-party site (T1539).",
                    tool="security-headers",
                )
            )
        elif acao == "*" and acac == "true":
            r.findings.append(
                finding(
                    severity="MEDIUM",
                    title="CORS wildcard with credentials",
                    location=base + "/",
                    identifier="cors-wildcard",
                    description="ACAO=* + ACAC=true (browsers block this, but it "
                    "signals a weak policy).",
                    tool="security-headers",
                )
            )
        _dump_raw(raw_dir, "security-headers", json.dumps(h, ensure_ascii=False))
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# Secret patterns in client-side JS. Values are masked; raw data is not stored.
_JS_SECRET_PATTERNS = [
    ("AWS access key", _re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", _re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe secret key", _re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe restricted key", _re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    ("Slack token", _re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}")),
    ("GitHub token", _re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}")),
    ("Private key block", _re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    (
        "Generic api secret",
        _re.compile(
            r"(?i)(?:api[_-]?key|secret|token)['\"]?\s*[:=]\s*"
            r"['\"][0-9a-zA-Z\-_]{24,}['\"]"
        ),
    ),
]


def _mask(s: str) -> str:
    s = s.strip()
    return s[:4] + "…" + s[-4:] if len(s) > 12 else "…"


def scan_js_secrets(url: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """Secrets in production JS bundles. A different surface from gitleaks over
    the repo: a key may never enter git yet still ship in the built frontend."""
    r = ToolResult(tool="js-secrets", layer="recon", status="ok")
    base = _base_url(url)
    try:
        status, _hdr, body = _http_get(base + "/", timeout, max_bytes=512 * 1024)
        if status < 0:
            r.status, r.reason = "error", "target unreachable"
            return r
        html = body.decode("utf-8", "replace")
        srcs = _re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
        js_urls = []
        for s in srcs[:20]:  # cap: we do not download the entire CDN
            if s.startswith("http"):
                js_urls.append(s)
            elif s.startswith("//"):
                js_urls.append(urlparse(base).scheme + ":" + s)
            else:
                js_urls.append(base + ("" if s.startswith("/") else "/") + s)
        seen: set[tuple[str, str]] = set()
        raw_lines = []
        for ju in js_urls:
            st, _h, jb = _http_get(ju, timeout, max_bytes=1024 * 1024)
            raw_lines.append(f"{st} {ju} ({len(jb)}b)")
            if st != 200 or not jb:
                continue
            text = jb.decode("utf-8", "replace")
            for name, pat in _JS_SECRET_PATTERNS:
                for m in pat.findall(text):
                    val = m if isinstance(m, str) else (m[0] if m else "")
                    key = (name, _mask(val))
                    if key in seen:
                        continue
                    seen.add(key)
                    r.findings.append(
                        finding(
                            severity="HIGH",
                            title=f"Secret in production JS: {name}",
                            location=ju,
                            identifier="js-secret",
                            description=f"{name} = {_mask(val)} in the client "
                            "bundle. Check the key's scope and whether it is live "
                            "(a whoami call to the provider).",
                            tool="js-secrets",
                        )
                    )
        _dump_raw(raw_dir, "js-secrets", "\n".join(raw_lines))
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


def scan_shodan_internetdb(url: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """Passive recon through Shodan InternetDB — open ports and CVEs by IP,
    with no request to the target itself and no API key. The request goes to
    Shodan, not to the user's service, so it does NOT require --authorized."""
    r = ToolResult(tool="shodan-internetdb", layer="recon", status="ok")
    host = (urlparse(url).hostname or "").strip()
    if not host:
        r.status, r.reason = "error", "no hostname in url"
        return r
    try:
        ip = socket.gethostbyname(host)
        if ipaddress.ip_address(ip).is_private:
            r.status, r.reason = "skipped", f"{host} resolves to private IP {ip}, skipped"
            return r
        status, _hdr, body = _http_get(f"https://internetdb.shodan.io/{ip}", timeout)
        _dump_raw(raw_dir, "shodan-internetdb", body.decode("utf-8", "replace"))
        if status == 404:
            r.reason = f"{ip}: no data in InternetDB (not indexed)"
            return r
        if status != 200:
            r.status, r.reason = "error", f"InternetDB status {status}"
            return r
        data = json.loads(body or "{}")
        ports = data.get("ports", []) or []
        cves = data.get("vulns", []) or []
        for p in ports:
            if p in _RISKY_PORTS:
                r.findings.append(
                    finding(
                        severity="MEDIUM",
                        title=f"Risky port exposed: {p}",
                        location=f"{host} ({ip}):{p}",
                        identifier=f"port-{p}",
                        description=_RISKY_PORTS[p],
                        tool="shodan-internetdb",
                    )
                )
        for cve in cves:
            r.findings.append(
                finding(
                    severity="HIGH",  # refine against the weaponized list during triage
                    title=f"Known vulnerability on the host: {cve}",
                    location=f"{host} ({ip})",
                    identifier=cve,
                    description="Shodan reports this host as vulnerable to "
                    f"{cve}. Check reachability and whether a public PoC exists "
                    "(see weaponized CVEs in SKILL.md, Step 6).",
                    tool="shodan-internetdb",
                )
            )
        if ports and not r.findings:
            r.reason = f"ports {ports}, none on the risky list"
    except socket.gaierror:
        r.status, r.reason = "error", f"does not resolve: {host}"
    except json.JSONDecodeError:
        r.status, r.reason = "error", "InternetDB returned non-JSON"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


def scan_email_spoofability(url: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """SPF/DMARC -> mail spoofing risk. Passive, DNS TXT only (through dig when
    available, otherwise skipped with a reason). A DNS query, not a target hit."""
    r = ToolResult(tool="email-spoofability", layer="recon", status="ok")
    host = (urlparse(url).hostname or "").strip()
    # the registered domain (last two labels) — SPF/DMARC live there
    domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    if not domain:
        r.status, r.reason = "error", "no domain in url"
        return r
    if not have("dig"):
        r.status, r.reason = "skipped", "dig not installed (required for DNS TXT)"
        return r
    try:

        def _txt(name: str) -> str:
            p = run_cmd(["dig", "+short", "TXT", name], timeout=min(timeout, 20))
            return p.stdout or ""

        spf_raw = _txt(domain)
        dmarc_raw = _txt(f"_dmarc.{domain}")
        _dump_raw(
            raw_dir, "email-spoofability", f"SPF:\n{spf_raw}\nDMARC:\n{dmarc_raw}"
        )
        spf = "missing"
        if "v=spf1" in spf_raw:
            if "-all" in spf_raw:
                spf = "hard"
            elif "~all" in spf_raw:
                spf = "soft"
            elif "?all" in spf_raw or "+all" in spf_raw:
                spf = "neutral"
            else:
                spf = "present-noall"
        dmarc = "missing"
        pct_partial = False
        if "v=DMARC1" in dmarc_raw:
            m = _re.search(r"p=(\w+)", dmarc_raw)
            dmarc = m.group(1).lower() if m else "none"
            pm = _re.search(r"pct=(\d+)", dmarc_raw)
            pct_partial = bool(pm and int(pm.group(1)) < 100)
        # Risk matrix (see references/playbooks.md).
        sev = None
        why = ""
        if spf == "missing" and dmarc == "missing":
            sev, why = "CRITICAL", "neither SPF nor DMARC — mail is freely spoofable"
        elif spf in ("soft", "neutral", "missing") and dmarc in ("none", "missing"):
            sev, why = "HIGH", f"weak SPF ({spf}) + DMARC {dmarc}"
        elif dmarc == "none" or pct_partial:
            sev, why = (
                "MEDIUM",
                f"SPF {spf}, DMARC p={dmarc}" + (" pct<100" if pct_partial else ""),
            )
        elif dmarc == "quarantine":
            sev, why = "LOW", f"SPF {spf}, DMARC quarantine — nearly strict"
        # p=reject plus a hard SPF is clean, no finding.
        if sev:
            r.findings.append(
                finding(
                    severity=sev,
                    title="Domain allows mail spoofing (SPF/DMARC)",
                    location=domain,
                    identifier="email-spoofability",
                    description=f"{why}. BEC and phishing 'from the company' get through.",
                    tool="email-spoofability",
                )
            )
        else:
            r.reason = f"SPF {spf}, DMARC {dmarc} — configuration is fine"
    except subprocess.TimeoutExpired:
        r.status, r.reason = "error", f"dig timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        r.status, r.reason = "error", str(e)[:300]
    return r


# --------------------------------------------------------------------------- #
# Layer: platform — production configuration of the DEPLOYED service via the CLI
#
# WHY A SEPARATE LAYER (measurement 2026-08-08): the static layers read 100% of
# the code and produced 7 findings, none of which survived triage as significant.
# Manual review produced one (initData replay). The worst issue of all — a
# production Postgres with superuser access, exposed to the internet through a TCP
# proxy, with a password matching the local .env — was found by NOTHING: no file
# in the repository carries those settings (no railway.json, no CI). The entire
# class of finding was outside the tool's field of view.
#
# The difference from the `iac` layer: that one reads Dockerfile/K8s/Terraform IN
# THE REPOSITORY, that is, a declaration of intent. Here we ask the provider about
# the ACTUAL state of the deployed service. A divergence is itself a finding.
#
# Authorisation: the layer goes through the provider's CLI (`railway`, `vercel`,
# `flyctl`), which already holds the user's login. The skill neither stores nor
# requests tokens. No CLI or no login yields status="skipped" with the install
# command, rather than a crash or a silent zero.
# --------------------------------------------------------------------------- #

# Ports whose public availability almost always means a configuration mistake:
# these are internal data stores with no reason to face the internet.
_DATASTORE_PORTS = {
    5432: "PostgreSQL",
    3306: "MySQL/MariaDB",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5672: "RabbitMQ",
    11211: "Memcached",
    9092: "Kafka",
    1433: "MSSQL",
    2379: "etcd",
}

# Variable names whose value is a secret. We compare VALUES against the local
# .env to catch "the production password is sitting on a developer laptop".
_SECRET_VAR_HINTS = (
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "DATABASE_URL",
    "CONNECTION_STRING",
    "DSN",
)

# Database roles that mean full control of the server. The application should
# connect under a restricted role, so that a compromised connection string does
# not hand over everything at once.
_SUPERUSER_ROLES = {"postgres", "root", "admin", "sa", "mysql", "sysdba"}


def _platform_skip(tool: str, reason: str) -> ToolResult:
    return ToolResult(tool=tool, layer="platform", status="skipped", reason=reason)


def _local_env_secrets(target: str) -> dict[str, str]:
    """Secret values from local .env files, for comparison against production.

    We read ONLY the values and keep them in memory: they never reach findings or
    the raw dump. The report carries the variable name and the fact of a match.
    """
    out: dict[str, str] = {}
    for name in (".env", ".env.local", ".env.production", "backend/.env", "api/.env"):
        path = os.path.join(target, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    k, v = k.strip(), v.strip().strip("'\"")
                    # Placeholders such as REPLACE_ME/changeme are not secrets,
                    # and matching on them would false-alarm on .env.example.
                    if len(v) < 8 or v.upper() in {"REPLACE_ME", "CHANGEME", "TODO"}:
                        continue
                    if any(h in k.upper() for h in _SECRET_VAR_HINTS):
                        out[k] = v
                        # The password INSIDE a connection string, separately.
                        #
                        # WHY (measurement 2026-08-08): the local DATABASE_URL
                        # holds a public host (proxy.example.net:51319) while the
                        # production variable holds an internal one
                        # (postgres.internal:5432). The password is identical but
                        # the full strings differ, so comparing whole values gave
                        # a FALSE ZERO: the check stayed silent exactly where it
                        # was supposed to fire.
                        if "://" in v:
                            try:
                                pwd = urlparse(v).password
                            except ValueError:
                                pwd = None
                            if pwd and len(pwd) >= 8:
                                out[f"{k} (password)"] = pwd
        except OSError:
            continue
    return out


def _railway_json(args: list[str], timeout: int, cwd: str | None = None) -> Any | None:
    """railway CLI with --json. None when the command did not run.

    cwd is meaningful and required: railway identifies the project from .railway in
    the CURRENT directory. Without it the layer reads the wrong project (or none),
    and silently — `railway status` outside a linked directory exits with an error,
    so the layer would return skipped on a perfectly good environment. Measured
    2026-08-08: from the project directory, 1 service; from /tmp, None.
    """
    try:
        proc = run_cmd(["railway", *args, "--json"], timeout=timeout, cwd=cwd)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def scan_railway_exposure(target: str, timeout: int, raw_dir: str | None) -> ToolResult:
    """Public network exposure of Railway services, plus privileges and secrets.

    It checks four things at once because all of them come from one API response
    and are uninformative separately: an open data-store port is dangerous exactly
    in proportion to how broad the credentials behind it are.
    """
    r = ToolResult(tool="railway-exposure", layer="platform", status="ok")
    if not have("railway"):
        return _platform_skip(
            "railway-exposure",
            "railway CLI not found. Install: npm i -g @railway/cli && railway login",
        )

    t0 = time.time()
    status = _railway_json(["status"], timeout, cwd=target)
    if status is None:
        r.duration_s = round(time.time() - t0, 1)
        return _platform_skip(
            "railway-exposure",
            "railway status failed: not logged in, or the project is not linked "
            "(`railway login`, then `railway link`)",
        )

    services = (
        status.get("services", {}).get("edges", []) if isinstance(status, dict) else []
    )
    local_secrets = _local_env_secrets(target)
    raw_chunks: list[str] = [json.dumps(status, ensure_ascii=False)]

    for edge in services:
        node = edge.get("node", {}) if isinstance(edge, dict) else {}
        svc_name = node.get("name", "?")

        variables = (
            _railway_json(["variables", "--service", svc_name], timeout, cwd=target)
            or {}
        )
        if variables:
            # We do NOT write a raw dump of the variables: those are production secrets.
            raw_chunks.append(f"service {svc_name}: {len(variables)} variables")

        tcp_domain = variables.get("RAILWAY_TCP_PROXY_DOMAIN")
        tcp_port = variables.get("RAILWAY_TCP_PROXY_PORT")
        app_port = variables.get("RAILWAY_TCP_APPLICATION_PORT")
        public_domain = variables.get("RAILWAY_PUBLIC_DOMAIN")

        # 1. A data store with a public TCP proxy.
        if tcp_domain and app_port:
            try:
                port_num = int(app_port)
            except (TypeError, ValueError):
                port_num = -1
            kind = _DATASTORE_PORTS.get(port_num)
            if kind:
                r.findings.append(
                    finding(
                        severity="HIGH",
                        title=f"{kind} of service '{svc_name}' is exposed to the public internet",
                        location=f"{tcp_domain}:{tcp_port} -> :{app_port}",
                        identifier="platform-datastore-exposed",
                        description=(
                            f"A TCP proxy makes {kind} reachable from any address. "
                            "The data store should be reachable only by the "
                            "application over the provider's private network. A "
                            "proxy is needed only for local development and should "
                            "be removed once the application is deployed."
                        ),
                        tool="railway-exposure",
                    )
                )

        # 2. An HTTP domain on a data-store service — useless and widens the surface.
        if public_domain and app_port:
            try:
                if int(app_port) in _DATASTORE_PORTS:
                    r.findings.append(
                        finding(
                            severity="MEDIUM",
                            title=(
                                f"HTTP domain on data-store service '{svc_name}' "
                                "(probably created by accident)"
                            ),
                            location=str(public_domain),
                            identifier="platform-useless-domain",
                            description=(
                                "A database does not serve HTTP. The domain achieves nothing "
                                "but adds a public endpoint and shows up in scanners "
                                "and certificate transparency logs."
                            ),
                            tool="railway-exposure",
                        )
                    )
            except (TypeError, ValueError):
                pass

        # 3. A superuser in the connection string.
        for key in ("DATABASE_URL", "PGUSER", "POSTGRES_USER", "MYSQL_USER"):
            val = variables.get(key)
            if not val:
                continue
            user = ""
            if "://" in str(val):
                try:
                    user = urlparse(str(val)).username or ""
                except ValueError:
                    user = ""
            else:
                user = str(val)
            if user.lower() in _SUPERUSER_ROLES:
                r.findings.append(
                    finding(
                        severity="HIGH",
                        title=(
                            f"The application connects to the database as superuser '{user}' "
                            f"(service '{svc_name}')"
                        ),
                        location=f"{svc_name}:{key}",
                        identifier="platform-db-superuser",
                        description=(
                            "A superuser can read and change everything, including the "
                            "schema and other databases. The application needs its "
                            "own role limited to its own tables, so that a leaked "
                            "connection string does not hand over the whole server."
                        ),
                        tool="railway-exposure",
                    )
                )
                break

        # 4. A production secret present in the local .env.
        #
        # We compare both the whole value and the password inside a connection
        # string: the host differs between dev and prod (a public proxy versus the
        # internal network), so full strings will not match even on one password.
        #
        # Deduplicate on the value itself: the provider spreads one password across
        # several variables (DATABASE_URL, PGPASSWORD, POSTGRES_PASSWORD), and
        # without this one fact yields three findings, inflating the severity table.
        reported_values: set[str] = set()
        for var_name, prod_val in variables.items():
            if not isinstance(prod_val, str) or len(prod_val) < 8:
                continue
            prod_candidates = {prod_val}
            if "://" in prod_val:
                try:
                    prod_pwd = urlparse(prod_val).password
                except ValueError:
                    prod_pwd = None
                if prod_pwd and len(prod_pwd) >= 8:
                    prod_candidates.add(prod_pwd)

            matched = False
            for local_key, local_val in local_secrets.items():
                if local_val in prod_candidates and local_val not in reported_values:
                    reported_values.add(local_val)
                    r.findings.append(
                        finding(
                            severity="HIGH",
                            title=(
                                f"Production secret {var_name} matches the local "
                                f"{local_key}"
                            ),
                            location=f"{svc_name}:{var_name} == local .env:{local_key}",
                            identifier="platform-secret-reuse",
                            description=(
                                "The same secret in production and on a developer machine: "
                                "compromising the laptop (a backup, a screenshot, a "
                                "stray `git add -f`, a shared folder) hands over "
                                "production. dev and prod need different values. The "
                                "provider may duplicate this password into other "
                                "variables — one finding per value. Secret values are "
                                "not printed in the report."
                            ),
                            tool="railway-exposure",
                        )
                    )
                    matched = True
                    break
            if matched:
                # One production variable yields at most one finding, otherwise
                # DATABASE_URL and its password duplicate the same fact.
                continue

        # 5. A connection without TLS.
        db_url = variables.get("DATABASE_URL", "")
        if isinstance(db_url, str) and db_url.startswith(
            ("postgres://", "postgresql://")
        ):
            if "sslmode=" not in db_url and tcp_domain:
                r.findings.append(
                    finding(
                        severity="MEDIUM",
                        title=f"Database connection string for '{svc_name}' has no sslmode",
                        location=f"{svc_name}:DATABASE_URL",
                        identifier="platform-db-no-tls",
                        description=(
                            "The connection crosses the public network with no explicit TLS "
                            "mode — the driver may negotiate a cleartext channel, "
                            "sending the password and data in the clear. Add "
                            "`?sslmode=require`."
                        ),
                        tool="railway-exposure",
                    )
                )

    # 6. A single environment — changes go straight to production.
    environments = _railway_json(["environment"], timeout, cwd=target)
    if isinstance(environments, list) and len(environments) == 1:
        r.findings.append(
            finding(
                severity="MEDIUM",
                title="Single environment in the project — production is not isolated from experiments",
                location=f"environment: {environments[0]}",
                identifier="platform-no-staging",
                description=(
                    "Any test of a migration or new code runs against live user "
                    "data, with nothing to roll back to."
                ),
                tool="railway-exposure",
            )
        )

    r.duration_s = round(time.time() - t0, 1)
    r.raw_available = _dump_raw(raw_dir, "railway-exposure", "\n".join(raw_chunks))
    return r


def scan_deploy_config_drift(
    target: str, timeout: int, raw_dir: str | None
) -> ToolResult:
    """Production configuration is not described in the repository, so it can be
    neither reviewed nor reproduced.

    This is not a "vulnerability" in scanner vocabulary, but it is what makes every
    other cloud finding invisible: if production state lives only in a web console,
    no diff and no code review will ever show it.
    """
    r = ToolResult(tool="deploy-config-drift", layer="platform", status="ok")
    t0 = time.time()

    deploy_configs = [
        "railway.json",
        "railway.toml",
        "vercel.json",
        "fly.toml",
        "render.yaml",
        "app.yaml",
        "Procfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "kubernetes",
        "k8s",
        ".github/workflows",
        ".gitlab-ci.yml",
    ]
    found = [c for c in deploy_configs if os.path.exists(os.path.join(target, c))]

    if not found:
        r.findings.append(
            finding(
                severity="LOW",
                title="Deploy configuration is absent from the repository",
                location=target,
                identifier="platform-config-undocumented",
                description=(
                    "No deploy-configuration or CI file was found. Production "
                    "settings exist only on the provider's side: they are invisible "
                    "to code review, cannot be rolled back with the code, and cannot "
                    "be restored if console access is lost. Such a production has to "
                    "be inspected manually through the API — which is what this layer "
                    "does."
                ),
                tool="deploy-config-drift",
            )
        )

    r.duration_s = round(time.time() - t0, 1)
    r.raw_available = _dump_raw(
        raw_dir, "deploy-config-drift", json.dumps({"found": found}, ensure_ascii=False)
    )
    return r


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _tmp(name: str) -> str:
    import tempfile

    return os.path.join(tempfile.gettempdir(), f"secscan_{os.getpid()}_{name}")


def _dump_raw(raw_dir: str | None, tool: str, content: str) -> bool:
    """Save a scanner's raw output. Returns True only when the file was actually
    written — the caller must set raw_available from this value rather than from
    the mere fact that raw_dir was passed (otherwise the agent goes off to read a
    file that does not exist, on a permissions or disk-space failure)."""
    if not raw_dir or not content:
        return False
    try:
        with open(os.path.join(raw_dir, f"{tool}.raw.json"), "w") as f:
            f.write(content)
        return True
    except OSError:
        return False


def scanner_errors(data: dict) -> list[str]:
    """Extract errors a scanner reports INSIDE its own JSON.

    WHY (measurement 2026-08-05): semgrep on a non-existent path writes
    {"errors":[{"code":2,"message":"Invalid scanning root: ..."}]} yet exits with
    code 0 and an empty "results". Reading only "results", the orchestrator set
    status="ok" with zero findings — that is, a typo in --target looked like "the
    service is clean per SAST". A silent zero is more dangerous than a crash: it is
    indistinguishable from a clean result and devalues the whole report.

    The formats differ: semgrep and bandit give a list of objects with
    message/reason, while trivy gives an error string. We take anything that looks
    like error text."""
    out: list[str] = []
    raw = data.get("errors") or []
    if isinstance(raw, str):
        raw = [raw]
    for e in raw if isinstance(raw, list) else []:
        if isinstance(e, str):
            out.append(e)
        elif isinstance(e, dict):
            msg = (
                e.get("message")
                or e.get("reason")
                or e.get("msg")
                or json.dumps(e, ensure_ascii=False)
            )
            loc = e.get("filename") or e.get("path") or ""
            out.append(f"{msg}{f' [{loc}]' if loc else ''}")
    return [s for s in (x.strip() for x in out) if s]


def changed_files(target: str, ref: str) -> tuple[list[str], str]:
    """Files changed relative to a ref, for an incremental run.

    WHY: the standard request — "I rewrote auth, check it" — does not require a
    full repository scan. A full run on a large tree eats the timeout and returns
    the same hundreds of old findings, among which the new one is invisible.

    Returns (list of absolute paths, reason-for-emptiness). An empty list with a
    non-empty reason means "narrowing failed" — the caller must fall back to a full
    scan rather than silently scan nothing: a quiet zero files is indistinguishable
    from "clean", which is the worst outcome.

    Staged, unstaged and untracked changes all count — otherwise a file just
    written and not yet added to the index falls out of the check.
    """
    if not os.path.isdir(os.path.join(target, ".git")):
        found = run_cmd(
            ["git", "-C", target, "rev-parse", "--show-toplevel"], timeout=10
        )
        if found.returncode != 0:
            return [], "not a git repository"
    try:
        # A non-existent ref must differ from "no changes": otherwise a typo in a
        # branch name reads as "all clean since the last release".
        probe = run_cmd(
            [
                "git",
                "-C",
                target,
                "rev-parse",
                "--verify",
                "--quiet",
                f"{ref}^{{commit}}",
            ],
            timeout=10,
        )
        if probe.returncode != 0:
            return [], f"ref {ref!r} does not exist"

        names: set[str] = set()
        for cmd in (
            ["git", "-C", target, "diff", "--name-only", "--diff-filter=ACMR", ref],
            [
                "git",
                "-C",
                target,
                "diff",
                "--name-only",
                "--diff-filter=ACMR",
                "--cached",
            ],
            ["git", "-C", target, "ls-files", "--others", "--exclude-standard"],
        ):
            p = run_cmd(cmd, timeout=30)
            if p.returncode == 0:
                names.update(x for x in p.stdout.splitlines() if x.strip())
        if not names:
            return [], f"no changes vs {ref}"
        paths = []
        for n in sorted(names):
            full = os.path.join(target, n)
            if not os.path.isfile(full):
                continue  # deleted files have nothing to scan
            if any(f"/{d}/" in f"/{n}/" for d in VENDOR_DIRS):
                continue
            paths.append(full)
        if not paths:
            return [], f"changed files vs {ref} are all deleted or vendored"
        return paths, ""
    except subprocess.TimeoutExpired:
        return [], "git timed out"
    except Exception as e:  # noqa: BLE001
        return [], f"git failed: {str(e)[:120]}"


def _has_ext(target: str, exts: set[str]) -> bool:
    if os.path.isfile(target):
        return os.path.splitext(target)[1] in exts
    for root, dirs, files in os.walk(target):
        dirs[:] = [
            d
            for d in dirs
            if d not in (".git", "node_modules", "venv", ".venv", "__pycache__")
        ]
        if any(os.path.splitext(fn)[1] in exts for fn in files):
            return True
    return False


def _find_dockerfiles(target: str) -> list[str]:
    found = []
    if os.path.isfile(target):
        return [target] if "dockerfile" in os.path.basename(target).lower() else []
    for root, dirs, files in os.walk(target):
        dirs[:] = [
            d for d in dirs if d not in (".git", "node_modules", "venv", ".venv")
        ]
        for fn in files:
            if fn.lower() == "dockerfile" or fn.lower().startswith("dockerfile."):
                found.append(os.path.join(root, fn))
    return found[:20]


# Registry: layer -> ordered list of scanner callables.
# Each callable takes (target_or_url, timeout, raw_dir) — dast differs, handled inline.
SAST_SCANNERS: list[Callable] = [scan_semgrep, scan_bandit]
SECRETS_SCANNERS: list[Callable] = [scan_gitleaks]
DEPS_SCANNERS: list[Callable] = [scan_osv, scan_trivy_fs]
IAC_SCANNERS: list[Callable] = [scan_trivy_config, scan_hadolint]

# Platform: the actual state of the DEPLOYED service through the provider CLI.
# Reads configuration and changes nothing. Needs no --authorized gate: the CLI
# works under the user's existing login, that is, inside their own
# infrastructure rather than against an arbitrary third-party target.
PLATFORM_SCANNERS: list[Callable] = [scan_railway_exposure, scan_deploy_config_drift]

# Recon: active probes hit the target (the same --authorized gate as nuclei),
# passive ones hit third-party services and DNS (no gate). Each is
# (url, timeout, raw_dir) -> ToolResult, like the other scanners.
RECON_ACTIVE_SCANNERS: list[Callable] = [
    scan_git_exposure,
    scan_security_headers,
    scan_js_secrets,
]
RECON_PASSIVE_SCANNERS: list[Callable] = [
    scan_shodan_internetdb,
    scan_email_spoofability,
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Unified security scan orchestrator")
    ap.add_argument("--target", default=".", help="path to source tree (default: .)")
    ap.add_argument("--url", default=None, help="live URL for dast/recon layers")
    ap.add_argument(
        "--layers",
        default="sast,secrets,deps,iac",
        help="comma list: sast,secrets,deps,iac,dast,recon,platform or 'all'",
    )
    ap.add_argument(
        "--authorized",
        action="store_true",
        help="permit active dast/recon probing against a non-local target",
    )
    ap.add_argument("--timeout", type=int, default=300, help="per-tool timeout seconds")
    ap.add_argument(
        "--raw-dir",
        default=None,
        help="directory to dump raw scanner outputs for deep dives",
    )
    ap.add_argument(
        "--diff",
        nargs="?",
        const="HEAD",
        default=None,
        metavar="REF",
        help=(
            "scan only files changed vs REF (default HEAD). Narrows sast/secrets "
            "to the changed set; deps/iac/dast need whole-project context and "
            "stay full-scope."
        ),
    )
    args = ap.parse_args()

    layers = (
        ALL_LAYERS
        if args.layers.strip() == "all"
        else [l.strip() for l in args.layers.split(",") if l.strip()]
    )
    bad = [l for l in layers if l not in ALL_LAYERS]
    if bad:
        print(f"error: unknown layer(s): {bad}. valid: {ALL_LAYERS}", file=sys.stderr)
        return 2

    if args.raw_dir:
        os.makedirs(args.raw_dir, exist_ok=True)

    target = os.path.abspath(args.target)
    report = ScanReport(
        target=target,
        url=args.url,
        layers_requested=layers,
        started_at=now_iso(),
    )

    if "dast" in layers and not args.url:
        report.notes.append("dast layer requested but no --url given; skipped")
        layers = [l for l in layers if l != "dast"]

    if "recon" in layers and not args.url:
        report.notes.append("recon layer requested but no --url given; skipped")
        layers = [ly for ly in layers if ly != "recon"]

    # Incremental mode: sast/secrets run over a slice tree of changed files.
    # deps/iac/dast stay full — a lock file, a Dockerfile and a live service are
    # only meaningful checked whole.

    # The slice is assembled as a copy in a temporary directory rather than a list
    # of paths: that way any scanner works without rewriting each one to accept N
    # paths. A copy rather than symlinks — some scanners do not follow links and
    # would return a quiet zero findings.
    narrowed_target = target
    diff_tmp: str | None = None
    if args.diff:
        files, why = changed_files(target, args.diff)
        if not files:
            # Narrowing failed — fall back honestly to a full scan and say so.
            # Scanning nothing and reporting "clean" is not acceptable.
            report.notes.append(
                f"--diff {args.diff}: {why}; fell back to full scan of {target}"
            )
        else:
            import shutil as _shutil
            import tempfile as _tempfile

            diff_tmp = _tempfile.mkdtemp(prefix="secscan_diff_")
            copied = 0
            for src in files:
                rel = os.path.relpath(src, target)
                dst = os.path.join(diff_tmp, rel)
                try:
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    _shutil.copy2(src, dst)
                    copied += 1
                except OSError:
                    continue
            if copied:
                narrowed_target = diff_tmp
                report.notes.append(
                    f"--diff {args.diff}: sast/secrets narrowed to {copied} changed "
                    f"file(s); deps/iac stay full-scope. Paths in findings are "
                    f"relative to the changed-file snapshot."
                )
            else:
                report.notes.append(
                    f"--diff {args.diff}: could not copy any changed file; "
                    f"fell back to full scan"
                )

    for layer in layers:
        if layer == "sast":
            for fn in SAST_SCANNERS:
                report.tools.append(fn(narrowed_target, args.timeout, args.raw_dir))
        elif layer == "secrets":
            for fn in SECRETS_SCANNERS:
                report.tools.append(fn(narrowed_target, args.timeout, args.raw_dir))
        elif layer == "deps":
            for fn in DEPS_SCANNERS:
                report.tools.append(fn(target, args.timeout, args.raw_dir))
        elif layer == "iac":
            for fn in IAC_SCANNERS:
                report.tools.append(fn(target, args.timeout, args.raw_dir))
        elif layer == "platform":
            # Full target, not the slice: production configuration has nothing to
            # do with the set of changed files, and the local .env used for secret
            # comparison is not part of the --diff snapshot.
            for fn in PLATFORM_SCANNERS:
                report.tools.append(fn(target, args.timeout, args.raw_dir))
        elif layer == "dast":
            report.tools.append(
                scan_nuclei(args.url, args.timeout, args.authorized, args.raw_dir)
            )
        elif layer == "recon":
            # Passive probes always run (they hit Shodan/DNS, not the target).
            for fn in RECON_PASSIVE_SCANNERS:
                report.tools.append(fn(args.url, args.timeout, args.raw_dir))
            # Active probes sit behind the same gate as nuclei.
            local = is_local_target(args.url)
            if local or args.authorized:
                for fn in RECON_ACTIVE_SCANNERS:
                    report.tools.append(fn(args.url, args.timeout, args.raw_dir))
            else:
                for fn in RECON_ACTIVE_SCANNERS:
                    report.tools.append(
                        ToolResult(
                            tool=fn.__name__.replace("scan_", ""),
                            layer="recon",
                            status="skipped",
                            reason=(
                                f"refusing active probe of non-local target "
                                f"{args.url} without --authorized"
                            ),
                        )
                    )

    # Aggregate
    counts = {k: 0 for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]}
    total = 0
    for t in report.tools:
        for f in t.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            total += 1
    counts["TOTAL"] = total
    report.summary = counts
    report.finished_at = now_iso()

    # Sort findings inside each tool by severity (worst first) for readability.
    for t in report.tools:
        t.findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 0), reverse=True)

    if diff_tmp:
        # Rewrite paths back to the real ones: the scanners saw a snapshot in a
        # temporary directory, while the user needs a path that opens in their
        # repository. Without this the finding is formally correct but useless.
        for t in report.tools:
            for f in t.findings:
                if diff_tmp in f.get("location", ""):
                    f["location"] = f["location"].replace(diff_tmp, target)

        import shutil as _shutil

        _shutil.rmtree(diff_tmp, ignore_errors=True)

    out = asdict(report)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
