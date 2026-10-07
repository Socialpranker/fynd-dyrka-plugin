# fynd-dyrka scanners

The orchestrator `scripts/scan.py` drives external CLI scanners. None is
mandatory — a missing one is marked `skipped`. This file covers what each does,
how to install it, and how to add another.

## By layer

### SAST (static analysis of code)

| Scanner | What | Install | Languages |
|---|---|---|---|
| **semgrep** | Semantic pattern matching; `--config auto` picks rules by language. The primary SAST engine. | `brew install semgrep` / `pip install semgrep` | 30+ |
| **bandit** | Python-specific issues (eval, pickle, weak crypto, hardcoded secrets). Runs only when the tree contains `.py`. | `pip install bandit` | Python |
| **mobsfscan** | Static scan of mobile sources: Java, Kotlin, Android XML, iOS `Info.plist`, Swift, Objective-C (semgrep + libsast, MobSF rules; LGPL-3.0). Runs only when Android (`AndroidManifest.xml` + `.kt`/`.java`) or iOS (`.swift` / `Info.plist`) sources exist. Static only — runtime storage, traffic and pinning need manual dynamic testing (`references/mobile.md`). | `pip install mobsfscan` | Java, Kotlin, Swift, Obj-C |

`scan.py` runs `mobsfscan --json --no-fail -c <config>`: `--no-fail` so that a
non-zero exit means the tool broke rather than "issues found"; the config ignores
the vendored directories (mobsfscan scans `node_modules` otherwise); a missing
path is turned into `error` (mobsfscan itself exits 0 with an empty result).
Absence-type rules (no pinning, no root detection) come back as INFO with no file.

### secrets

| Scanner | What | Install |
|---|---|---|
| **gitleaks** | Leaked keys and tokens. In a git repository it scans **the whole history** (`git` mode), otherwise the working tree (`dir` mode). Regex plus entropy. | `brew install gitleaks` |

Optionally add **trufflehog** (AGPL-3.0), which can *verify* a discovered
credential with a live API call (fewer false positives). That call leaves your
machine with the found credential — an **external effect** — so it is not wired in
by default and should not be pointed at someone else's images or repositories
without the owner's consent. Where it fits (Docker layers, source-map extractions)
is in `references/baas-and-artifacts.md`.

### deps (vulnerable dependencies)

| Scanner | What | Install |
|---|---|---|
| **osv-scanner** | Matches lock files against the OSV database (Google). Multi-ecosystem: npm, pip, cargo, go, maven… | `brew install osv-scanner` |
| **trivy fs** | A second opinion on dependencies, and it also handles secrets and misconfigurations. | `brew install trivy` |

osv is more precise on versions (fewer false positives), trivy is broader. Both
run in the layer — CVE deduplication happens during triage.

### iac (containers / infrastructure as code)

| Scanner | What | Install |
|---|---|---|
| **trivy config** | Dockerfile, Kubernetes, Terraform misconfigurations against built-in rules. | `brew install trivy` |
| **hadolint** | Dockerfile linter (best practices, unsafe instructions). Runs on every Dockerfile found. | `brew install hadolint` |
| **zizmor** | Audits GitHub Actions workflows (`.github/workflows/*.yml`): template injection, dangerous triggers, excessive permissions, unpinned actions, credential persistence. MIT. | `pip install zizmor` / `pipx install zizmor` / `uv tool install zizmor` / `brew install zizmor` |
| **supabase-migrations** | Built into `scan.py`, stdlib only. Heuristics over `*.sql` under `migrations/` or `supabase/`: public tables without RLS, `USING (true)` policies, `user_metadata` in policies, `SECURITY DEFINER` without `search_path`, views without `security_invoker`. Candidates to verify against the live DB (`references/baas-and-artifacts.md`). | nothing to install |

**zizmor and the `GH_TOKEN` trap.** zizmor switches to online audits **by itself**
when `GH_TOKEN`, `GITHUB_TOKEN` or `ZIZMOR_GITHUB_TOKEN` is in the environment —
and a developer machine or CI job usually has one. Then the run needs the network
and the token, and can fail: observed here, with a bogus `GH_TOKEN` and no
`--offline`, zizmor exited with `'ref-confusion' audit failed … request error
while accessing GitHub API`. `scan.py` therefore **always** passes `--offline`
**and** sets `ZIZMOR_OFFLINE=1`. The price: four to five online-only audits
(`impostor-commit`, `known-vulnerable-actions`, `ref-confusion`,
`stale-action-refs`; `typosquat-uses` runs offline at lower confidence) do not run,
and the layer says so in its `reason`. Exit codes: 0 = clean, 11–14 = findings by
severity, anything else (1, 3) = zizmor failed → `error`, not `ok`. Personas
(`regular` by default, `pedantic`, `auditor`) change how much `template-injection`
reports; the layer uses the default.

### dast (active probing of a live service)

| Scanner | What | Install |
|---|---|---|
| **nuclei** | Template-based: sends real HTTP requests at the target and matches responses. CVEs, misconfigurations, exposure. | `brew install nuclei` |

**Only against a running service.** The authorisation gate lives in `scan.py`
(`is_local_target` + `--authorized`): localhost and private IPs are free, public
domains require the explicit flag.

For heavier DAST there is **OWASP ZAP** (`brew install --cask zap`): it crawls
the application and runs an active scan with broader coverage than nuclei, but
slower and requiring setup. Not wired in by default; add it as `scan_zap`
modelled on `scan_nuclei` if you need a full web scan that walks forms and
sessions.

### fuzz (property-based API testing — local targets only)

| Scanner | What | Install |
|---|---|---|
| **schemathesis** | Generates requests from an OpenAPI spec and flags 5xx on generated input (`not_a_server_error`). MIT. | `uv tool install schemathesis` / `pip install schemathesis` |

`scan.py --url http://127.0.0.1:8000 --layers fuzz` runs `schemathesis run <spec>
--origin <origin> -w 1 --rate-limit 10/s -n 100 -c not_a_server_error
--request-timeout 10 --report json` (flags checked against `schemathesis run
--help`, v4.28.0) in a temporary working directory. **The gate is stricter than
dast/recon: only `is_local_target(url)`; `--authorized` does not lift it** — the
layer returns `skipped` with an explicit refusal, because fuzzing writes data and
can take a service down. No `--url` or no spec at a common path → `skipped` with
the reason. `--layers all` includes `fuzz`, so it will fuzz a local `--url`: use a
disposable instance. Method, what it did and did not find, and the safe-run rules:
`references/fuzzing.md`.

### Recommended, not wired in

| Tool | Facts | Install |
|---|---|---|
| **apkleaks** | APK → URIs, endpoints, secrets via jadx + regex; Apache-2.0; needs jadx (its licence/install not confirmed) | `pip3 install apkleaks`; `apkleaks -f app.apk` |
| **lockfile-lint** | lock-file integrity: allowed hosts, https, integrity hashes, name vs resolved-URL mismatch; npm and yarn (for pnpm the README says the tarball-substitution vector is absent); Apache-2.0; offline use not confirmed | `npx lockfile-lint --path yarn.lock --allowed-hosts npm yarn --validate-https` |
| **poutine** | CI/CD pipeline analysis: GitHub Actions, GitLab CI, Azure DevOps, Tekton; Apache-2.0; `analyze_local .` needs no token; rules include `unpinnable_action`, `pr_runs_on_self_hosted`, `github_action_from_unverified_creator_used`, `if_always_true`, `debug_enabled` | `brew install poutine`, Docker, or build from source (Go) |

### recon (external reconnaissance of a live URL, no external CLI)

A pure-stdlib layer — it works on a bare machine with nothing to install. Probes:

| Probe | What | Type | Gated |
|---|---|---|---|
| **git-exposure** | `/.git/HEAD\|config\|index\|logs/HEAD`, classified by content signature rather than status code | active | yes |
| **security-headers** | HSTS/CSP/X-Frame/X-Content-Type plus reflective CORS with credentials | active | yes |
| **js-secrets** | secrets in production JS bundles (AWS/Stripe/Slack/GitHub/private keys); values are masked | active | yes |
| **injection-candidates** | crawls the same-origin GET surface (depth 2, ≤20 pages, ≤10 parameterised URLs) and flags a reflected HTML-metacharacter marker (XSS candidate) or a trailing quote that trips a DB error signature (SQLi candidate); POST forms are discovered but never submitted | active | yes |
| **port-scan** | `nmap` over a curated list of database/admin/remote-access ports — not a full 0–65535 sweep, that's a dedicated tool's job | active | yes |
| **sensitive-paths** | `.env`/`.env.local`, swagger/openapi (JSON + UI), `phpinfo.php`, `server-status`, `.aws/credentials`, `wp-config.php.bak`/`config.php.bak`, `.DS_Store` — classified by a content signature per path, not status code, so an SPA catch-all doesn't read as "found" | active | yes |
| **http-methods** | `OPTIONS` on the base URL; flags `PUT`/`DELETE`/`TRACE`/`CONNECT` in the `Allow` header as worth a manual authorization check | active | yes |
| **shodan-internetdb** | open ports and known CVEs by IP via `internetdb.shodan.io` (no key needed) | passive | no |
| **email-spoofability** | SPF/DMARC → mail spoofing risk (requires `dig`) | passive | no |
| **whois** | domain registration expiry via raw WHOIS (port 43): IANA referral → registry lookup; flags an expiry under 30 days out | passive | no |
| **virustotal** | domain reputation via the VirusTotal API — vendor `malicious`/`suspicious` verdict counts; skipped without `VIRUSTOTAL_API_KEY` | passive | no |

**Active vs passive.** Active probes send GETs (or, for `http-methods`, an
`OPTIONS`) to **the target** → the same gate as nuclei (localhost free, public
domain only with `--authorized`). Passive probes hit a third party — Shodan,
DNS, IANA and the domain's own registry, VirusTotal — never the target, so they
need no gate. Three probes are opt-in on tooling or credentials rather than
guaranteed to run, and all three skip rather than error when it's missing:
`email-spoofability` needs `dig` (`brew install bind`; already present on
macOS), `port-scan` needs `nmap`, `virustotal` needs a `VIRUSTOTAL_API_KEY`
environment variable.

Extensions to this layer that are deliberately NOT wired in (heavy external
tools): subdomain enumeration (`subfinder`/`amass`) with a wildcard-DNS filter,
and JS fetching through a full crawler (`katana`). Add them modelled on the
existing probes.

Two tools from a typical offensive-tooling inventory are deliberately left
unimplemented, not merely deferred. **wpscan** is CMS-specific (WordPress) and
has nothing to check against a service that isn't running WordPress — it
doesn't generalize the way the probes above do. **hydra** is active credential
brute-forcing: pointed at your own service it risks locking out real accounts
or triggering a DoS, i.e. the scan itself becomes the incident. Neither is a
"model it on the existing probes" candidate the way subfinder or katana are —
they're excluded by design, not by priority.

## Install everything at once

```bash
brew install semgrep gitleaks osv-scanner trivy hadolint nuclei
pip install bandit
```

Optional, added in 1.4.0 (each is skipped, not an error, when absent):

```bash
pip install zizmor mobsfscan schemathesis
```

## Adding a scanner to the orchestrator

1. Write `scan_<tool>(target, timeout, raw_dir) -> ToolResult` modelled on the
   existing ones: check `have("<tool>")`, run it through `run_cmd`, parse the
   output, add findings via `finding(...)` (which normalises severity and trims
   fields), return a `ToolResult`.
2. Register it in the right list: `SAST_SCANNERS` / `SECRETS_SCANNERS` /
   `DEPS_SCANNERS` / `IAC_SCANNERS`; for recon, `RECON_ACTIVE_SCANNERS` (hits the
   target, gated) or `RECON_PASSIVE_SCANNERS` (hits a third-party service or DNS,
   ungated); for fuzz, `FUZZ_SCANNERS` (takes `(url, timeout, raw_dir)` and must
   do its own local-only gating). DAST is handled inline in `main` because of the
   gate.
3. `run_cmd(..., env={...})` adds variables to the inherited environment (used to
   pin `ZIZMOR_OFFLINE=1`). A tool that writes to a working directory gets its own
   temporary `cwd`.
4. Always catch `TimeoutExpired` and `JSONDecodeError` separately — they are the
   most common scanner failures, and neither should bring down the run.

The key invariant: **a scanner that crashes or is missing never fails the scan** —
it only marks its own `status`. That way "check the security of this" on a bare
machine still yields a partial result rather than an error.
