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

### secrets

| Scanner | What | Install |
|---|---|---|
| **gitleaks** | Leaked keys and tokens. In a git repository it scans **the whole history** (`git` mode), otherwise the working tree (`dir` mode). Regex plus entropy. | `brew install gitleaks` |

Optionally add **trufflehog**, which can *verify* a discovered credential with a
live API call (fewer false positives). Not wired in by default.

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

## Adding a scanner to the orchestrator

1. Write `scan_<tool>(target, timeout, raw_dir) -> ToolResult` modelled on the
   existing ones: check `have("<tool>")`, run it through `run_cmd`, parse the
   output, add findings via `finding(...)` (which normalises severity and trims
   fields), return a `ToolResult`.
2. Register it in the right list: `SAST_SCANNERS` / `SECRETS_SCANNERS` /
   `DEPS_SCANNERS` / `IAC_SCANNERS`; for recon, `RECON_ACTIVE_SCANNERS` (hits the
   target, gated) or `RECON_PASSIVE_SCANNERS` (hits a third-party service or DNS,
   ungated). DAST is handled inline in `main` because of the gate.
3. Always catch `TimeoutExpired` and `JSONDecodeError` separately — they are the
   most common scanner failures, and neither should bring down the run.

The key invariant: **a scanner that crashes or is missing never fails the scan** —
it only marks its own `status`. That way "check the security of this" on a bare
machine still yields a partial result rather than an error.
