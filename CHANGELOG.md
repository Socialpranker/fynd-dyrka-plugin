# Changelog

## 1.3.0 — 2026-09-03

### Added
- Six new recon checks in `scan.py`: `scan_sensitive_paths` (`.env`, swagger/
  openapi, phpinfo, server-status, `.aws/credentials`, backup files —
  classified by content, not status code), `scan_http_methods` (flags PUT/
  DELETE/TRACE/CONNECT via OPTIONS), `scan_injection_candidates` (a bounded
  same-origin crawl — depth 2, at most 20 pages, at most 10 parameterised URLs
  — with reflected-XSS marker and single-quote SQLi-signature detection;
  GET-only, a POST form is found but never auto-submitted), `scan_port_scan`
  (nmap over a curated database/admin/remote-access port list, not a full
  sweep, skipped without nmap), `scan_whois` (a raw two-hop socket lookup
  flagging a domain expiring within 30 days), `scan_virustotal_reputation`
  (skipped without `VIRUSTOTAL_API_KEY`).
- `references/social-engineering.md` — an optional human-layer reference
  (OSINT by role, 4 pretexting scenarios, a physical-security checklist,
  phishing-risk scoring), gated behind its own explicit-scope confirmation,
  separate from and stricter than the Step 4 code/service gate.
- `scanners.md` documents all six new checks, plus why `wpscan` and `hydra`
  (present in the tool inventory) are intentionally not wired into any
  scanner: CMS-specific and active credential brute-force respectively — the
  latter risks locking out accounts on the very service being reviewed.

### Changed
- The `recon` row in the Layers table, and the plugin/marketplace
  descriptions, now reflect the expanded checks. `recon` is no longer purely
  stdlib: the port-scan check optionally shells out to `nmap`, skipped (not
  an error) when it is absent — the same convention `scan_nuclei` already
  used for `nuclei`.

## 1.2.0 — 2026-09-01

First public release.

### Added
- `references/auth-crypto.md` — a new reference closing the largest coverage gap:
  CSRF and `SameSite`, session lifecycle and fixation, JWT verification failures,
  password and credential storage, CSPRNG randomness, crypto misuse and the
  config fail-open, and WebSocket authorisation.
- `injection.md` grew from 10 sinks to 12: **SQL injection** (which had no
  section of its own despite being the most classic class) and **XXE / XML
  parsing**.
- CI: the reference invariant, script and fixture compilation, manifest and eval
  JSON validation, cross-manifest version agreement, semgrep rule validation, and
  an end-to-end orchestrator run against a fixture.
- MIT licence, README, this changelog.

### Changed
- The entire plugin is now in English: `SKILL.md`, all 15 references, both
  scripts, the semgrep rule messages, the HTML report template, the evals, the
  fixtures and the manifests.
- `SKILL.md` shrank from 67,311 to 45,579 bytes through translation alone (UTF-8
  Cyrillic costs two bytes per character), well inside the 70,000-byte budget.
- The Step 3 reading order now has eight references rather than seven, with
  `auth-crypto.md` as queue 1b.

### Fixed
- `SKILL.md` had lost three references from its Extending list (`logic-flaws.md`,
  `triage.md`, `coverage-check.md`).
- The eval for swarm mode expected `DUPLICATES` while `fanout.md` specifies
  `SEEN`.
