# Changelog

## 1.4.0 — 2026-09-29

First wave of the research-driven extension. Every new claim in the references is
marked **confirmed** / **assumption** / **not confirmed**, so an unverified
statement is never read as a fact.

### Added
- The `fuzz` layer (`scan_schemathesis`): property-based fuzzing of a **local**
  service from its OpenAPI spec (`-w 1 --rate-limit 10/s -n 100 -c
  not_a_server_error`, flags checked against `schemathesis run --help`, run from a
  temporary working directory, `--origin` pinned to the checked local origin).
  The gate is stricter than `dast`/`recon`: only `is_local_target(url)`, and
  `--authorized` deliberately does **not** lift the refusal. No `--url` or no spec
  is `skipped` with the reason; a schema-load failure is `error`, never `ok`.
  `fuzz` is in `ALL_LAYERS`, so `--layers all` includes it.
- `scan_zizmor` (layer `iac`): GitHub Actions workflow audit. Always `--offline`
  plus `ZIZMOR_OFFLINE=1` — zizmor otherwise goes online on its own when
  `GH_TOKEN`/`GITHUB_TOKEN` is set. Exit codes 0 and 11–14 are results; anything
  else is `error`.
- `scan_mobsfscan` (layer `sast`): only when Android (`AndroidManifest.xml` +
  `.kt`/`.java`) or iOS (`.swift`/`Info.plist`) sources exist; vendored
  directories ignored through a generated config.
- `scan_supabase_migrations` (layer `iac`, stdlib): RLS heuristics over `*.sql`
  — public tables without RLS, `USING (true)`/`WITH CHECK (true)`, `user_metadata`
  in policies, `SECURITY DEFINER` without `search_path`, views without
  `security_invoker`, with Supabase lint ids. Findings say "heuristic candidate,
  verify against the live DB". Fixtures `fixtures/supabase-rls/` (bad: 6 findings,
  clean: 0).
- `references/fuzzing.md`, `references/mobile.md`,
  `references/baas-and-artifacts.md`, each with a reading-queue entry in Step 3.
- `references/agentic.md` §2a: OWASP MCP Top 10 (beta) items MCP01/02/07/09 and the
  MCP specification's security requirements (token passthrough and audience,
  confused deputy in an OAuth proxy, exact `redirect_uri`, scope minimisation, the
  start command of a local server). The "OWASP Top 10 for Agentic Applications
  2026" citation now says its existence was not verified.
- The proof rule in Step 3 gained **ORACLE**: a PoC needs an oracle tied to the
  sink plus a negative control; "it ran and crashed" is not proof (PoC-Gym,
  arxiv 2602.04165: 116 candidates passed runtime validation, 65 passed post-hoc).
- `references/scanners.md` documents zizmor (including the `GH_TOKEN` trap),
  mobsfscan, schemathesis, and apkleaks / lockfile-lint / poutine as recommended
  but not wired in.

### Changed
- `run_cmd` accepts an optional `env` (added to the inherited environment).
- The Step 3 reading order now has eleven references; Step 2 gained a
  "Mobile app / SDK" row.
- `--layers all` now includes `fuzz`, which writes to a local `--url` target;
  documented in `--help`, `SKILL.md` and `scanners.md`.

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
