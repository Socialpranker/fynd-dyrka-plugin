# Changelog

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
