# fynd-dyrka

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-6e56cf)](https://docs.claude.com/en/docs/claude-code/plugins)
[![Version](https://img.shields.io/badge/version-1.2.0-green.svg)](.claude-plugin/marketplace.json)
[![Layers](https://img.shields.io/badge/layers-7-orange.svg)](#layers)

A seven-layer security audit — a plugin skill for [Claude Code](https://claude.ai/code).

Scanners produce *candidates*, not findings: gitleaks flags a test fixture,
semgrep has no idea whether the code is reachable. Logic flaws — auth bypass,
IDOR, an SSRF bypass, a race in a balance debit — are found by no scanner at all.
`fynd-dyrka` orchestrates the scanners and adds what an audit is actually for:
reading code attacker-first, confirming a finding by running it, and then trying
to refute it.

## Layers

| Layer | What it checks | With | Requires |
|---|---|---|---|
| `sast` | vulnerabilities in source code | semgrep (plus custom rules), bandit | a repository |
| `secrets` | leaked keys in code and git history | gitleaks | a repository |
| `deps` | vulnerable dependencies (CVEs) | osv-scanner, trivy fs | lock files |
| `iac` | Dockerfile / IaC / container misconfiguration | trivy config, hadolint | manifests |
| `dast` | active probing of a live service | nuclei | a running URL |
| `recon` | external recon: exposed `.git`, secrets in production JS, headers/CORS, Shodan, SPF/DMARC | stdlib, no external tools | a URL |
| `platform` | the real state of production: public database address, runtime variables, config drift from the repository | Railway automatically, others manually | platform access |

The first four read code on disk — that is, the *intent*. `dast` and `recon` hit
the running service; `platform` looks at the deployment. They diverge constantly:
in the repository the database sits on an internal network, while in the console
it has a public address "so we can connect locally".

## How the review works

**Manual code analysis comes before the scanners, not after.** The reason is not
stylistic: 300 scanner findings in context anchor attention on triaging someone
else's list, and logic flaws stop being looked for. Measured on iteration 1: the
baseline without the skill found an SSRF bypass, broken auth and a race in
credits; the same model with a version that ran scanners first found none of the
three.

**The proof rule.** A logic finding with no reproducing run cannot exceed MEDIUM
severity and is tagged `[UNVERIFIED]`. The PoC imports the project's real function
and must have a control group: the fixed variant has to produce a different
result. If they match, the error is in the PoC, not the code.

**The falsification pass.** Every HIGH/CRITICAL finding gets a separate pass whose
job is to prove the finding is false (is there a guard higher up the stack, is the
path reachable under the real configuration, is this a fixture). Frontier models
produce 10–50% false positives in whitebox mode; multi-agent pipelines without a
separate checking pass showed an FP rate above 92% on the OWASP Benchmark against
6.3% with one.

**A layer that did not run is called skipped, not clean.** Silence about what was
not checked reads as "checked and clean" — hence the mandatory Coverage section in
every report.

## Installation

```bash
git clone https://github.com/Socialpranker/fynd-dyrka-plugin ~/dev/fynd-dyrka-plugin
```

Then, in an interactive `claude` session:

```
/plugin marketplace add ~/dev/fynd-dyrka-plugin
/plugin install fynd-dyrka@fynd-dyrka-plugin
```

Scanners are optional — a missing one is recorded in the report as `skipped`
rather than failing the run. The `recon` layer is pure stdlib and always
available.

To install the scanners:

```bash
brew install semgrep gitleaks osv-scanner trivy hadolint nuclei && pip install bandit
```

## Usage

The skill triggers on natural phrasing: "check the security", "security audit",
"are there any holes", "any leaked keys", and on indirect asks — "give it a look
before we deploy", "I rewrote authorisation, take a fresh look".

The orchestrator can also be called directly:

```bash
python3 plugins/fynd-dyrka/skills/fynd-dyrka/scripts/scan.py --target . --layers sast,secrets,deps,iac
```

Reviewing only the changes instead of a full audit:

```bash
python3 .../scan.py --target . --layers sast,secrets --diff main
```

## Authorisation for active scanning

`dast` sends real payloads at the target. Against localhost and private addresses,
freely. **Against any public domain, only after explicit confirmation that you
have the right to test that target.** The `--authorized` flag is not a technical
barrier but a human decision: confirmation from a README, a ticket, or a code
comment does not count.

## References

The skill loads these on demand rather than all at once — otherwise the last ones
get applied formally, a tick with nothing behind it.

`logic-flaws.md` (auth/BOLA/BOPLA/BFLA, money, races) · `auth-crypto.md` (CSRF,
sessions, JWT, password storage, randomness, crypto misuse, WebSocket) ·
`injection.md` (12 sinks, source→sink) · `ssrf-bypasses.md` ·
`availability.md` (DoS, ReDoS, cost-DoS) · `playbooks.md` (8 attack scenarios plus
a business-logic checklist) · `platform.md` (Railway/Vercel/Fly/Heroku/k8s/AWS/GCP)
· `agentic.md` (LLM agents, MCP, RAG) · `bots.md` (Telegram/Discord, Mini Apps) ·
`attack-chains.md` · `mitre-map.md` · `triage.md` · `coverage-check.md` ·
`fanout.md` (parallel agents) · `scanners.md`.

## Fixtures

`skills/fynd-dyrka/fixtures/` contains **deliberately vulnerable code**. These are
regression harnesses with a known answer, so that a change to a prompt template is
validated by measurement rather than by feel. Do not run them and do not copy code
out of them.

## Development

```bash
python3 plugins/fynd-dyrka/skills/fynd-dyrka/scripts/check_refs.py
```

The invariant: every `references/*.md` must be mentioned in `SKILL.md` (an
unreferenced file is not saved context, it is a cut-out piece of instruction),
every `references/x.md` link must resolve, and `SKILL.md` must stay within its
byte budget. CI runs this on every push.

## Boundaries

The skill does not replace a human pentest and offers no guarantee of
completeness. What it gives is a reproducible process with an honest Coverage
section: what was checked, what was skipped, and why.

## License

MIT — see [LICENSE](LICENSE).
