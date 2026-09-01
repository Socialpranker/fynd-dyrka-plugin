# Triaging scanner findings — Step 6

> Read this on Step 6, after the orchestrator run. The order of questions to ask
> a finding, the deduplication and identifier traps, and a deterministic rule for
> contextual severity.

Walk `tools[].findings` and decide, for each finding that matters:

⚠️ If you ran `platform` separately on Step 2 you have **two** JSON documents,
not one. Take `tools[]` from both: production findings (a public storage address,
a superuser in the connection string, a production secret matching the local
`.env`) come only from the first and are absent from the Step 5 output.

1. **Is it real?** gitleaks hitting `tests/fixtures/sample.js` or `demo/…` is
   almost always a test stub, not a leak. A semgrep pattern in dead code ranks
   lower. Mark such items false or low **with the reason**, never silently.
2. **Is it reachable?** A vulnerability in a dependency that is never called, or
   an endpoint behind authentication — lower it. Do not drop severity
   arbitrarily: justify it.

   ⚠️ **Ask separately: is this even a project dependency, or someone else's
   binary inside `node_modules`?** Scanners that read binary artefacts (grype,
   trivy fs) look **inside** compiled tools and report vulnerabilities in their
   runtime rather than in your code. Measurement on a JS project: grype returned
   56 findings, every one of them `stdlib go1.20.12` inside the `esbuild` binary
   under `node_modules/vite/`, in a project containing no Go at all; it found zero
   npm vulnerabilities, while osv-scanner on the same tree found 5 real ones
   (vite, vitest, esbuild as npm packages). The tell for this class of noise: the
   artefact type does not match the project's stack, the path leads into
   `node_modules`/`vendor`/`bin`, and the vulnerability is in another language's
   standard library. Filter them out in bulk with a one-line reason — but **first
   check whether that binary ships into the production image** (a build-time dev
   dependency does not; a tool copied into the final Dockerfile layer does, and
   then the finding is real).
3. **Is it part of a chain?** Fold scanner findings AND your manual findings from
   Step 3 into chains: a leaked key plus an open admin endpoint plus no rate
   limiting is an attack worse than the sum of its parts. Build `attack_chains`
   explicitly using the `requires`/`amplifiers`/`severity+1` rule from
   **`references/attack-chains.md`** (which also carries four ready templates:
   credential-leak→cloud-pivot, subdomain-takeover→phishing,
   exposed-git→credential-harvest, weak-tls→mitm). A chain is not a footnote but
   a first-class part of the report.
4. **Deduplication.** ⚠️ osv-scanner emits `GHSA-…`/`OSV-…`, trivy-fs emits
   `CVE-…`: **one vulnerability under different identifiers**, which string
   comparison will not merge. Deduplicate on "package + version + bug class" and
   list both identifiers (`GHSA-xxx / CVE-yyy`). semgrep and bandit frequently
   report the same location.
5. **Scanner silence is not an argument.** If a scanner says nothing where you
   found a hole by hand, that is expected: logic bugs are structurally out of its
   reach. Do not lower your finding because "nothing confirmed it".
6. **Scanner noise is not an argument either.** The symmetric rule: a fired rule
   is a candidate, not a fact. For a baseline, bare semgrep on the OWASP Benchmark
   yields roughly 39% false positives at 80% true positives — every third or
   fourth finding is wrong before your triage begins. So a scanner finding you
   intend to carry into CRITICAL/HIGH goes through the Step 3 falsification pass
   exactly like your own: open the code, check reachability, try to refute it. Do
   not copy the scanner's `message` into the report as a conclusion — it is its
   hypothesis, not your verification.
7. **Assign a MITRE ATT&CK ID** to every finding that matters, using
   **`references/mitre-map.md`** (type/template → keyword → class default). It is
   the standard report vocabulary that scanners do not provide and that clients
   and compliance expect.

**Contextual severity (a deterministic rule, not a feel).** Adjust the base
severity in steps (INFO=1…CRITICAL=5, clamped to 1–5). ⚠️ The `[UNVERIFIED]` cap
is applied **last and overrides the result**: a finding without a reproducing run
stays MEDIUM no matter how many pluses the steps awarded. An unconfirmed IDOR on
`/checkout` is MEDIUM `[UNVERIFIED]`, not HIGH:
- **a WAF in front of the target** → −1 (exploitation is harder);
- **a sensitive endpoint** (`/admin`, `/checkout`, `/payment`, `/login`,
  `/oauth`) → +1;
- **a public weaponised PoC** → +1. The list that escalates automatically on
  sight: `CVE-2021-44228`/`45046` (Log4Shell), `CVE-2017-5638` (Struts2),
  `CVE-2014-0160` (Heartbleed), `CVE-2017-0144` (EternalBlue), `CVE-2019-19781`
  (Citrix), `CVE-2020-1472` (Zerologon), `CVE-2021-26855`… (ProxyLogon),
  `CVE-2022-22965` (Spring4Shell), `CVE-2023-23397` (Outlook), `CVE-2024-3400`
  (Palo Alto); plus the phrases "exploit available / public PoC / metasploit".

Final priority: a real leaked working secret, RCE or injection in reachable code,
and a **reproduced** SSRF or auth bypass are CRITICAL. A vulnerable production
dependency with an exploit, broken auth, and IDOR are HIGH. Missing security
headers, a weak misconfiguration, and a race with no demonstrated monetary damage
are MEDIUM/LOW. Do not inflate severity for drama, and do not mute something real
to keep the report clean.
