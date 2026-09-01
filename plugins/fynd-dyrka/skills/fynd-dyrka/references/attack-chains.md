# Building attack chains

The skill assembles `attack_chains` by judgement — this reference gives a
deterministic rule and a starter set of templates, so chains come out consistent
instead of being lost.

## The rule (portable as written, needs no code)

1. Assign a MITRE ATT&CK ID to every finding (see `mitre-map.md`).
2. A **chain** is a set of findings where one creates a **precondition**
   (`requires`) and the others **amplify** it (`amplifiers`).
3. A chain rule fires only when **all** its `requires` are present in the current
   scan. `amplifiers` are optional: present, they add a step; absent, the rule
   still fires.
4. **Chain severity = max(component severity) + one step**, capped at CRITICAL.
   The combination is worse than the sum of its parts — that is the whole point.
5. Give each chain a one- or two-sentence narrative: **what the attacker actually
   gets** by joining these findings, not a restatement of each finding.

## Starter templates

Recognise them by substance, not only by exact ID — if findings fit a template
in meaning, apply it even when the ATT&CK ID differs slightly.

| Chain | requires | amplifiers | What the attacker gets |
|---|---|---|---|
| **credential-leak → cloud-pivot** | leaked key (T1552.001) | external access / open API (T1133, T1190) | A key in code or JS → provider access; with an AWS/GCP key plus an open DB or API, a full pivot into the cloud account |
| **subdomain-takeover → phishing** | domain takeover (T1584.001) | weak SPF/DMARC (T1566.001) | Control of a trusted subdomain plus the ability to send mail "from the company" = credible phishing from a legitimate origin |
| **exposed-git → credential-harvest** | exposed `.git` (T1213.003) | leaked key (T1552.001) | Source pulled from `.git` → secrets in commit history that are absent from the working tree |
| **weak-tls → mitm** | weak TLS (T1040) | default credentials (T1078) | Traffic interception; with default credentials, the MITM lands straight in an authenticated session |

These four are not the limit. If findings form a chain with no template — SSRF →
metadata access → temporary credentials → cloud, say — assemble it with the same
requires/amplifiers/severity+1 rule and write the narrative.

## Chain format in the report

```
### <chain name>
1. <precondition finding> → 2. <amplifier> → 3. <impact>
**Severity:** <max+1, capped at CRITICAL>
**Bottom line:** <what the attacker gets, in one sentence>
```

A chain is a first-class part of the report, not a footnote: it explains why
three "medium" findings together are a critical risk.
