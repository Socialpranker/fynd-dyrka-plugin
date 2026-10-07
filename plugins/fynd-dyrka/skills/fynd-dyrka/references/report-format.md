# Report format (Markdown, default)

# Security Scan — <target>

**Date:** <ISO>  ·  **Layers:** <layers>  ·  **Risk: <GRADE>**

## Summary
<2–3 lines: the main thing found, and what to do first>

| Severity | Count |
|----------|-------|
| CRITICAL | N |
| HIGH     | N |
| MEDIUM   | N |
| LOW      | N |
| UNKNOWN  | N |

`UNKNOWN` covers findings whose severity was not recognised (a scanner changed its
vocabulary, a custom rule). The row is mandatory even at N = 0; at N > 0 work
through them by hand — something critical may be sitting there.

## Critical — fix now
### [CRITICAL] <title>
- **Where:** file:line / endpoint
- **What:** the problem and how it is exploited
- **Proof:** run output (mandatory for logic findings)
  ```
  $ python3 -c "from worker.domain_guard import is_safe_url; ..."
  http://[::ffff:169.254.169.254]/ -> True    # ← should be False
  ```
- **How to fix:** a concrete step
- **Source:** manual review (Step 3) / <tool> (<identifier>)

## Attack chains
### <name>
1. step → 2. step → 3. impact
**Bottom line:** <what the attacker gets>

## Everything else (descending)
<HIGH/MEDIUM/LOW briefly, grouped. Unverified hypotheses are tagged
[UNVERIFIED] with what prevented verification>

## Filtered out as false or low
<scanner findings you downgraded, plus the reason — so the user can re-check your
triage instead of taking it on trust>

## Refuted hypotheses
<what you suspected, how you tested it, why it turned out not to be a bug — this
shows the depth of the review and saves the user re-checking the same places>

## Coverage
<what of the attack surface was reviewed, what was not and why; skipped layers and
scanners plus install commands where a tool was missing>
