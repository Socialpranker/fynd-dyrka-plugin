# Coverage self-check — Step 7

> Read this on Step 7, before the report. A coverage table and six control
> questions answered with an action, not a word.

Open `/tmp/secscan/surface.md` and **write the table out** — do not "check
mentally". A rhetorical question to yourself always gets a yes; a table does not,
as long as a cell is still empty.

| Inventory item (Step 2) | What you opened (file:lines) | Outcome |
|---|---|---|
| `POST /api/scan` | `src/app/api/scan/route.ts:40-90` | auth present, race in credits → finding #3 |
| `worker/phases/*` | — | **skipped:** ran out of context |

The outcome is one of three: a finding (with its number), clean (with what you
checked), or skipped (with why). The third is legitimate; only an empty cell is
not. The table goes into the report as the "Coverage" section.

Then the control questions — answer each with an action, not a word:

1. **Zero logic findings while the scanners returned something?** A standard sign
   that Step 3 was done formally. Go back and walk two paths deliberately: auth
   (from endpoint to permission check) and money (from request to balance write).
   Zero findings is a valid result, but only if those rows say "clean" with what
   was checked.
2. **Has every CRITICAL/HIGH been through both halves of verification?** This is
   one pass over the report, not two: a finding needs **both** proof **and** a
   survived refutation — they answer different questions.

   | Half | What to look for in the finding | If absent |
   |---|---|---|
   | Proof (Step 3, the proof rule) | a block with PoC run output | severity → MEDIUM, tag `[UNVERIFIED]` |
   | Refutation (Step 3, the falsification pass) | a line "tried X — it did not hold" | severity → MEDIUM: found but unverified |

   The rule is identical for your own findings and for scanner findings that
   landed in HIGH. Answering "yes" to both halves without opening the report is
   exactly the formalism Step 7 exists to prevent.
3. **Did you compare similar places against each other?** Name at least one group
   of same-shaped operations (money, ownership transfer, admin actions) and what
   the comparison inside it showed. "I looked at each endpoint individually"
   means the technique was not applied: divergence between neighbours is
   invisible that way.
4. **The three classes no scanner finds — is there a line for each?** Not "did I
   look at all" but specifically: **availability** (rate limiting before
   authentication, a ceiling on `limit`/batch, synchronous heavy work),
   **observability** (significant actions logged, anomaly alerting, retention),
   and **the production perimeter** (public database address, stray variables,
   debug or `/metrics` exposed). Each gets a finding, a "clean" with what was
   checked, or a "skipped" with a reason (no platform access is a legitimate
   reason). All three missing from the report means the audit covered
   confidentiality and integrity but neither availability nor investigability.
5. **Is every identifier copied from tool output or verified at the source?**
   Walk the report: every CVE/GHSA, package name, and `file:line` — where did it
   come from? "I remember" does not count: models invent CVE numbers and
   non-existent packages. If it does not check out, drop the identifier, not the
   whole finding.
6. **If there was a fan-out, where did the agents' `blind_spots` go?** Every
   wave-1 agent returns a list of what it should have read and could not. Those
   are ready-made "skipped, because" rows — move them into the coverage table. An
   unclosed `blind_spot` that never reaches the report turns fan-out into a false
   sense of completeness: there were many agents, so surely everything was seen.

⚠️ **Re-running this skill over the same code is not verification.** The same
input and the same instruction produce the same result, including the same
omissions: the second run confirms the first and manufactures a verification that
never happened. To check your own audit, change a condition rather than repeat
it: a different model, diff mode instead of full, someone else's inventory as
input, a swarm instead of waves. Agreement under a **changed** condition is the
signal.
