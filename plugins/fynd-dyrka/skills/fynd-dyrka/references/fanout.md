# Subagent fan-out — auditing a large repository in parallel

When a repository does not fit in one context, the audit is parallelised across
subagents. This file is the procedure. Read it only once you have decided fan-out
is warranted (the criterion is in SKILL.md, Step 2a).

## Contents

1. [When fan-out helps and when it hurts](#when)
2. [Architecture: two waves plus verification](#architecture)
3. [Wave 1 — discovery by lens](#wave-1)
4. [Wave 2 — chains across lenses](#wave-2)
4a. [Swarm mode — when the inventory cannot be trusted](#swarm)
5. [Verification: why not voting](#verification)
6. [Prompt templates](#templates)
7. [Limits and budget](#limits)
8. [Assembling results](#assembly)

---

<a id="when"></a>
## 1. When fan-out helps and when it hurts

**Warranted:** a repository where the Step 2 inventory produced more than about
100 entry points, or a codebase that physically cannot be read in one context
(tens of thousands of lines across the relevant modules).

> **What fan-out delivers in practice** (measurement, 2026-08-05). Two previous
> full audits by a single agent missed two things that narrow lenses found at
> once:
> - `exposure` → **a fail-open in rate limiting**: the `catch` returns
>   `{allowed:true}`, so when Redis is unavailable limits silently disappear
>   across every endpoint at once;
> - `state-money` → **a double debit in `captureHold`**, reproduced against a
>   real Postgres (balance 20 → −20 with two concurrent calls).
>
> The generalist agent **read** both places and judged them fine. The narrow lens
> got as far as error handling and transaction boundaries because it had nothing
> else to look at. That is the value: depth on one question, not breadth.

**Two modes, and choosing between them matters more than fleet size:**
partitioning by inventory (waves 1–2 below) when the Step 2 inventory can be
trusted, and a **swarm over open territory** (§4a) when it cannot, because the
repository is unfamiliar or the inventory may have missed a whole class of entry
points. Measurement: on a repository where half the surface lay outside HTTP
routes, the first mode found 1 of 5 planted bugs and the second found 5 of 5.

**Harmful** — more often than you would expect:

- **Small and medium repositories.** One agent reading the whole auth path sees
  the chain "endpoint → middleware → permission check → database query". Five
  agents reading fragments see it not at all. Fan-out buys volume at the cost of
  coherence — do not pay that price without need.
- **When one specific check is wanted.** "Look for SSRF in the worker" is one
  context's work, not a fleet's.
- **When you have no inventory — but only for lens partitioning.** Waves 1–2
  without Step 2 are five agents each guessing afresh what to look at: the
  inventory *is* their partitioning plan. This does NOT apply to swarm mode
  (§4a), which deliberately works without an inventory and hands agents territory
  rather than a slice. No inventory and no time to build one → swarm, not waves.

> A subagent starts with a **clean context**: it does not see the conversation,
> your inventory, or the files you already read. Everything it needs must be in
> its prompt. This is the main source of failed fan-outs — an agent receives
> "check auth" with no indication of where auth lives and burns half its budget
> looking.

<a id="architecture"></a>
## 2. Architecture: two waves plus verification

```
Step 2 (inventory)
      │
      ├──── Wave 1: N finder agents, one per lens ──────┐
      │     each: its own lens × its own slice of code  │
      │     output: candidates (hypotheses, NOT findings)│
      │                                                  ▼
      │                                      candidate deduplication
      │                                      (flat code, not an agent)
      │                                                  │
      ├──── Wave 2: chains across lenses ────────────────┤
      │     input: the wave 1 candidate summary          │
      │     seeks: links no single lens can see          │
      │                                                  ▼
      └──── Verification: one agent per candidate ───────┘
            input: ONLY the claim, without the author's reasoning
            task: refute it, not confirm it
            output: confirmed / refuted / untestable
                            │
                            ▼
                   Step 5 (scanners) → Step 6 (triage) → report
```

The key point: wave 1 produces **candidates**, not findings. A candidate becomes
a finding only after verification with a run.

<a id="wave-1"></a>
## 3. Wave 1 — discovery by lens

Partition **by lens** (vulnerability class), not only by file. The reason: an
agent with the "IDOR" lens and an agent with the "races" lens reading the same
file see different things. File partitioning buys volume, but every agent looks
"at everything" and finds whatever is obvious.

The base lens set — one agent per lens:

| Lens | What it looks for | Where to look (from the inventory) | Reference |
|---|---|---|---|
| `authn` | fail-open, unsafe secret comparison, check bypass | entry points plus "secrets and trust" | API2 |
| `authz` | BOLA, BOPLA, BFLA — three different bugs, see below | entry points plus database queries | API1/3/5 |
| `ssrf-inject` | SSRF, SQLi, command injection, traversal, deserialisation | "input that leaves the process" | API7 |
| `state-money` | races, double debits, TOCTOU, skipping process steps | "state and money mutations" | WSTG-BUSL |
| `exposure` | debug/demo/internal routes with no auth, missing rate limits | entry points with no auth | API4 |
| `audit` | no audit log for significant actions (STRIDE "R") | "state mutations", admin actions | STRIDE |

### The `authz` lens — three separate questions, not one

"Check for IDOR" is too vague; the agent will check only the first case. Ask
them separately:

- **BOLA** (access to someone else's object). Does the endpoint take `id` from
  the request and run `WHERE id = :id` with no `AND owner_id = :current_user`? Is
  there an ownership check, but **after** the action rather than before?
- **BOPLA** (access to someone else's *fields* on the same object). Two
  sub-cases, both commonly missed:
  - *mass assignment*: the update binds the whole incoming JSON onto the model
    with no field allowlist — a client sends `{"role":"admin"}` or
    `{"credits":9999}` and it goes through;
  - *excessive exposure*: the response serialises the whole object with no
    allowlist, leaking the password hash, internal flags, other people's fields.
- **BFLA** (access to someone else's *function*). Does the admin endpoint check
  only "logged in" rather than "logged in AND role = admin"? Compare the role
  list actually checked with the list the function should be available to.

### The `state-money` lens — add process circumvention

Beyond races, check **circumvention of workflows**: can a mandatory step of a
multi-step process be skipped? Payment → delivery without payment confirmation;
verification → a privilege without verification; draft → publication around
moderation. The tell in code: the state transition comes from the client's
request instead of being derived server-side from the previous state.

Second: **reuse limits** — a promo code, invite or trial that should fire once
with no server-side check that it did.

On a large repository, a lens is further cut by code slice: `authz × src/api/v1`,
`authz × src/api/v2`. The "lens × slice" pair is one agent's unit of work.

**Every agent's prompt must contain:**

1. Concrete file paths from the inventory — not "find auth" but "read these
   files". If the inventory degraded to module level (a repository above ~100
   entry points, see SKILL.md "Degradation on a large repository") it holds no
   paths, so the agent receives **its zone boundary**: a module or service, plus
   the requirement to build the per-endpoint list inside it first and return that
   list along with its findings. What you must not do is hand over a module name
   silently as though it were a path: the agent will spend half its budget
   working out where its zone even begins.
2. Its lens and **only** its lens — an unfocused agent returns noise.
3. A requirement to return a structured candidate list with `file:line`.
4. A prohibition on creating subagents (otherwise recursion and lost reports).
5. An explicit "no findings is a valid answer" — otherwise the agent invents one
   rather than look useless. This is a real failure mode, not a theoretical one.
6. **Permission to reach the implementation of any check** the given slice relies
   on (see below) — otherwise the agent assesses a call to `validate(x)` without
   ever opening `validate`.
7. A mandatory `blind_spots` field — what it should have read and could not.

### The slice is a starting point, not a fence

"Read ONLY these files" saves context but cuts away exactly the surface where the
bug usually lives: the check is called inside the slice and written outside it.

> **Measurement (this skill's baseline, 2026-08-16).** An endpoint in the given
> slice correctly called `validate_redirect()` and `is_internal_host()`; both
> functions were flawed (`host.endswith(allowed)` lets `evilexample.com` through;
> the internal-address check compares string prefixes) and both lived in a
> neighbouring module outside the slice. Two agents out of two **never opened**
> it — both wrote "outside my permitted zone" and returned boilerplate
> hypotheses from priors (DNS rebinding, `::ffff:`, decimal IP) instead of
> findings. Neither named the real bugs.
>
> The same effect appears in Anthropic's measurement across 15 OSS projects
> (2026-08-13): half of a coordinating swarm's findings lay **outside** the
> directories the independent agents were pointed at; the overlap between the two
> methods was 12 findings out of 266 and 21. The methods are complementary:
> partitioning searches where you point, self-direction finds where to look.

The rule: an agent **must** read the implementation of any function in its slice
that its "this is safe" verdict depends on, following imports to any depth. That
is not widening the lens — the lens is unchanged, only the reading boundary
moves. Everything else outside the slice it leaves alone and records in
`blind_spots`.

`blind_spots` feed wave 2 alongside candidates. Agents name their own coverage
gaps; in the baseline above, both wrote "requires reading `lib/urlcheck.py`" —
a ready-made address for the next wave, and losing it is not an option.

### Do not duplicate a lens for confidence

Two agents with the same lens, the same slice and the same model return the same
result — in the baseline above, two replicas matched in both the set and the
order of candidates. A second agent on the same lens does not raise reliability,
it raises the bill. Reliability comes from verification (§5); diversity comes
from a different lens, a different slice, or a different model.

<a id="wave-2"></a>
## 4. Wave 2 — chains across lenses

Any partitioning loses multi-step attacks: an IDOR with no rate limit is one
attack, but the `authz` lens sees only the first half and `exposure` only the
second.

So after wave 1 you run **one** agent (not a fleet) that receives the summary of
all candidates and looks for links:

- a leaked key plus an endpoint that accepts it;
- an open route plus an expensive operation behind it = resource exhaustion;
- an IDOR plus a missing limit = mass extraction of other users' data;
- weak validation plus a path to `subprocess`/SQL.

Wave 2's input is a compact summary (title + `file:line` + lens), not the agents'
full reports. Otherwise the context fills with exactly what we were avoiding.

<a id="swarm"></a>
## 4a. Swarm mode — when the inventory cannot be trusted

Waves 1–2 distribute agents **by inventory**: they search where you point. That
is also their ceiling — a zone the inventory missed is invisible to the entire
fan-out at once.

Swarm mode solves a different problem: agents get **no slice**, they get the
territory whole and decide where to dig themselves.

**When to switch to a swarm:** an unfamiliar repository; a suspicion the
inventory is incomplete; a pre-delivery audit where the cost of a miss exceeds
the cost of tokens. When not to: the inventory is reliable and small — a swarm
will spend its budget rediscovering what you already know.

> **Measurement 2026-08-16** (a Flask service plus `ops/` and migrations, 5
> planted bugs). Partitioning by an inventory of HTTP entry points found **1 of
> 5**. A swarm of three agents over open territory found **5 of 5**, plus a chain
> across two files (`restore_archive` unpacks an archive into the same directory
> `load_state` reads a pickle from → RCE) that all three found.

### Protocol

The forum is a `forum/` directory with one file per agent (`agent-N.md`): each
writes only its own and reads all of them. A file per agent instead of a shared
one removes the write race.

The agent's report format is also the forum file format:

```
ZONE: <what it took>
WHY: <one line, why here>
FINDINGS: a list of "claim | file:line"
MAP: every file in the territory — inspected / not inspected
NEXT: what the next agent should take, and why
```

`MAP` and `NEXT` matter more than `FINDINGS`: they turn one agent's pass into a
shared map.

**Rounds, not one parallel volley.** In the same measurement, three agents
starting simultaneously into an empty forum all three wrote "the forum is empty,
I am first" and took **the same** zone. There was no coordination — the win came
from open territory, not from the forum. The forum starts working in round two,
when it holds other agents' `ZONE` and `NEXT`: agents 4 and 5 read three reports,
both declined to duplicate, and brought findings of a different class
(permissions on the state file, an unhandled `returncode` before deleting data).

Hence the protocol: **round 1 — 2–3 agents in parallel** (dispersion comes from
different starting questions, if you choose to pose them, not from the forum);
**round 2 and on — one or two at a time, each required to read the forum**.

The round-2 prompt needs two lines, or the agent returns someone else's work in
its own words:

```
Take a zone NOBODY has taken. Repeating another agent's search is forbidden:
returning findings already recorded in the forum means the run does not count.
SEEN: how many other agents' findings you read in the forum (a number). You do
not need to confirm or dispute them — that is verification's job, not yours.
```

⚠️ `SEEN` is a read counter, **not a vote**. Asking an agent to "double-check and
confirm" other findings is wrong for two reasons at once: it will read the claim
together with the author's `WHY` and anchor on it (§5 requires the opposite — the
verifier gets the claim alone), and the result is precisely the voting that §5
declares not to be verification.

**A finding standing alone is not weakened by that.** That nobody duplicated a
finding is no argument against it: a swarm puts one agent on a zone, so there is
nobody to duplicate it. Weight comes only from the empirical gate. The inverse
rule — "two confirmed it, so it is more serious" — is voting through the back
door.

**Stopping criterion:** an agent returns an empty `FINDINGS` with a non-zero
`SEEN` — the territory is exhausted and the swarm has converged. An empty
`FINDINGS` with `SEEN` at zero means something else: the agent did not read the
forum, so restart it.

Swarm findings then go through the same verification (§5) — a swarm produces
candidates, not findings. `MAP` rows marked "not inspected" travel into the Step
7 report as "skipped" lines.

<a id="verification"></a>
## 5. Verification: why not voting

**Voting across N agents does not work.** A documented case: 80+ agents
unanimously confirmed a non-existent OpenSSL vulnerability, which one empirical
test killed. Models converge on shared training priors, not on truth; "ask five
more" amplifies agreement, not accuracy.

What does work:

1. **Role separation.** Whoever found it does not verify it. Different prompts.
2. **Context asymmetry.** The verifier receives **only the claim** —
   "`is_safe_ip` lets IPv4-mapped IPv6 through" — and the file path. The author's
   reasoning is withheld: otherwise the verifier anchors and agrees.
3. **The task is framed as refutation.** "Try to show this is NOT a bug" catches
   more than "check whether this is a bug".
4. **An empirical gate.** A "confirmed" verdict requires run output — importing
   the project's real function and calling it with attacking input. Without a
   run, `[UNVERIFIED]` at most and severity ≤ MEDIUM (the Step 3 rule).

Three verification outcomes, all legitimate: confirmed (with output) · refuted
(the hypothesis did not hold) · untestable (exactly what prevented it, and which
test the user can run).

### A PoC must have a control group

Showing that the bug reproduces is not enough — show that **the fixed variant of
the same PoC gives a different result**. Without that you do not know what you
reproduced.

A real case from a run of this skill: a double-debit PoC returned −20 (the bug is
there), but the "fixed" version returned the same −20. That means the explanation
of the cause was wrong: the debit in the PoC ran unconditionally regardless of
hold status, so changing the condition changed nothing. Until the control group
gives a **different** result, you have a reproduced symptom but not an
understood cause — and the fix will be written from your explanation.

The rule: a PoC is the vulnerable variant (expect a bad result) plus the fixed
variant (expect a good one). If they match, look for the error in the PoC, not in
the code.

<a id="templates"></a>
## 6. Prompt templates

### Wave 1 agent (discovery)

```
Work alone. Do NOT create subagents.

You are looking for vulnerabilities of class <LENS> and that class only.

Your slice is a starting point, not a fence: <paths from the inventory>
[if the inventory degraded to modules, substitute this branch for the paths:]
Your zone is <module/service>; the inventory holds no paths for it. First,
build the per-endpoint list inside the zone yourself (entry points, what calls
them, whether a permission check exists) and return it as a separate ZONE_MAP
block alongside your findings — it closes the "not expanded" line in the
inventory. Do not leave the zone, except for check implementations per the rule
below.
If a verdict of "this is safe" rests on a call to a function defined outside
your slice (a validator, a permission check, a sanitiser), you MUST open its
implementation by import and read it — to any depth, until you see the check's
own code. Assessing `validate(x)` without opening `validate` is forbidden: that
is most often where the bug is. Read nothing else outside the slice — record it
in blind_spots.

What to look for: <2–4 concrete questions from the lens table>

Return a list of CANDIDATES (hypotheses, not confirmed findings). For each:
- claim: one sentence on what exactly is broken
- location: file:line
- why: why you think it is a bug (2–3 lines)
- how_to_verify: which run would confirm it

Then return a separate blind_spots list — what you needed to read and could not
(no access, could not find it, outside the slice and not reachable by import).
Format: path or module name plus one line on which question went unanswered.
An empty blind_spots is acceptable, but only if you genuinely reached the code
of every check you relied on.

A hypothesis about a vulnerability class that is not backed by reading concrete
code ("validators like this usually break on DNS rebinding") is NOT a candidate.
Either open the code and show the line, or send the question to blind_spots.

No findings is a COMPLETE answer. Return an empty list and say what you checked.
Do not invent a finding to avoid coming back empty-handed.

Do not fix code. Do not write a report for a human. Your answer is data for
assembly.
```

### Verification agent (one per candidate)

```
Work alone. Do NOT create subagents.

CLAIM: <claim>
WHERE: <file:line>

Your task is to REFUTE this claim. It is probably wrong: the usual reasons are
that the code is unreachable, a check exists higher up the stack, the input is
impossible for an external user, or the behaviour is intentional.

Order of work:
1. Read the code at the given path and around it.
2. Write a minimal script that IMPORTS the project's real function and calls it
   with attacking input. Do not paraphrase the logic — that checks your copy,
   not the project's code.
3. Run it.

Return:
- verdict: confirmed | refuted | untestable
- evidence: verbatim run output (mandatory for confirmed)
- reason: why it was refuted, or what prevented verification
- severity: CRITICAL|HIGH|MEDIUM|LOW — above MEDIUM only with evidence

If you could not verify it, return verdict: untestable and exactly what stopped
you. "I could not check it" is not "it cannot be checked": first try standing up
the environment or mocking the dependency.
```

<a id="limits"></a>
## 7. Limits and budget

- **At most 8 agents at once.** The platform ceiling is 20, but at 20 the risk of
  hitting an unrecoverable limit error rises. 8 is the working default.
- **200 subagents per session**, nesting depth 3. Agents are explicitly forbidden
  to spawn their own — otherwise you hit the depth limit and lose reports.
- **Model per task:** discovery and verification both use the normal working
  model; economising on verification is not an option, as it is the last line
  against false findings. **The verifier runs on a different model from the
  finder.** The same model errs in similar places roughly 60% of the time: the
  prior that produced a false candidate tends to confirm it. Changing the model
  buys dispersion for free, whereas a second agent on the same model buys the
  same opinion at double the price.
- **Do not invent hierarchy in prompts.** Roles ("you are the tech lead"), an
  appointed lead agent, a chain of command — measured to make no difference at
  all. What works is splitting the question (lens, zone, territory), not splitting
  rank.
- **The price of the "reach the check's implementation" rule.** Measurement
  2026-08-17: an agent required either to show the line of code or to admit a
  `blind_spot` stands up an environment and runs code — 91–100k tokens and 6–9
  minutes, against 62k and 50 seconds for an agent that reads only its slice.
  Three times the cost; across ten lenses that is the difference between "over
  lunch" and "over an evening". The rule is worth it (0/2 versus 2/2 on real
  bugs), but budget for it in advance.
- **Budget.** Wave 1 of 5 lenses, plus wave 2, plus verification of 6 candidates
  ≈ 12 agents. On a large repository partitioned by slices the count runs into
  the dozens — estimate before launching and tell the user when the bill is
  large.

<a id="assembly"></a>
## 8. Assembling results

Deduplicate candidates with **flat code, not an agent**: key on "file + line +
class". Two agents with different lenses often point at one place — that is not
two findings.

⚠️ Deduplicate against the set of **all candidates seen**, not only confirmed
ones. Otherwise hypotheses that verification killed resurface on the next round
and the loop never converges.

**Collect `ZONE_MAP` and `blind_spots` before the report, or the inventory keeps
lying.** An agent that worked to a zone boundary returned a per-endpoint list —
write it into `surface.md` in place of the "not expanded" line; an agent that hit
something unreadable returned `blind_spots` — those go into the Step 7 coverage
table as "skipped, because" rows. Fail to carry them over and Step 7 will show
coverage that never existed.

A fan-out report contains everything a normal run's does (Step 8), plus:

- how many agents, under which lenses, and which code slices were covered;
- candidates killed by verification — in "Refuted hypotheses", with the reason;
- **what no lens covered** — the most valuable line in the report, because
  fan-out manufactures a false sense of completeness: there were many agents, so
  surely everything was seen. No: exactly what was in the inventory was seen.
