# Fixtures — regression harnesses for fan-out prompts

Subject repositories with a known answer. They exist so that a change to a prompt
template is validated by measurement rather than by feel. Each fixture answers one
question.

⚠️ **The code in these fixtures is deliberately vulnerable.** Do not run it and do
not copy from it.

To run: copy the prompt template from `references/fanout.md`, substitute the
fixture path, run **two replicas** (a single one lies about reproducibility), and
compare with the table below. Run replicas on your working model — on another
model the numbers will differ.

## `slice-not-fence/` — does the agent leave the boundary of its slice?

The agent's slice: `app/api/routes.py`. The endpoints call the checks correctly;
both holes are in `app/lib/urlcheck.py`, outside the slice.

| What it should find | Where |
|---|---|
| `host.endswith(allowed)` lets `evilexample.com` through | `app/lib/urlcheck.py` |
| a list of string prefixes misses `localhost`, `::1`, `172.16/12`, decimal IP | `app/lib/urlcheck.py` |
| `requests.get` without `allow_redirects=False` | `app/api/routes.py` |

**Failure:** the agent stays in the given file, writes "outside my permitted zone",
and returns boilerplate hypotheses (DNS rebinding, `::ffff:`) with no line of code.

Measurement 2026-08-16: the old template scored 0/2 replicas, the new one 2/2.

## `swarm-territory/` — does the inventory cover non-HTTP entry points?

The whole territory. One hole in the HTTP surface, four outside it.

| What it should find | Where |
|---|---|
| IDOR: `get_report` does not filter by `owner_id` | `db/queries.py` |
| command injection, `shell=True` + `%` | `ops/cleanup.py` (two places) |
| SQL injection in a `DELETE` via `%` | `ops/cleanup.py` |
| `pickle.loads` from a state file | `ops/rotate.py` |
| SQL injection via `.format(**params)` + `executescript` | `db/migrate.py` |
| a chain: `restore_archive` unpacks into the directory `load_state` reads a pickle from → RCE | `ops/` |

**False-positive trap:** `list_reports` builds `LIMIT %d` by formatting, but
`int(limit)` in the route casts it first — there is no injection. An agent that
reported it as a finding did not follow the path to the end.

Measurement 2026-08-16: an inventory of HTTP entry points scored 1/5, open
territory 5/5.

## `toctou-and-fp/` — does the agent catch check-vs-use, and does it kill its own hypothesis?

Written to be deliberately clean: exact host comparison with a mandatory dot,
address classification through `ipaddress.is_global`, `ipv4_mapped`, and
`allow_redirects=False`. Eight assertions on classification pass.

It turned out not to be clean — and that is its value.

| What it should find | Why the assertions missed it |
|---|---|
| TOCTOU: `is_internal_host` resolves the host, `requests.get` resolves it again, the IP is not pinned → DNS rebinding | the assertions checked address classification, not the check-to-use linkage |

**False-positive trap:** the backslash differential
(`http://evil.com\@example.com/` — Python's `urlparse` sees `example.com`, while a
browser following WHATWG stops at `\`). It looks alive in the code and in the text
of the specification, but Werkzeug escapes `\` as `%5C` and the differential dies.
It can be killed **only by running it** — through `Flask.test_client()` and a real
browser.

Measurement 2026-08-17: the replica that consulted the specification declared the
bypass a candidate; the replica that stood up a venv and ran the request dropped
the hypothesis. The difference was neither the model nor the prompt, but 18 tool
calls against 8.

The price of the "reach the check's implementation" rule: 91–100k tokens and 6–9
minutes, against 62k and 50 seconds for an agent that reads only its slice.

## What the fixtures do not test

All three are synthetic, 5–9 files each, and their territory is exhausted in two
rounds. Swarm behaviour on a real repository (thousands of files, `MAP` not
buildable, the stopping criterion never firing) is **tested by nothing**. The first
real audit is worth running as a measurement and appending here.
