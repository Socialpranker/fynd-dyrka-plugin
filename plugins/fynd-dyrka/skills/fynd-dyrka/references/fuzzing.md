# Boundary values and parser/transport divergence — Step 3, queue 4b

A class that sits between injection and logic flaws: no attacker-controlled sink,
no missing check — the code simply meets a value it never imagined. A date at the
edge of the calendar, a number that overflows on arithmetic, a lone surrogate on
its way into UTF-8, a body that arrives in a shape the size limit does not
understand, a URL that two parsers read differently. The failure is an unhandled
exception (a 500, a crash, a hung worker) or a **disagreement between two
components** about the same bytes: validator vs consumer, proxy vs backend,
limit vs reader. Scanners barely reach it; reading code rarely does either,
because each component looks correct in isolation.

**Marking.** **[confirmed]** — read in the tool's own documentation or repository
during the wave-1 research, or reproduced in this repository's own run.
**[assumption]** — reasoning or general practice, not checked against a source.
**[not confirmed]** — looked for and not found. Carry these marks into the report;
do not upgrade an assumption to a fact.

**The gate: local targets only.** Fuzzing writes data (POST/PUT/DELETE with
generated bodies), fills tables and can take the service down, so it runs against
`localhost` / private addresses and never against a public host — not even with
authorisation. The `fuzz` layer of `scan.py` enforces this: it refuses any URL for
which `is_local_target()` is false and **`--authorized` does not lift the refusal**.
Every PoC you write from this file follows the same rule: run it against a local
copy (§4), not against production or staging with real data.

## 1. Schemathesis — the `fuzz` layer

Generates requests from the service's OpenAPI spec and checks the responses.
MIT **[confirmed]**; `uv tool install schemathesis` / `pip install schemathesis`
**[confirmed]**. Its own summary: it catches "500 errors that crash your API on
edge case inputs", schema violations, validation bypass and stateful bugs
**[confirmed]**.

```bash
python3 <skill>/scripts/scan.py --url http://127.0.0.1:8000 --layers fuzz --raw-dir /tmp/secscan
```

What the layer runs (flags checked against `schemathesis run --help`, v4.28.0,
run locally): `-w 1 --rate-limit 10/s -n 100 -c not_a_server_error
--request-timeout 10 --origin <the local origin> --report json`, in a temporary
working directory (Schemathesis and Hypothesis create `.hypothesis/` and
`.schemathesis/` in the cwd). `--origin` keeps requests on the verified local
origin even if the spec names another host in `servers`. The spec is taken from
`/openapi.json`, `/swagger.json`, `/openapi.yaml`, `/api/openapi.json` or
`/v3/api-docs`; pass `--url` pointing at the spec file for anything else. No
`--url` or no spec → `skipped` with the reason, never a silent zero. Big APIs
outrun the default `--timeout 300` (100 examples × operations at 10 req/s): raise
it.

**Only `not_a_server_error` is enabled.** The other default checks
(`response_schema_conformance`, `positive_data_acceptance`,
`negative_data_rejection`, `content_type_conformance` and so on) are documented
**[confirmed]** but are likely to be noisy when the spec drifts from the code
**[assumption]**; `ignored_auth` will misfire where the spec declares no security
**[assumption]**. Turn them on by hand once the spec is trusted.

**What it did and did not find here** (one FastAPI toy app, Schemathesis 4.28.0,
default generation — an observation, not a benchmark):

| Defect in the handler | Result |
|---|---|
| `ts - timedelta(days=1)` on a `datetime` field — overflows only within a day of `datetime.min` | **not found** in 3,030 generated cases |
| `struct.pack("<I", int(ts.timestamp()))` — unsigned 32-bit epoch, fails for every date before 1970 or after 2106 | found within ~36 cases; the same app with a range check returned 422 and gave zero findings |

So Schemathesis finds broad classes quickly and misses a defect that lives on one
exact boundary value. For the exact boundary, write the property yourself (§2).
Also **[confirmed]**: Hypothesis draws dates from `datetime.min` to `datetime.max`
by default, yet the run above did not land on the extreme edge — treat hitting
one exact boundary as luck, not design (my reading of that observation).

A hit is a **candidate**: the Reproducer line in the finding is a `curl` to
replay. Then Step 3 applies unchanged — a PoC that imports the real handler, an
oracle tied to the failing line (the exact exception raised from the exact call),
and a control (the fixed variant answers 4xx, not 5xx).

Not wired in **[confirmed facts]**: **RESTler** (MIT; Python 3.12.8 + .NET 8.0;
macOS "experimental"; the authors warn fuzzing "may create outages in the service
under test"), **EvoMaster** (LGPL v3; black-box for any language, white-box only
JVM; `evomaster --schema <url>`). For an ASGI app the in-process route is
`schemathesis.openapi.from_asgi("/openapi.json", app)` with
`@schema.parametrize()` and a Starlette `TestClient` — no network, no public
`/openapi.json` needed; this came from a search snippet and the page was not
opened, so check the current API before relying on it **[assumption]**. Next.js
generates no spec; how to fuzz it without OpenAPI **[not confirmed]**.

## 2. Hypothesis in your own PoC

For a parser, validator or date/number routine, write the property directly.
MPL-2.0, `pip install hypothesis` **[confirmed]**. `st.datetimes()` and
`st.dates()` cover `datetime.min`–`datetime.max` by default, and `st.text()`
generates **no surrogates** by default — request them with
`st.characters(categories=["Cs"])` **[confirmed; the second also by the run
below]**. The template below was run
against stand-in functions (four deliberately broken ones failed, the correct
roundtrip passed); replace the imports with the project's **real** functions —
importing your own copy tests your copy.

```python
# /tmp/secscan/poc_boundary.py
from datetime import datetime, timezone
from hypothesis import given, settings, strategies as st, example
from myproj.billing import next_billing_date, store_epoch, render_name   # REAL imports
from myproj.codec import serialize, parse
from myproj.urls import check_host, fetch_host    # the validator and the consumer

UTC = timezone.utc

@settings(max_examples=500, deadline=None)
@given(st.datetimes(timezones=st.just(UTC)))
@example(datetime.min.replace(tzinfo=UTC))        # the exact edges, never left to luck
@example(datetime.max.replace(tzinfo=UTC))
def test_date_arithmetic_never_escapes(ts):
    try:
        next_billing_date(ts)
    except ValueError:      # the declared, handled error type
        pass                # anything else (OverflowError, struct.error) fails the property

@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.characters(categories=["Cs"]), min_size=1))   # lone surrogates
def test_surrogates_survive_encoding(s):
    render_name(s).encode("utf-8")       # the encode a DB driver / JSON dump / log line does

@given(st.dates())
def test_roundtrip(d):
    assert parse(serialize(d)) == (d.year, d.month)

@settings(max_examples=500, deadline=None)
@given(st.from_regex(r"https?://[a-z0-9.@:\\/#?%]{1,30}", fullmatch=True))
def test_checker_and_consumer_agree(url):
    assert check_host(url) == fetch_host(url)   # differential: guard vs the code that fetches
```

The oracle is **the property**, and it must be one you can state: "no exception
outside the declared set", "encode succeeds", "parse inverts serialize", "the
check and the use read the same host". A property you cannot state is not an
oracle. Boundaries worth an explicit `@example`:

- **Dates:** `datetime.min` / `datetime.max`; `+ timedelta` at the top and
  `- timedelta` at the bottom (`OverflowError`); `.replace(year=y ± 1)` at the
  ends of the range and on 29 February (`ValueError`); a naive vs an aware value.
  `time.mktime(d.timetuple())` raised `OverflowError` for years before 1970 on
  the macOS / Python 3.14 machine used here — platform-dependent, check yours
  **[confirmed on that machine only]**. `struct.pack("<I", int(ts.timestamp()))`
  fails outside 1970–2106 (the toy app in §1).
- **Numbers:** 0, −1, `2**31−1`, `2**63`, `float("nan")`/`inf`, a huge integer
  string, a negative quantity or price.
- **Unicode:** lone surrogates (they pass a JSON/`str` boundary and die at the
  UTF-8 encode), NUL, very long strings, combining marks, right-to-left marks,
  normalisation-sensitive identifiers (`"é"` as one code point vs two).
- **Sizes:** empty, one byte, exactly the limit, limit + 1.

False positives come from a wrong property, not from the tool: a property that
also fails on the *fixed* code is the PoC's fault (Step 3's control group).

## 3. Differential of the transport: one body, several framings

A limit or a validation applied to one representation of a request and skipped on
another. **The class:** a body-size cap enforced by reading the `Content-Length`
header is not applied when the same body arrives as `Transfer-Encoding: chunked`
(no `Content-Length` at all) — the same bytes, a different code path. Treat this
as an **example of the class, not as a sourced finding**: no source for a
specific framework was found **[not confirmed]**. The other framings to try are
HTTP/2 (`Content-Length` optional, framed differently) and the chunk/`Content-Length`
mix a proxy and a backend may parse differently.

```python
# /tmp/secscan/poc_transport.py — one body, framed two ways; compare the outcomes
import http.client

HOST, PORT, PATH = "127.0.0.1", 8000, "/upload"
BODY = b"A" * 100_000                    # far above the documented limit

def send(mode):
    c = http.client.HTTPConnection(HOST, PORT, timeout=10)
    hdrs = {"Content-Type": "application/octet-stream"}
    if mode == "content-length":         # http.client sets Content-Length itself
        c.request("POST", PATH, body=BODY, headers=hdrs)
    else:                                # "chunked"
        hdrs["Transfer-Encoding"] = "chunked"
        chunks = (BODY[i:i + 4096] for i in range(0, len(BODY), 4096))
        c.request("POST", PATH, body=chunks, headers=hdrs, encode_chunked=True)
    r = c.getresponse()
    return r.status, r.read()

for mode in ("content-length", "chunked"):
    print(f"{mode:15} -> {send(mode)}")
```

Run against a toy app whose middleware rejected only by `Content-Length`, this
printed `413` for `content-length` and `200 {"received":100000}` for `chunked` —
that shows the harness works and the class exists, **not** that any real framework
behaves so. Against the project, the finding is a **divergence with a
consequence** (limit bypassed, a 500, a different parse of the same value), not a
divergence alone: different answers for the same body are only noise until you
can say what an attacker gains. An HTTP/2 variant needs an HTTP/2 client and
server (`httpx[http2]` is the obvious client **[assumption]**); it was not run in
this wave. How Schemathesis itself frames requests (chunked, HTTP/2):
**[not confirmed]**.

The other members of the class, in the same shape (one input, two readers):
**URL parsers** — a validator and an HTTP client that disagree about the host
(Claroty's research compared 16 parsers and grouped the confusions into scheme,
slash, backslash, URL-encoded and scheme-mixup **[confirmed]**; they released no
tool, so use the five categories as seeds for your own differential, as in the
last property above; the SSRF side is `ssrf-bypasses.md`); **request smuggling** —
needs a front proxy plus a backend, weak evidence on a single local service;
nuclei ships `cl-te` / `te-cl` templates (`unsafe: true`, severity low) and
`defparam/smuggler` (MIT) covers CL.TE / TE.CL only **[confirmed]**.

## 4. Running it safely — a recommendation without a source

These are this skill's own rules, not taken from a document **[assumption]**; the
only sourced part is that Schemathesis exposes `--rate-limit` and `-w`, and that
RESTler warns about outages.

- **A copy, not the real thing.** A temporary SQLite / test database or a seeded
  copy; a fuzz run on the real database inserts junk and can delete rows.
- **Mock every outbound effect:** payments, email, SMS, push, LLM calls, webhooks.
  A generated body that reaches a real provider spends money or messages a person.
- **No real keys in the environment** of the process under test.
- **`-w 1` and a rate limit** (the layer uses 10 requests per second); a time
  limit and a body-size limit on the run.
- **`DELETE`/`PUT` only against the seeded database.**
- Watch the service while it runs; a fuzz that flattens the process is a finding
  about availability (`availability.md`), not a reason to run harder.

## 5. Other engines — not wired in

| Where | Tool | Note |
|---|---|---|
| Python code, native extensions | Atheris (Apache-2.0, `pip3 install atheris`) | needs libFuzzer from Clang; Apple Clang does not ship it **[confirmed]**; needs a harness per target |
| JVM | Jazzer (Apache-2.0) | `@FuzzTest`, `JAZZER_FUZZ=1`; sanitizers include SSRF, path traversal, OS command injection (full list not seen) **[confirmed]** |
| Go | built in since Go 1.18 (`func FuzzXxx(f *testing.F)`, `go test -fuzz=`) | corpus in `testdata/fuzz/` **[confirmed]** |
| Rust | cargo-fuzz (MIT OR Apache-2.0) | nightly; not Windows **[confirmed]** |

Each needs a harness written for the target, so none is an automatic layer. If
the project already has `Fuzz*` functions or `fuzz_*.py` files, run them; if it
has a parser and none, say so in the report as a gap.
