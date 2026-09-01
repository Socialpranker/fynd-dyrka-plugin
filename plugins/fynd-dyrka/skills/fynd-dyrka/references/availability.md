# Availability and resource exhaustion (DoS / cost-DoS)

A layer separate from confidentiality and integrity: the threat is not "steal the
data" but "knock the service over" or "bankrupt the owner", without exploiting a
single injection — simply by using an endpoint in the wrong volume. Scanners
(semgrep/gitleaks/osv-scanner) do not find this class at all: there is no
vulnerable code pattern here, there is a missing limit. It is found by reading
code for what is unbounded and by a short measurement, not by matching signatures.

## 1. Rate limiting as a check of its own

| Question | How to check | What happens if the answer is bad |
|---|---|---|
| Is there a limit at all | grep for middleware (`express-rate-limit`, `slowapi`, nginx `limit_req`, Cloudflare rules) on the target route | unbounded brute force, scraping, spam |
| At which layer | edge (Cloudflare/nginx) vs application (middleware) vs database (none at all) | an edge-only limit is bypassed by hitting the origin IP directly once it leaks |
| Limit keyed by IP | easily bypassed: proxy pools, Tor or residential rotation, an IPv6 /64 (billions of addresses in one allocation) | the limit is nominal |
| Limit keyed by user_id | bypassed by mass registration of new accounts, unless registration itself is limited | the same, one step more expensive |
| What happens on exceeding it | 429 with `Retry-After`? A silent ban? Merely slower? Nothing? | "nothing" means there is effectively no limit |
| Are expensive and cheap operations separated | one shared limit for the whole API vs a dedicated one for `/search`, `/export`, `/login` | the cheap allowance is consumed by an expensive request sharing the counter |

**Check pre-authentication endpoints separately** — they cannot be limited by
`user_id` because there is no user yet: signup, login, `forgot-password`,
`resend-code`/OTP, email verification, invite acceptance. If the limit here is
IP-only (or absent), that is the hole for credential stuffing, OTP brute force,
signup spam, and mail/SMS spam aimed at someone else's address (see §9).

## 2. Expensive endpoints — one request, a lot of CPU, memory or time

Signals to look for in code:

| In code | Example | Effect |
|---|---|---|
| Sorting/aggregation in the application rather than the database | `results.sort(...)` / `groupBy` in JS or Python over the whole result set | O(n log n) per request with no cache |
| Image/PDF/video generation synchronously in the handler | `pdfkit`, `sharp.resize`, `ffmpeg` invoked inside an HTTP handler | seconds of CPU per HTTP request, blocking a worker |
| Parsing large structures from input | `JSON.parse`/`yaml.load`/`csv.parse` with no size limit | see §4 |
| Recursion over user data with no depth limit | walking a comment tree, nested categories, arbitrarily nested JSON | stack overflow / exponential time |
| N+1 database queries per HTTP request | a loop with `await db.query()` inside `.map()` | 1 external request → hundreds against the database; cheap flooding takes the database down |
| Synchronous heavy work in the handler instead of a queue | sending email/SMS/webhooks, resizing, exporting — all inline | one slow external call holds a worker or thread; the pool drains faster than under normal load |

How to confirm: `time curl` against the suspect endpoint with a realistic data
volume on a **local copy**, not production. Measure one request; do not flood.

## 3. Unbounded queries

| Signal | Where to look | Effect |
|---|---|---|
| `SELECT` with no `LIMIT` | an ORM call without `.limit()`/`.take()`, raw SQL | the whole table pulled in one request |
| Pagination with no upper bound | `?limit=` read straight into the query with no `min(limit, MAX)` | `?limit=999999` is item 1 in another wrapper |
| "Export all records" / "download as CSV" | an endpoint with no paging, the whole dataset in memory | OOM on the instance |
| GraphQL with no depth or complexity limit | no `graphql-depth-limit`, `graphql-cost-analysis`, query complexity | a nested `user{friends{friends{friends{...}}}}` fans out exponentially in the database |
| Batch endpoints with no batch-size limit | `POST /batch` accepts an array of any length | one HTTP request equals N operations, N unbounded |

How to confirm: read the pagination/limit code and show the client value reaching
the query without `Math.min`/`clamp`. Locally, issue one request with a large
`limit` and measure time and response size.

## 4. Input size

| What to check | How | Effect without protection |
|---|---|---|
| Request body limit | `body-parser`/`express.json({limit})`, nginx `client_max_body_size`, framework default | a gigabyte of JSON in process memory |
| Upload size limit | maximum size in the upload middleware config (multer/formidable/etc.) | disk or memory exhausted by a single upload |
| Decompression bombs | the server inflates `Content-Encoding: gzip`/`zip` with no cap on the result | 1 KB in → gigabytes out (zip bomb, `42.zip`) |
| Very large or deeply nested JSON | the parser is called with no depth limit (`JSON.parse` is recursive) | parser stack overflow on nesting like `[[[[[...]]]]]` |
| XML bombs (billion laughs) | an XML parser with entity expansion enabled, `DOCTYPE` not disabled | a few KB of XML expand into gigabytes of memory |
| Many fields or files in multipart | no cap on part count (`maxFields`, `maxFiles` in multer/busboy) | thousands of tiny fields load the parser |

How to confirm: check the limit configuration in code (is a value set, or is it
the framework default — and what is that default, often "unlimited"). Locally,
send one request slightly over the limit and confirm the server answers 413
rather than crashing or hanging.

## 5. ReDoS — catastrophic backtracking

Dangerous patterns in a regular expression:

- Nested quantifiers: `(a+)+`, `(a*)*`, `(\d+)+`
- Alternation with overlapping branches: `(a|a)*`, `(a|ab)*`
- A quantifier over a group that can itself consume the same text differently:
  `([a-zA-Z]+)*$`, `(.*a){x}` for large x

Where user input typically ends up inside a regex:

- Email/URL/phone validation (the most common place — a copy-pasted Stack
  Overflow regex with nested quantifiers)
- Parsing `User-Agent` or other headers
- Search and filtering over a user-entered string
- Custom routing with regex path patterns

How to check — an isolated measurement, NOT through the server:

```js
// Proving ReDoS means showing time GROWING with input length, not one number.
// A single measurement proves nothing: 200 ms can be blamed on anything.
const re = /^([a-zA-Z]+)*$/;          // substitute the project's pattern
for (const n of [20, 25, 28, 30, 32]) {
  const evil = "a".repeat(n) + "!";   // a tail that breaks the match
  const t0 = process.hrtime.bigint();
  re.test(evil);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`n=${n}\t${ms.toFixed(1)} ms`);
  if (ms > 5000) break;               // no need to wait further
}
```

Measured for this pattern in Node (V8): `n=20 → 107 ms`, `n=25 → 350 ms`,
`n=28 → 2345 ms`, `n=30 → 10462 ms`. Time doubling for every one or two extra
characters is the confirmation; linear growth means the pattern is safe. The
Python equivalent is the same loop with `time.perf_counter()` and `re.match`.

The killer string is usually N repeats of a character the quantifier accepts,
plus one character at the end that breaks the match (forcing the engine through
every backtracking combination before giving up).

Engines that are safe (linear time, backtracking impossible by construction):
**Go (`regexp`, RE2), Rust (the `regex` crate)**. Unsafe (backtracking-based,
vulnerable by construction): **JavaScript (V8), Python (`re`), Java
(`java.util.regex`), PHP (PCRE)**. Such an engine in the stack is not itself the
vulnerability, but it raises the priority of manually checking every regex that
touches user input.

## 6. Cost in money (cost-DoS / cost amplification)

A modern and frequently missed class: the attack does not take the service down,
it sends the owner a bill. It appears when a user request triggers a **paid
external API** — an LLM call, OCR, geocoding, SMS or email delivery, video
transcoding — as well as the infrastructure's own metered limits: serverless
invocations, egress traffic, paid storage.

| Question | Why it matters |
|---|---|
| Is there a per-user quota (requests/tokens/files per hour or day)? | without one, a single account equals an unbounded bill |
| Is there a global daily or monthly spending cap at the provider? | the last line of defence when the per-user quota fails |
| Is there an alert on a spend or call spike? | without it, the DoS is discovered by the invoice at month end |
| Is the length or size of input passed to the paid API bounded? | a long prompt or a large OCR file costs more per call, not only per call count |
| Are repeated calls to the paid API cached? | without a cache, an identical request is paid for every time |

The calculation for the report: `price_per_call × achievable_rate × 3600` = the
cost of one hour of attack. **Take both numbers from reality, not from here**:
the price from the provider's pricing page, the rate from your own measurement on
a local copy (how many requests per second get through on one connection before
something starts throttling them).

The template is `$PRICE × N_req_sec × 3600 = $X/hour` from a single IP, and
multiples of that with a proxy pool. `$X` is the severity justification — "no
quota" without a number is not an argument. If you could not measure the rate,
say so ("rate not measured, ceiling not estimated") rather than substituting a
plausible number: an invented figure in a report is worse than no figure.

## 7. Timeouts and cascading failures

| Signal | Effect |
|---|---|
| No timeout on an outbound HTTP call (to the database, to an external API) | one hung upstream holds a worker indefinitely; the pool drains |
| No cap on retries | retry storm: a failed upstream receives multiples of the load from retries exactly as it recovers |
| No circuit breaker | the service keeps hammering an unavailable upstream instead of failing fast |
| A database connection pool sized without regard to concurrency | concurrent slow queries consume the pool; other requests queue or time out |
| A blocking call in the event loop (Node/asyncio) | one synchronous heavy call (crypto, `JSON.parse` of a huge object) freezes the whole process, not just that request |
| Slowloris / hanging connections | no timeout on reading headers or body — the connection stays open, exhausting the concurrent-connection limit |

How to check: grep for `timeout` in the HTTP client (`axios`, `fetch`,
`requests`, `httpx` — is `timeout=` explicit, or is the library default in use,
which may be `None`/infinite). Check the database pool configuration
(`max connections`) against realistic concurrency.

## 8. State-space exhaustion

Unbounded growth of anything on disk, in memory, or in the database:

- Sessions with no TTL and no per-user cap
- Temporary files (uploads, exports, previews) not removed after use or when the
  connection drops
- Database rows created by **unauthenticated** users (guest carts, drafts, log
  events) with no TTL or cleanup
- A background job queue with no backpressure — accepting work faster than it
  processes, growing without bound
- A cache with no eviction policy (an unbounded in-process `Map`/dict that grows
  with every unique request)
- Logs with no rotation — the disk fills and the process dies on write

How to check: find where a resource is created with no matching cleanup or TTL;
for in-memory caches, whether there is a `maxSize`/LRU or just a bare `{}`/`Map()`.

## 9. Amplification and external effects

An endpoint that turns the service into a source of outbound traffic aimed at
third parties:

| Pattern | How it is exploited |
|---|---|
| Sending email/SMS to an arbitrary address on user request (notification, invite, "share") | the service as a spam relay — the attacker supplies someone else's address, the victim receives a stream of mail or SMS from a legitimate domain |
| Webhook registration with no validation of the target URL | the service hits the given address as often as asked (combines with SSRF — see `ssrf-bypasses.md`) |
| An endpoint that initiates many outbound requests from one inbound (link preview fetch, batch notifications, fan-out to subscribers) | one attacker request equals N requests from the service to a third party — the service becomes the attacker by amplification |
| Retries or webhooks with no limit on an attacker-supplied URL | the service as a DDoS instrument against a third-party site |

Check: is there a limit on emails/SMS sent per account per hour; is the webhook
URL validated so it cannot point at the attacker's own infrastructure in an
unbounded loop.

## 10. Algorithmic complexity

| Pattern | Effect |
|---|---|
| Hash-collision DoS | a data structure keyed on user input is vulnerable to crafted collisions (relevant for old or custom hash tables, not for modern Node/Python with a random seed) |
| An expensive password hash with no rate limit on login | bcrypt is **deliberately** slow: cost 12 ≈ 150–250 ms, cost 14 ≈ 630–1000 ms on 2019–2021 CPUs (each +1 doubles the work). That is an order of magnitude — measure on your own hardware rather than quoting it as fact. Without a limit, login becomes a CPU DoS: N concurrent attempts equal N threads busy hashing |
| Quadratic sorting or searching over user data | a hand-rolled algorithm instead of the standard library, on input whose size the attacker controls |

How to check: measure `/login` response time for a wrong password under 10–20
concurrent requests locally — response time growing disproportionately to request
count indicates CPU exhaustion in hashing.

## How to confirm

The skill's rule is that a reproducing run is mandatory for severity above
MEDIUM. For DoS findings that does **not** mean flooding production. Safe ways to
confirm:

1. **Measure one request, not a flood.** `time curl` (or
   `curl -w "%{time_total}\n"`) against the expensive endpoint — if a single
   request already burns seconds of CPU, extrapolating to N concurrent requests
   is obvious without an actual flood.
2. **Arithmetic instead of an attack.** "1 request = N seconds of CPU / M MB of
   memory" → "how many requests per second consume the instance's CPU or RAM" is
   arithmetic, not a load test.
3. **A local copy, not production.** When the effect must be observed under load
   (connection pools, backpressure), stand the service up locally or in a
   container and drive load there.
4. **ReDoS: an isolated regex measurement** outside the HTTP stack entirely (see
   §5) — the engine and pattern are the same, and the result transfers to
   production without risking it.
5. **Rate limiting: a single bypass check**, not a full brute force — make N+1
   requests where N is the claimed limit and show the (N+1)th got through, or that
   changing IP or account resets the counter. Thousands of requests are
   unnecessary; crossing the boundary once is enough.
6. **Cost-DoS: arithmetic from the provider's price list**, not real calls on a
   production key.

**Stated plainly: do not run a load attack against production without the
owner's separate, explicit permission.** The difference between "I showed one
request costs 3 seconds of CPU" and "I sent 10,000 requests and took production
down" is the difference between a PoC and an incident the auditor owns.

## Severity for DoS

Axis 1 — availability to the attacker:

- Reachable anonymously (pre-authentication), cheap for the attacker (one request,
  no special tooling), expensive for the victim (much CPU, memory or money per
  request) → **HIGH/CRITICAL**.
- Requires authentication, but signup is open and itself unlimited → nearly the
  same, one step more expensive → still **HIGH** when the effect is shared (not
  confined to the attacker's own session).
- Requires authentication and the effect is confined to the attacker's own
  session or account (filling their own quota) → **LOW/MEDIUM**.

Axis 2 — cost asymmetry. The wider the gap between what the attacker spends and
what the victim spends, the higher the severity: 1 HTTP request → minutes of CPU
or dollars on the bill is amplification, not merely load.

Rate cost-DoS **in money per hour of attack** (see the formula in §6), not in
abstract categories — a concrete figure prioritises better than "may lead to
increased expenditure".

Mitigating factors: the effect is temporary and self-healing (the rate-limit
window closes); the access required is already privileged (an internal
admin-only batch endpoint — an admin DoSing themselves is not a priority finding).
