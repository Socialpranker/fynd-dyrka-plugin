# Logic flaws — Step 3, queue 1

> Read this first on Step 3, before the other references. This is the class
> scanners miss structurally: there is no vulnerable pattern here, there is a
> wrong decision in the code. The proof rule, the falsification pass and the
> "compare similar places" technique live in `SKILL.md`, Step 3, and apply here.

- **Authentication and authorisation.** Does every protected endpoint actually
  call auth? Are secrets and tokens compared with `timingSafeEqual` /
  `hmac.compare_digest` rather than `==`/`!==`? Is there a fail-open (a missing
  key in the config lets the request through instead of blocking it)? Are there
  client-side permission checks that the server does not repeat?
  🔐 Sessions, CSRF, JWT verification, password storage, randomness and crypto
  misuse — **`references/auth-crypto.md`**. Read it whenever the app has a
  browser-facing session or issues tokens of any kind.
- **Machine callers: cron, webhooks, service-to-service.** These are not checked
  by a session but by a separate mechanism (a shared secret, an HMAC) that is
  rarely covered by tests. The key question is what happens when the secret is
  **unset** in the environment. The standard fail-open: `CRON_SECRET` is empty,
  both sides of the comparison collapse to `Bearer `, `timingSafeEqual` honestly
  answers "equal", and the route is open to everyone. Also: non-constant-time
  comparison; a signature with no TTL or nonce (the request can be replayed);
  trusting `X-Forwarded-For`/`X-Internal` headers instead of cryptography.
- **Authorisation is three different bugs — ask them separately** (OWASP
  API1/3/5; a single vague "is there an IDOR" question only covers the first):
  - *someone else's object (BOLA)*: does the query filter by the current user's
    `userId`, or can another id be substituted? Is ownership checked before the
    action or after?
  - *someone else's fields (BOPLA)*: does the update bind the whole incoming JSON
    onto the model with no allowlist — does a client sending `{"role":"admin"}`
    or `{"credits":9999}` get away with it? Does the response serialise the whole
    object, leaking hashes, internal flags, other people's fields?
  - *someone else's function (BFLA)*: does the admin endpoint check only "logged
    in" rather than "logged in AND role = admin"?
- **SSRF / validating input that goes to the network.** How is the private-range
  check built? Classic bypasses: `::ffff:169.254.169.254` (IPv4-mapped IPv6 to
  cloud metadata), `0.0.0.0`, octal and decimal IP notation, DNS rebinding, a
  redirect to a private address, `[::]`. The full checklist (9 patterns and how
  to confirm each) is **`references/ssrf-bypasses.md`**. Test the guard with a
  reproducing run: does it compare the **host string** or the **resolved IP**?
  does it resolve once or twice? does it follow redirects?
- **Races in money and state.** Is a balance debit atomic (a single UPDATE with
  `WHERE balance >= N`, or a transaction with a lock), or a read-modify-write
  that two concurrent requests drive negative?
- **Skipping process steps.** Can a mandatory step be bypassed: delivery without
  payment confirmation, a privilege without verification, publishing around
  moderation? The tell in code: the state transition is taken from the client's
  request instead of derived server-side from the previous state. Same class:
  something one-shot applied twice — a promo code, an invite, a trial with no
  server-side reuse check.
- **Traceability.** Are significant actions (permission changes, money movements,
  admin operations, access to other users' data) written to an audit log? Without
  one an incident cannot be investigated or proven, and insider abuse is
  invisible. 📓 Full treatment — **`references/platform.md` §9** (what is logged,
  whether secrets leak into the logs themselves, whether anomalies alert, whether
  a human reads it, whether retention covers an investigation).
- **Availability and cost.** A separate class from data theft: the service is not
  broken into, it is knocked over or bankrupted with ordinary requests. No scanner
  finds this — there is no vulnerable pattern, there is a **missing limit**. Ask:
  is there rate limiting on **pre-authentication** endpoints (login, signup, OTP,
  resend)? is `limit`/batch size bounded from above? is heavy work (PDF, resize,
  export, an external API call) done synchronously in the handler? is spend on
  paid external calls capped?
  ⚡ A ten-section checklist, rules for confirming **without flooding
  production**, and a severity scale — **`references/availability.md`**. Read it
  when the target has public endpoints, paid external APIs, or user input that
  influences how much work is done.
- **Open endpoints.** Demo/debug/internal routes with no auth and no rate limit.
- **Injection: input reached a dangerous place.** The danger is not "there is user
  input" but "input reaches a sink without neutralisation", and correct
  neutralisation depends on the sink: HTML escaping does not help in SQL, and
  filtering `..` does not stop path traversal. For every flow found in Step 2 ask
  one question: **parameterisation/allowlist, or concatenation with a denylist
  filter?** The second is almost always bypassable.
  💉 Twelve sinks in full (SQL injection, command and argument injection, path
  traversal and zip slip, file upload, deserialisation and prototype pollution,
  XXE and XML parsing, SSTI, all three kinds of XSS, NoSQL operators, CRLF/header
  injection, prompt injection in LLM calls, missing boundary schema validation)
  plus a "sink → what to grep → correct fix" summary table —
  **`references/injection.md`**.
  ⚠️ On LLMs specifically: if user text or the contents of an external document
  reaches the prompt of a model that holds tools with side effects, that is a
  full sink, not "a product characteristic". No reliable prompt filter exists;
  the defence is limiting the model's authority. See `references/injection.md`
  §11.
