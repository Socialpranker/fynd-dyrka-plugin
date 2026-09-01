# Session, CSRF and crypto — Step 3, queue 1b

Read after `logic-flaws.md`. That file asks whether an endpoint checks *who you
are*; this one asks whether the mechanism that answers "who you are" can be
forged, replayed, or guessed — and whether the crypto underneath it holds.

Order inside this file follows how often the class is actually exploited, not
how interesting it is: session and CSRF first, password storage second,
randomness third, everything else after.

## 1. CSRF — the browser sends the cookie for the attacker

The class scanners miss most consistently, because nothing in the code *looks*
wrong: the handler is authenticated, the query is parameterised, the check is
there. The bug is that the browser attaches the session cookie to a request the
user never intended to make.

**Applies when** the session is carried by a cookie (or HTTP Basic, or a client
certificate) — anything the browser attaches automatically. A `Authorization:
Bearer` header read from JS memory is not CSRF-able; the same app storing that
token in a cookie is.

Ask per state-changing endpoint:

- Is there a CSRF token, and is it **verified server-side**, not merely issued?
  A token generated, planted in the form, and never compared is the most common
  fail-open here.
- Is the token bound to the session? A token valid for any user turns CSRF into
  a two-request attack, not a fix.
- `SameSite` on the session cookie: `Strict`/`Lax` blocks the naive cross-site
  POST; `None` requires `Secure` and re-opens the class. Note `Lax` still allows
  top-level GET — so a **state-changing GET** stays exploitable under `Lax`.
- Are state-changing operations reachable by `GET` at all? `GET /admin/delete?id=`
  is CSRF-able through an `<img>` tag regardless of framework middleware.
- Is the framework's CSRF middleware **globally on**, or per-route opt-in? Look
  for the exemption list: `@csrf_exempt`, `csrf: false`, routes registered
  before the middleware, webhook handlers that disabled it and then grew
  user-facing functionality.
- JSON-only APIs: is `Content-Type: application/json` actually enforced? Simple
  form posts (`text/plain`, `application/x-www-form-urlencoded`) bypass preflight,
  so an API that parses any body regardless of content type is CSRF-able.

```
grep -rnE "csrf_exempt|csrf: *false|CSRF_ENABLED|SameSite|withCredentials|credentials: *['\"]include"
```

**Severity.** CSRF on an admin action (create user, grant role, change email) is
HIGH — it is privilege escalation with one visited page. CSRF on a preference
toggle is LOW. Judge by what the forged request does, not by the class name.

**Proof.** A PoC is a second-origin HTML page that submits the form and a run
showing the state changed. Control group: the same request with the CSRF token
removed *should* fail on a fixed build — if it succeeds both with and without,
you have proven the check is absent, which is the finding.

## 2. Session lifecycle

- **Rotation on privilege change.** Does the session ID change after login and
  after a role change? If not, session fixation: the attacker plants a known
  session ID, the victim logs in, the attacker now holds an authenticated session.
- **Invalidation.** Does logout destroy the server-side session or only clear the
  cookie? A cookie-only logout leaves a valid session for anyone who captured it.
  Same question for password change and for "log out all devices".
- **Cookie flags.** `HttpOnly` (blocks theft via XSS), `Secure` (blocks plaintext
  transport), `SameSite` (see §1), `Domain` scoped no wider than needed — a cookie
  set on `.example.com` is readable by every subdomain, including the one running
  someone else's marketing page.
- **Expiry.** Is there an absolute lifetime, or only an idle timeout that a
  keep-alive request refreshes forever?
- **Concurrency.** Can the same session be used from two IPs at once, and is that
  visible anywhere (see the observability section in `logic-flaws.md`)?

## 3. JWT — the failure modes are in verification, not signing

- `alg: none` accepted, or the algorithm taken **from the token** rather than
  pinned by the verifier.
- **HS256/RS256 confusion**: a verifier that accepts both lets an attacker sign
  an HS256 token using the public RSA key as the HMAC secret.
- Signature verified at all? `jwt.decode(token, verify=False)`, `decode` without
  a key, or a manual base64 split with no verification step.
- `exp`/`nbf` checked, and is there clock-skew tolerance wide enough to matter?
- Revocation: a stateless JWT cannot be revoked before expiry. If the app has
  "ban user" or "log out all devices", is there a denylist, or does the banned
  user keep working until the token expires?
- Secret strength and origin: hardcoded, committed, or defaulted to a literal
  like `"secret"`/`"changeme"` when the env var is missing (that last one is the
  fail-open — see §6).
- Sensitive data in the payload: JWT is signed, not encrypted; it is readable by
  anyone holding it.

```
grep -rnE "jwt\.(decode|verify)|verify *= *False|algorithms? *= *\[|alg.{0,10}none|jsonwebtoken"
```

## 4. Password and credential storage

- Which hash: bcrypt / scrypt / Argon2id / PBKDF2 with a real work factor — or
  MD5/SHA-1/SHA-256, plain or "salted"? A single unsalted SHA-256 is a finding
  even though the primitive itself is not broken: it is fast, and that is the bug.
- Cost parameter set explicitly, or left at a library default from a decade ago?
- Comparison in **constant time** (`hmac.compare_digest`, `crypto.timingSafeEqual`)?
  This matters more for API keys and reset tokens compared with `==` than for
  password hashes, which are compared through the hash library.
- Are API keys and webhook secrets stored hashed, or in plaintext next to the
  user row? A read-only SQL injection over a plaintext key table is total
  compromise; over a hashed one it is not.
- Password reset tokens: single-use, expiring, invalidated on use and on password
  change, tied to the user, and **not** the same value as the user id or email.

```
grep -rnE "md5|sha1|sha256|hashlib\.|bcrypt|argon2|scrypt|pbkdf2|compare_digest|timingSafeEqual"
```

## 5. Randomness — the quiet one

Any value whose security depends on being unguessable must come from a CSPRNG:
session IDs, reset and invite tokens, API keys, OTPs, filenames of uploaded
files served from a public path, "unguessable" share links.

- Python: `secrets.token_urlsafe()` / `os.urandom`, **not** `random.*`.
- Node: `crypto.randomBytes` / `crypto.randomUUID`, **not** `Math.random()`.
- Not `uuid1()` (encodes MAC address and timestamp), not `time.time()`, not a
  counter, not a hash of the timestamp.

```
grep -rnE "random\.(random|randint|choice|sample)|Math\.random|uuid1\(|time\(\)|timestamp"
```

**Proof.** Generate a few thousand tokens, check for structure: monotonic
prefixes, shared timestamp bits, repeats. Control group: the same test against
`secrets.token_urlsafe()` must show none.

## 6. Crypto misuse and the config fail-open

- ECB mode (`AES.new(key, AES.MODE_ECB)`) — identical plaintext blocks produce
  identical ciphertext.
- Static or zero IV/nonce reused across messages; nonce reuse in GCM is fatal,
  not cosmetic.
- Encryption without authentication (CBC without a MAC) — the padding oracle
  class lives here.
- Home-rolled "encryption": XOR with a key, base64 called encryption, a hash
  used as a cipher.
- Certificate verification disabled: `verify=False`, `rejectUnauthorized: false`,
  `InsecureSkipVerify: true`, a global SSL context override.
- **The fail-open pattern that matters most here**: what happens when the key or
  secret is *missing*? A `os.getenv("SECRET", "dev")` fallback means production
  runs on a publicly known secret whenever the variable fails to load — and
  nothing in the logs says so. Trace every secret read to its default.

```
grep -rnE "MODE_ECB|iv *= *(b?['\"]0|bytes\(|\[0)|verify *= *False|rejectUnauthorized|InsecureSkipVerify|getenv\([^)]+, *['\"]"
```

## 7. WebSocket and long-lived channels

Not an injection class — an entry point that inventories built from route lists
miss entirely, because the handler is registered somewhere else and there is one
of it for many operations.

- Is the **handshake** authenticated, and is authorisation re-checked per message,
  or only once at connect? A connection opened as a low-privilege user and then
  upgraded server-side stays open with the old rights checked once.
- Is `Origin` validated on the handshake? Cookies are attached to WebSocket
  handshakes, and `SameSite` does not apply — this is Cross-Site WebSocket
  Hijacking, the CSRF of realtime.
- Is there per-connection rate limiting and a message size cap, or does the
  connection accept unbounded messages (see `availability.md`)?
- Do subscribe/room-join messages check ownership of the room id, or is joining
  `room:{id}` enough to receive another tenant's stream? This is IDOR over a
  channel — same question as BOLA, different transport.
- Are the same authorisation helpers used as on the HTTP side, or a parallel
  re-implementation? Compare them: divergence between the two is the finding
  (the "compare similar places" technique from SKILL.md, Step 3).

```
grep -rnE "websocket|socket\.io|WebSocketHandler|on\(['\"]connection|ws\.on|@sio\."
```

## Summary: symptom → grep → fix

| Symptom | Grep for | Fix |
|---|---|---|
| CSRF unenforced | `csrf_exempt`, `csrf: false`, state-changing `GET` routes | global CSRF middleware, session-bound token verified server-side, `SameSite=Lax` minimum |
| Session fixation | login handler with no `session.regenerate`/`cycle_key` | rotate session id on login and on privilege change |
| Cookie theft via XSS | `set_cookie(` without `httponly` | `HttpOnly`, `Secure`, `SameSite`, narrow `Domain` |
| JWT forgery | `verify=False`, `algorithms=[...]` wide, `alg` from token | pin one algorithm, verify signature and `exp`, denylist for revocation |
| Weak password storage | `md5`, `sha1`, bare `hashlib` | bcrypt/scrypt/Argon2id with an explicit cost |
| Guessable token | `random.`, `Math.random`, `uuid1(`, `time()` | `secrets.token_urlsafe` / `crypto.randomBytes` |
| Crypto misuse | `MODE_ECB`, static IV, `verify=False` | authenticated encryption (AES-GCM/libsodium), unique nonce, keep certificate verification on |
| Secret defaults to a literal | `getenv(..., "dev")` | fail closed on a missing secret — refuse to start |
| WebSocket unauthenticated | `on('connection'`, `socket.io` | authenticate the handshake, validate `Origin`, re-check authorisation per message |
