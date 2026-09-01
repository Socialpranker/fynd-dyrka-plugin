# SSRF bypass catalogue

A reference for auditing SSRF defences in **someone else's code** (the skill's
target): what to check when you see a function shaped like `is_safe_url` /
`validate_domain` / a private-range allowlist. Each item is a bypass a typical
check lets through, plus how to confirm it.

> ⚠️ This is a list of what to look for, **not a model of a correct defence**. It
> was extracted from a real guard in which item 1 (`::ffff:`) was **not closed**
> at the time of extraction — that is, even a service whose guard looks serious
> gets caught by this catalogue. Do not treat the presence of a private-range
> check as sufficient until you have run these inputs through it.

Test the guard with a **reproducing run** (the proof rule in SKILL.md): import
the real function, feed it the inputs below, and show a private address passing
as "safe". The control group is the same input after normalisation to canonical
form.

## Patterns

1. **IPv4-mapped IPv6** — `::ffff:127.0.0.1`, `::ffff:169.254.169.254`.
   `ipaddress.ip_address()` parses these as IPv6; a check over private IPv4
   ranges (`10/8`, `192.168/16`, `169.254/16`) misses them, and the IPv6 list
   usually holds only `::1/128` and `fc00::/7`.
   The fix that should be in the code: inspect `.ipv4_mapped` and unwrap to IPv4
   **before** the network check.

2. **Decimal / octal / hex IP notation** — `http://2130706433/` (= 127.0.0.1),
   `http://0177.0.0.1/`, `http://0x7f.0.0.1/`.
   Many HTTP clients and `socket.getaddrinfo` normalise these into a valid IP,
   while a regex or keyword filter asking "is this a domain?" waves them through.

3. **`0.0.0.0` and `[::]` / `::`** — not in RFC1918, so private-range lists often
   omit them, yet several operating systems resolve them to loopback or the
   any-address, granting access to local services.

4. **DNS rebinding (TOCTOU)** — the domain resolves to a public IP during
   validation and to a private one during the request.
   The fix that should be there: resolve **once**, pin the IP, and use the pinned
   IP for every subsequent request. The tell: validation resolves the domain and
   the HTTP client then resolves it **again**.

5. **Redirects (3xx) to a private or metadata address** — the initial URL is
   public and passes the check, but `Location:` points at `169.254.169.254`.
   Fix: `allow_redirects=False`, or re-run the SSRF check on every redirect. The
   tell: only the input URL is validated and the client has `allow_redirects=True`.

6. **Cloud metadata endpoints** — `169.254.169.254` (AWS/GCP/Azure/DO) and the
   IPv6 IMDS form `fd00:ec2::254` (AWS).
   The ordinary link-local range `169.254.0.0/16` catches only the IPv4 form; the
   IPv6 metadata address needs a rule of its own.

7. **Alternate loopback forms** — `127.1`, `127.0.1`, `0`,
   `localhost.localdomain`, and any domain resolving into `127.0.0.0/8`.
   `http://0/` equals `0.0.0.0` on some systems.

8. **A keyword filter presented as a defence** — a substring denylist
   (`localhost/internal/corp/private`) is bypassed by a domain that resolves to a
   private IP without containing those words (`db.attacker.com` → A record
   `10.0.0.5`). A keyword filter is a UX hint, **not** a defence; the only real
   defence is resolve-then-check-the-IP.

## The quick audit question

Does the guard check the **resolved IP** or the **host string**? If the string,
items 1–2 and 7 almost certainly pass. If the IP but resolved **twice**, item 4.
If the IP once but the client follows redirects, item 5.
