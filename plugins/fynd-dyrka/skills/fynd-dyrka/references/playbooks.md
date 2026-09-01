# Attack playbooks — a scenario checklist

Extends Step 3 (manual review). The open question "are there any logic flaws?" is
weak — it gives you nothing to grab. These playbooks give concrete, reproducible
scenarios: for each, the precondition, how to check, and the MITRE chain. Walk the
list and answer every item with "applies / does not apply / checked — clean".

## 8 playbooks (external + web)

1. **Recon → data breach**
   A leaked API key in production JS or in `.git` → access to data or cloud.
   Check: pull the JS bundles and `.git`, grep for keys; verify the key is live
   (a whoami call to the provider). Chain: T1595 → T1552.001 → T1213.

2. **Subdomain takeover**
   A dangling CNAME to an unclaimed service (S3/GitHub Pages/Heroku).
   Check: enumerate subdomains, find a CNAME to a non-existent bucket or app.
   Chain: T1590 → T1584.001 → T1566.001.

3. **Password-reset exploitation**
   Host-header injection in the reset email, a predictable token, no
   invalidation of the previous one. Check: how the reset token is generated,
   whether it is bound to the session, whether it expires, whether the domain in
   the link can be substituted. Chain: T1190 → T1078.

4. **API key in client-side JS**
   A secret (Stripe/Firebase/Maps with broad scope, a private key) in the
   frontend bundle. Check: scan JS for key patterns; assess the key's scope
   (publishable vs secret). Chain: T1592 → T1552.001.

5. **CORS → session theft**
   `Access-Control-Allow-Origin` reflects an arbitrary Origin together with
   `Allow-Credentials: true`. Check: send `Origin: https://evil.com` and see
   whether it is reflected alongside credentials. Chain: T1190 → T1539.

6. **Email spoofing / BEC**
   No SPF `-all` / DMARC `p=reject` → mail "from the company" is delivered.
   Check: `dig TXT` for SPF and `_dmarc`; see the matrix below. Chain: T1590 →
   T1566.001.

7. **Admin panel + default credentials**
   An exposed `/admin` with no rate limit plus default or weak accounts.
   Check: locate admin routes, verify auth and rate limiting, try typical
   defaults. Chain: T1133 → T1078 → T1190.

8. **Cloud storage misconfiguration**
   A public, listable S3/GCS bucket holding sensitive objects.
   Check: find bucket references in code and JS, test listing and ACLs.
   Chain: T1580 → T1530.

## Business-logic / access-control checklist

Makes the "logic flaws" of Step 3 concrete. Ask each separately:

- **Payment / process bypass** — can goods, credits or an upgrade be obtained
  without paying (a state transition taken from the client's request rather than
  from a server-side payment fact)?
- **IDOR (BOLA)** — substituting someone else's `id`; does the query filter by
  the current user's `userId`?
- **Privilege escalation** — can a role be raised: mass assignment
  (`{"role":"admin"}`), a separate "internal" endpoint with no role check?
- **JWT `alg:none`** — does the server accept a token with `"alg":"none"`, or an
  RS256→HS256 switch (signing with the public key)?
- **Session fixation** — does the session ID change after login?
- **Mass enumeration** — sequential IDs (`/user/1`, `/user/2`) with no rate limit
  → the whole user base can be pulled?
- **GraphQL introspection** — is `__schema` open in production, exposing the data
  model and hidden mutations?
- **Race conditions** — do concurrent balance debits, promo-code redemptions or
  invite uses drive state past what is allowed (see "compare similar places" in
  SKILL.md)?

## Email spoofability (SPF × DMARC matrix)

A cheap passive check — `dig TXT` only. Spoofing risk:

| SPF | DMARC | Risk |
|---|---|---|
| none | none | **CRITICAL** — mail is spoofable freely |
| `~all` (soft) or `?all` | `p=none` | **HIGH** |
| `-all` (hard) | `p=none` or `pct<100` | **MEDIUM** |
| `-all` | `p=quarantine` | **LOW-MEDIUM** |
| `-all` | `p=reject`, `pct=100` | **LOW** — correct configuration |

`pct=` below 100 in DMARC means partial enforcement: lower your confidence in
"protected". DKIM is checked separately (presence of a selector), but SPF plus
DMARC is the primary signal.
