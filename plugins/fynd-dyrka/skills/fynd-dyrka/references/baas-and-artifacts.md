# BaaS access rules and secrets in build artifacts — Step 3, queue 6c

Two neighbouring blind spots. **Backend-as-a-service rules** (Supabase RLS,
Firebase rules) are authorisation written in SQL or a rules DSL, invisible to
SAST and to most reading: a table with no policy is not "code that is wrong", it
is code that is absent. **Artifacts** (a production source map, a Docker image, a
built client bundle) carry secrets and source that never appear in the
repository's working tree, so `gitleaks` over the repository says nothing about
them.

**Marking.** **[confirmed]** — read in the cited documentation or repository
during the wave-1 research (page summaries, not raw text) or reproduced in this
repository's own run. **[assumption]** — my reasoning or general practice, not
checked against a source. **[hypothesis]** — an idea worth testing, to be
verified on a live example before it is trusted. **[not confirmed]** — looked for
and not found. Carry these marks into the report.

## 1. Supabase: Row Level Security from the migrations

Supabase's database linter (Advisors) has these rules **[confirmed]**, source
`supabase.com/docs/guides/database/database-linter`:

| Id | What it flags | In `scan_supabase_migrations` |
|---|---|---|
| `0013_rls_disabled_in_public` | table in `public` without RLS | yes |
| `0007_policy_exists_rls_disabled` | policies exist but RLS is off | yes |
| `0008_rls_enabled_no_policy` | RLS on, no policy | no |
| `0024_permissive_rls_policy` | `USING (true)` / `WITH CHECK (true)` | yes |
| `0015_rls_references_user_metadata` | a policy reads `user_metadata` | yes |
| `0010_security_definer_view` | view with the security-definer property | yes (view without `security_invoker`) |
| `0011_function_search_path_mutable` | function without a fixed `search_path` | yes, for `SECURITY DEFINER` functions |
| `0028` / `0029` `*_security_definer_function_executable` | definer function callable by anon / authenticated | no (asks who may `EXECUTE`) |
| `0023_sensitive_columns_exposed`, `0025_public_bucket_allows_listing`, `0002_auth_users_exposed`, `0016_materialized_view_in_api`, `0026` / `0027` pg_graphql exposure | as named | no |

The linter **needs a live database connection**; it runs from Studio, `supabase db
advisors` (CLI), the MCP `get_advisors` tool or the Management API
**[confirmed]**. The CLI flags and whether it accepts a local or ephemeral
database were **not** confirmed. Without a database, this skill reads the SQL.

**The check** (`scan_supabase_migrations`, layer `iac`, stdlib only): reads every
`*.sql` under a `migrations/` or `supabase/` directory in path order, understands
comments, quoted strings and `$$` bodies, tracks state across files (an `ENABLE
ROW LEVEL SECURITY` in a later migration covers a table created earlier), and
reports `CREATE TABLE` in `public` never covered by `ENABLE ROW LEVEL SECURITY`,
policies with `USING (true)` / `WITH CHECK (true)`, a policy that references
`user_metadata`, `SECURITY DEFINER` functions with no `SET search_path` (in the
statement or a later `ALTER FUNCTION`), and views without `security_invoker`. A
policy restricted to `service_role` is skipped. Findings are MEDIUM/HIGH and their
description says **"heuristic candidate, verify against the live DB"**. Fixtures
with a bad and a clean migration are in `fixtures/supabase-rls/`.

**Where it is wrong.** A migration is not the state of production: a dashboard edit,
a table created by hand or a policy dropped in the console is invisible to it —
that is the `platform` layer's question (`platform.md`). `0024` and `0013` fire on
tables that are intentionally public, reference data for example **[assumption]**.
`GRANT … TO anon/PUBLIC` in migrations is not checked, and no tool for it was
found **[not confirmed]**. Squawk (`pip install squawk-cli`) lints migrations
statically without a database, but its confirmed rules are about downtime and
destructive changes (`ban-drop-column`, `require-concurrent-index-creation`), not
access control; its licence was not confirmed. A hybrid — apply the migrations to
an ephemeral Postgres and query `pg_catalog` (`relrowsecurity`) or run Advisors
against it — is an idea **[hypothesis]**; nothing confirms that Advisors accepts a
local database.

**A `service_role` key in a client bundle** **[hypothesis]** — a source for this
was not found. The idea: a Supabase key is a JWT whose payload carries a `role`
claim; the `service_role` one bypasses RLS, and it must never reach a browser or a
mobile app. Search the repository and the built bundle for JWT-shaped strings and
decode the payload. `gitleaks` / `trufflehog` are the baseline **[assumption]**.
Verify on a live bundle before relying on it. A minimal stdlib check, run on a
synthetic bundle in this wave:

```python
import base64, json, re, sys, pathlib
JWT = re.compile(r"eyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}")
def role_of(token):
    p = token.split(".")[1]
    try:
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("role")
    except (ValueError, UnicodeDecodeError):
        return None
for f in pathlib.Path(sys.argv[1]).rglob("*"):
    if f.is_file() and f.suffix in {".js", ".mjs", ".html", ".map", ".json", ".env"}:
        for m in JWT.finditer(f.read_text(errors="replace")):
            if role_of(m.group(0)) == "service_role":
                print(f"{f}: JWT with role=service_role ({m.group(0)[:12]}...)")
```

The `anon` key is meant to be public **[assumption]**; the finding is `service_role`, and its
severity depends on the key being live (check it as the "When a finding requires
action" section of `SKILL.md` describes — with the provider's own whoami-style
endpoint, not an action with side effects).

## 2. Firebase rules

Source: `firebase.google.com/docs/rules/insecure-rules` **[confirmed]**. The
patterns it names as insecure:

- Firestore: `allow read, write: if true;`
- Realtime Database: `".read": true, ".write": true`
- Storage: `allow read, write;` (no condition)
- "any signed-in user": `request.auth != null` / `request.auth.uid != null`
  (Firestore, Storage), `auth.uid !== null` (RTDB) — authentication used as
  authorisation, so any account, including one the attacker registers, passes.
- RTDB: a rule on a child does not revoke a permission granted on its parent.

No static linter for Firebase rules was found **[not confirmed]**; testing is done
with the Firebase Emulator Suite, the Rules Simulator or the Firebase CLI
**[confirmed]**. Detection is a grep over `firestore.rules`, `database.rules.json`
and `storage.rules`, no database needed. False positives: `if true` on
intentionally public read, and `auth != null` on content that is public anyway
**[assumption]**.

## 3. Source maps in production

A `.map` file carries the original sources in `sourcesContent`, so a production
map deminifies the whole front end, including internal logic and sometimes
secrets. What the sources say **[confirmed by a search summary — the pages were not
read in full]**: `sourcesContent` holds the sources whole; the `//#
sourceMappingURL` comment is visible in the bundle; `devtool: 'hidden-source-map'`
removes the comment but the `.map` may still sit on the server; the manual check
is to append `.map` to the JavaScript URL; the fix is `sourcemap: false`, or hidden
maps uploaded to an error tracker, or denying `*.map` in the web root.

**Procedure.**

1. Static: `sourcemap: true` / a `devtool` that emits maps in the production build
   config.
2. Fetch `<bundle>.js.map` from the production URL. **This is an active request to
   the target** — the Step 4 gate applies (`localhost` is free; a public host only
   after the user confirms the right to test it).
3. If it returns 200 with a non-empty `sourcesContent`, extract the sources and
   scan them: **[assumption: this pipeline is my design; only the filesystem scan
   of TruffleHog is confirmed as a capability]**

```python
import json, pathlib, sys
def extract(map_path, out_dir):
    m = json.load(open(map_path, encoding="utf-8"))
    n = 0
    for name, text in zip(m.get("sources", []), m.get("sourcesContent") or []):
        if text is None:
            continue
        rel = pathlib.PurePosixPath(name.split("://")[-1].lstrip("/"))
        dest = pathlib.Path(out_dir, *[p for p in rel.parts if p not in ("..", ".")])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        n += 1
    return n
print(extract(sys.argv[1], sys.argv[2]), "source files written")
```

then `gitleaks dir -v <out_dir>` **[confirmed subcommand]**. Ready-made extractors
exist (mapxtractor, sourcemapper, unwebpack-sourcemap), but their licences and
install commands were **not confirmed**, which is why the snippet above is
stdlib. Expect false positives from public keys. A map on production is a finding
in itself even with no secret in it: the source of the auth and pricing logic is
now in an attacker's hands, and it makes every other finding easier to weaponise
**[assumption: my judgement]**.

## 4. Docker image layers

A secret deleted in a later layer is still in the earlier one; the image on the
registry is the artifact, not the Dockerfile.

- **`docker history <image>`** for `ENV` / `ARG` carrying secrets (also in
  `platform.md` §2).
- **Trivy** — Apache-2.0, `brew install trivy`, `trivy image python:3.4-alpine`;
  scanners `vuln`, `secret`, `misconfig` (README example: `trivy fs --scanners
  vuln,secret,misconfig myproject/`) **[confirmed]**. The exact `trivy image
  --scanners secret` combination is not shown literally in the README
  **[not confirmed literally]** — check `trivy image --help`. Trivy is already in
  the skill for `fs` and `config`.
- **TruffleHog** — reads Docker images, S3, GCS, the filesystem, git, Jenkins,
  CircleCI and Travis CI **[confirmed]**; `brew install trufflehog`, or the
  `trufflesecurity/trufflehog` Docker image. **Two cautions, both confirmed:**
  its verification step **makes live requests to the provider** (for AWS it calls
  `GetCallerIdentity`) — an **external effect**: the request leaves your machine
  with the found credential, so do not run it over a client's or a third party's
  images without the owner's consent, and name the effect to the user first. A
  flag that turns verification off exists but was **not confirmed**. The licence
  is **AGPL-3.0** — call it as an external tool, do not vendor it into this
  plugin (a licensing judgement of mine, not a legal opinion **[assumption]**).
- **Checkov** — `checkov --docker-image <img>:tag --dockerfile-path
  /path/to/Dockerfile` **[confirmed]**; Apache-2.0.
- False positives: test and example keys, and public keys (anon/publishable)
  **[assumption]**.

## 5. PII in logs and schema — technical checks only

What can be looked for **in code and schema**, without claiming a legal outcome —
a design of this skill, not taken from a source **[assumption]**:

| Check | Where |
|---|---|
| PII-looking columns (email, phone, birth date, document numbers) | migrations, models |
| a deletion path exists for them: `ON DELETE CASCADE`, a `DELETE` endpoint, a TTL or cron job | migrations, routes, jobs |
| request bodies or user objects written to a logger | `logger.info(req.body)`, `console.log(user)`, error handlers that dump the request |
| `identify(email)` and similar calls to an analytics SDK | client and server code |
| the region of the database or bucket, at-rest encryption flags, public buckets | Terraform, platform configuration |

Presidio (MIT; analyzer, anonymizer, image-redactor, structured packages) finds PII
in text, logs and fixtures; its README says it does not find everything
**[confirmed]**; the exact `pip install` line and out-of-the-box recognisers for
Russian identifiers (INN, SNILS, passport) were **not confirmed**, and false
positives are high **[assumption]**. It is not wired in.

**Not checkable from code, so say so in Coverage:** the legal basis for
processing, the validity of consent, whether a retention period is proportionate,
processor agreements, regulator notifications, and purging backups and external
analytics copies. Legal requirements are deliberately not cited in this file: they
were not verified in the research, and a wrong article number in a report is worse
than none.
