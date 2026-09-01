# Production deployment security (the platform layer)

`iac` reads files in the repository (Dockerfile, terraform, k8s manifests) — what
is *intended*. This file looks at the real state of production — what is
*deployed and configured right now*, including manual edits made in the
platform's console that no repository reflects. It is platform-agnostic;
concrete commands are given for Railway/Vercel/Fly/Heroku/k8s/Docker/AWS where
they apply.

## 1. Service exposure

| Question | Why it is bad | How to check |
|---|---|---|
| Does the database (Postgres/Mongo/MySQL) listen on a public address? | Direct access bypassing the API layer; brute force or a database exploit from outside | Railway: `list_domains` / `list_tcp_proxies` on the database service — is there an external proxy; `private_network_status`. Fly: `fly status` — the Services section, public ports. AWS: `aws rds describe-db-instances --query 'DBInstances[].PubliclyAccessible'` |
| Is Redis or the cache public and unauthenticated? | Full access to sessions and cache; a documented path to RCE — `CONFIG SET dir` + `dbfilename` + `SAVE` writing an SSH key or a cron entry to disk (redis.io/security); `MODULE LOAD` likewise, though it needs a `.so` on the host | An external port plus `redis-cli -h <host> ping` with no auth: `PONG` means no password, `NOAUTH` means protected. An empty answer probably means protected-mode is refusing it |
| Does a worker or queue listen on HTTP where it should not? | Extra attack surface on a component with no auth layer | List the project's services, then confirm for each whether an external domain was intended |
| Is the admin panel on a public domain with no additional protection (VPN, IP allowlist, Basic Auth in front of the app)? | The only barrier is the application's own login | Check the service's domains, and separately whether an admin route sits on the same domain as the public API |
| Are metrics endpoints (`/metrics`, `/actuator`, `/debug/pprof`) exposed? | Leaks versions and topology, sometimes tokens in labels | `curl <domain>/metrics` — the status code and whether data comes back unauthenticated |
| Are debug ports open (Node `--inspect`, .NET remote debug, Python `debugpy`, Java JMX)? | Full RCE through the debug protocol | The service's open port list; in configuration, launch flags such as `--inspect=0.0.0.0` |
| Does the managed database have both a private and a public endpoint? | The public endpoint is usually left "so we can connect locally" and then forgotten | Railway: compare `private_network_status` (which should carry service-to-service traffic) with `list_tcp_proxies`/`list_domains` (public access) — if both are active, the public one is almost never needed |

The classic: a managed Postgres with a public TCP proxy "so someone can connect
with DBeaver", holding production data behind a weak password. Ask directly:
"does anyone actually connect from outside on a regular basis, or was this left
over from a one-off debugging session?"

## 2. Environment variables and runtime secrets

| Question | Why it is bad | How to check |
|---|---|---|
| Where are secrets stored — a platform-native vault, or plaintext in config or the image? | Plaintext in a Dockerfile or image means the secret ships to the registry permanently | `docker history <image>` for `ENV`/`ARG` carrying secrets; grep the Dockerfile |
| Who on the team can see values, not merely names? | Excess access is an extra leak point | Roles and permissions on the platform (Railway teams, Vercel project members) |
| Are there placeholder defaults in code (`JWT_SECRET = "changeme"`, `os.getenv("KEY", "test")`)? | A forgotten default in production is a backdoor with no secret | grep for `getenv(..., "` with a non-empty second argument; compare against the actual runtime value |
| Do public-prefixed variables (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`) contain a secret by mistake? | A variable with that prefix is compiled into the client bundle and readable by anyone | grep the service's variable list for those prefixes and check each one for a broadly scoped key |
| Are the same secrets used across dev/staging/prod? | A leak from the dev environment (which is less protected) compromises production | Compare values, not names, between environments — Railway: `list_variables` per environment |
| Are secrets rotated, or have they lived since the project was created? | A key leaked a year ago still works | The variable's last-modified date where the platform shows it; otherwise ask the user |
| Is a `.env` with real values committed, or sitting in CI artefacts? | A secret in git history has leaked permanently | Already covered by the secrets layer; here the additional check is that runtime values do not match committed ones |

## 3. The dev/prod difference

| Question | Why it is bad | How to check |
|---|---|---|
| Is debug mode on in production (`DEBUG=True`, `NODE_ENV` not `production`, Flask/Django debug)? | Detailed stack traces and an interactive debug console (Werkzeug) mean RCE | `curl` a non-existent route or send malformed input and see whether a stack trace with paths and versions comes back |
| Are source maps (`.map`) reachable in production? | Deminification of the entire frontend, including internal logic and sometimes secrets | `curl <bundle>.js.map` — 200 or 404 |
| Are seed data or test accounts alive in production (`admin/admin`, `test@test.com`)? | A ready-made way in, bypassing normal signup | Check whether a seed script exists and whether it ran against the production database; attempt a login with known test credentials (only with permission) |
| Is CORS `*`, or does `Access-Control-Allow-Origin` reflect the Origin, left over from development? | Combined with credentials, session theft from any site (playbook 5 in `playbooks.md`) | `curl -H "Origin: https://evil.com" -I <api>` and read the response |
| Is TLS verification disabled on outbound requests (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False`, `curl -k`)? | MITM against all of the service's outbound traffic | grep environment variables and code for those flags |
| Is production logging at `debug`/`trace` level? | PII and tokens leak into logs that other people can read | The log level in the service's launch configuration |

## 4. Network and transport

| Question | Why it is bad | How to check |
|---|---|---|
| Is HTTPS enforced, with HTTP redirecting to it? | Traffic can be read or altered in transit | `curl -I http://<domain>` — expect a 30x to https, not a 200 |
| Is HSTS set (`Strict-Transport-Security`) with a sensible `max-age`? | Without HSTS, a downgrade attack on the first visit | `curl -I https://<domain>` — the header and its `max-age` |
| Is TLS at 1.2 or above, with weak ciphers disabled? | Obsolete TLS means known attacks (POODLE, BEAST) | `nmap --script ssl-enum-ciphers -p 443 <domain>` or `testssl.sh` |
| Is internal traffic between services (API↔DB, API↔worker) encrypted? | On a shared public network it can be intercepted where privacy is not guaranteed | Railway/Fly: is `private_network`/6PN used for service-to-service rather than public addresses |
| Are the project's services genuinely on a private network rather than merely adjacent? | Without one, an internal call is an external HTTP request visible from outside | Railway: `private_network_status`; Fly: `fly ips private`; k8s: whether a NetworkPolicy exists |

## 5. Data access

| Question | Why it is bad | How to check |
|---|---|---|
| Who can connect to the database — the whole internet, the VPC, or only the application service? | A wider circle is a wider attack surface | See §1 plus the platform's security groups and firewall rules |
| Does the application connect as a superuser, or as a dedicated least-privilege user? | Compromising the application then means full control of the database (DROP, access to other schemas) | The username in the connection string in environment variables; that user's grants in the database (`\du` in psql) |
| Are backups taken at all? | An incident or ransomware means total data loss with no recovery | The managed database's settings (Railway/RDS/Cloud SQL — automated backups on or off) and the schedule |
| Are backups encrypted at rest? | A leaked backup is the whole database in plaintext | Encryption settings on the storage holding backups (managed services usually encrypt by default — check it has not been disabled) |
| Has restoring from backup ever been tested? | A backup that does not restore is not a backup | Ask for the date of the last restore test; never is a red flag |
| Who has access to backups (a separate policy from production database access)? | Backups are often less protected than the database while holding the same data | Permissions on the backup bucket or storage, separately from the database's |

## 6. CI/CD and the supply chain

| Question | Why it is bad | How to check |
|---|---|---|
| Are CI secrets (GitHub Actions/GitLab CI) encrypted secrets, or plaintext YAML? | A secret in YAML has leaked into the repository's history | grep workflow files for literals instead of `${{ secrets.X }}` |
| Is there a `pull_request_target` that checks out a fork and then runs code or uses secrets? | The classic injection: a PR from a fork gains access to repository secrets | grep `.github/workflows/*.yml` for `pull_request_target` plus `actions/checkout` with `ref: ${{ github.event.pull_request... }}` |
| Who can deploy to production — any merge to main, only a tag or release, or a manual approval? | With no gate, compromising any contributor means a production deploy | Branch protection rules, and whether an environment gate with required reviewers exists |
| Are images signed (cosign/Notary), and is the signature verified before deploy? | Swapping the image in the registry between build and deploy goes undetected | Whether `cosign verify` appears in the deploy pipeline |
| Are base images official and version-pinned rather than `:latest`? | `:latest` means an unpredictable image on every build and a supply-chain risk from upstream | The `FROM` lines in the Dockerfile — is there a digest or version tag |
| Who has push access to the image registry? | Excess access means an image can be replaced directly, bypassing CI | Registry permissions (Docker Hub org, GHCR, ECR) |
| Are dependencies pinned by lock file and installed with `--frozen`/`--ci` rather than resolved fresh? | Version drift between the dev and production build (partly covered by the deps layer, but check the actual CI command) | The install command in CI — `npm ci` vs `npm install`, `pip install -r` without hash pinning |

## 7. Identity and access to the platform itself

| Question | Why it is bad | How to check |
|---|---|---|
| Is MFA enabled on the platform account (Railway/AWS/GitHub/Vercel)? | A leaked password means full access to all infrastructure | Account and organisation settings on the platform; ask the user when you have no access |
| Who on the team has production access — everyone, or only the roles that need it? | More people with access means more vectors (phishing, leaked credentials, offboarding leftovers) | The list of organisation/project members and their roles |
| Are platform API tokens scoped and time-limited, or permanent with full access? | A permanent full-access token is a standing key to everything if it leaks | The list of active tokens with creation and last-used dates |
| Do former team members still have access? | The classic orphaned access | Reconcile the member list against the current team |
| Is SSH to hosts key-based with a passphrase, or password/shared key? | A password or shared key makes it impossible to tell who logged in, and is easier to brute force | `sshd_config` — `PasswordAuthentication`, `PermitRootLogin` |
| Are deploy keys (GitHub deploy keys, CI service accounts) read-only where writes are unnecessary, and scoped to one repository? | A read-write deploy key leaked from CI means writes to every repository it can reach | Deploy key settings in GitHub/GitLab — permissions and scope |

## 8. Container and runtime

| Question | Why it is bad | How to check |
|---|---|---|
| Does the container process run as root? | A container escape immediately yields root on the host | `docker inspect <container> --format '{{.Config.User}}'` — empty or `0` means root; check for `USER` in the Dockerfile |
| Is `privileged: true` set where it is not strictly required? | Full access to host devices, bypassing most isolation | `docker inspect --format '{{.HostConfig.Privileged}}'`; in k8s, `securityContext.privileged` in the manifest |
| Are surplus Linux capabilities left in place (`--cap-drop=ALL` plus a targeted `--cap-add`)? | `CAP_SYS_ADMIN`, `CAP_NET_RAW` and friends widen the escape surface by default | `docker inspect --format '{{.HostConfig.CapAdd}} {{.HostConfig.CapDrop}}'` |
| Is `/var/run/docker.sock` mounted into the container? | Equivalent to root on the host — any container with any privileges can be started | `docker inspect --format '{{.Mounts}}'`, looking for `docker.sock` |
| Is the container filesystem read-only where nothing needs writing? | Without read-only, a successful RCE persists by writing into the container | `docker inspect --format '{{.HostConfig.ReadonlyRootfs}}'` |
| Are CPU and memory limits set? | Without limits, one service (or one memory leak) takes down the host and every neighbouring service | `docker inspect --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}'`; in k8s, `resources.limits`; on Railway/Fly, the service plan |

## 9. Observability and response

| Question | Why it is bad | How to check |
|---|---|---|
| Are significant events logged (auth failures, permission changes, payments, admin actions)? | An incident happens and leaves no trace to investigate | Inspect the log format for those events; Railway: `get_logs` on the service |
| Are secrets and PII kept out of the logs (passwords, tokens, card numbers, full emails in plaintext)? | Logs are a frequent leak point, and access to them is broader than to the database | grep real logs for token, email and card-number patterns |
| Are there anomaly alerts — a 5xx spike, an outbound traffic spike, a sudden burn of an external API quota? | Incidents and abuse are noticed only afterwards, from the invoice | Railway: `http_error_rate`, `service_metrics`; whether alerting exists (Sentry/Datadog/the platform's own) |
| Will anyone actually see the alert — is there a channel (Slack/PagerDuty/email) that someone reads? | An alert configured into the void is equivalent to no alert | Ask where alerts go and when anyone last acted on one |
| Is log retention long enough to investigate (usually 30 days or more)? | The log rotated away before the incident was noticed | Retention settings on the platform or log aggregator |

## 10. Configuration resilience

| Question | Why it is bad | How to check |
|---|---|---|
| Is there a health check (a functional one, not merely "the process is alive")? | The platform considers the service healthy while it answers 200 on `/` although the database behind it is unreachable | The service configuration — the health-check path and what it actually verifies |
| Is a restart policy set (`always`/`on-failure` with backoff, not `no`)? | A crashed process means downtime until someone intervenes | `docker inspect --format '{{.HostConfig.RestartPolicy}}'`; on Railway/Fly, the restart policy in the service config |
| What happens when a dependency (database, external API) is unavailable — degradation or a cascading crash? | One failed component takes the whole service down instead of degrading | Code — are there timeouts and circuit breakers on external calls; behaviour with the database stopped (tested separately) |
| Does autoscaling have an upper limit? | Without a ceiling, a DoS or a retry bug becomes an unbounded bill | Railway: `get_service_config`/`environment_status` — replica limits; AWS ASG — `MaxSize` |
| Are there quotas or rate limits on your side for billed external APIs (LLM, SMS, email provider)? | A leaked key or a looping bug means a bill in the tens of thousands within hours | The provider's settings — is there a spending limit or a daily quota |

## How to obtain platform configuration

| Platform | Method |
|---|---|
| Railway | MCP: `list_variables`, `get_service_config`, `list_domains`, `list_tcp_proxies`, `private_network_status`, `list_services`, `list_projects`, `environment_status`, `service_metrics`, `get_logs` |
| Vercel | `vercel env ls`, `vercel project ls`, `vercel inspect <deployment>` |
| Fly.io | `fly config show`, `fly secrets list`, `fly status`, `fly ips list`, `fly certs list` |
| Render | The Dashboard API (`GET /v1/services`) or the web console — the CLI is limited |
| Heroku | `heroku config`, `heroku ps`, `heroku domains`, `heroku pg:info` |
| Docker Compose / VPS | `docker inspect <container>`, `docker compose config`, `docker network inspect` |
| Kubernetes | `kubectl get pods,svc,ingress -o yaml`, `kubectl describe networkpolicy`, `kubectl get secrets` (names only, not values, without further rights) |
| AWS | `aws ec2 describe-security-groups`, `aws rds describe-db-instances`, `aws s3api get-bucket-acl`, `aws iam list-*` |
| GCP | `gcloud compute firewall-rules list`, `gcloud sql instances describe`, `gcloud iam service-accounts list` |

With no platform access (no MCP, no CLI session, no permissions) — **ask the
user** ("paste the output of `fly secrets list`", "open Railway → Variables and
tell me whether the database has a public proxy"). Do not invent configuration,
and do not treat a platform's default as an established fact.

## Red flags — say these immediately, not at the end of the report

- A managed database or Redis on a public address with a weak or default password.
- A broadly scoped secret in a variable prefixed `NEXT_PUBLIC_`/`VITE_`/
  `REACT_APP_`/`EXPO_PUBLIC_`.
- `pull_request_target` checking out fork PR code in a workflow that holds secrets.
- A Docker container with `/var/run/docker.sock` mounted and a public entry point
  (a web application, a queue worker).
- Debug mode or detailed stack traces answering on the production domain.
- The same secret (especially a payment, JWT, or broadly scoped API key) in dev
  and production at once.
- No MFA on an account with production access to the platform or cloud.
- No backups at all, or a restore that has never been tested.
