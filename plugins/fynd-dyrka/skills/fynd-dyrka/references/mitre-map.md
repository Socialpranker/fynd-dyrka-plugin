# Mapping findings to MITRE ATT&CK

A lookup table for attaching an ATT&CK technique ID to a finding. Clients and
compliance functions (SOC teams, red-team reports) expect ATT&CK vocabulary
rather than free text. Use it manually: match by finding type or template first,
then by keywords in the title and description; if nothing matches, fall back to
the class default or leave it empty.

Precedence: an existing `mitre_id` is never overwritten → exact lookup by type →
keyword match → class default.

## By finding type / template

| Finding type | ATT&CK ID | Technique |
|---|---|---|
| Any service-exploitation CVE (`CVE-*`) | T1190 | Exploit Public-Facing Application |
| Subdomain takeover (aws/azure/github/heroku, dangling CNAME) | T1584.001 | Compromise Infrastructure: Domains |
| Default / weak credentials, default login | T1078 | Valid Accounts |
| phpinfo / debug page exposed | T1592.004 | Gather Victim Host Info: Client Config |
| Exposed `/.git/config` | T1213.003 | Data from Info Repos: Code Repositories |
| Exposed SQL dump / backup | T1213 | Data from Information Repositories |
| Swagger / GraphQL introspection open | T1592.001 | Gather Victim Org Info |
| CORS misconfiguration, SSRF, XXE, SSTI | T1190 | Exploit Public-Facing Application |
| Open redirect | T1204.001 | User Execution: Malicious Link |
| Weak cipher / expired TLS / bad issuer | T1040 | Network Sniffing |

## By keyword (fallback)

| Title or description contains | ATT&CK ID |
|---|---|
| leaked key/secret/token/credential/password | T1552.001 (Unsecured Credentials: Credentials in Files) |
| aws/github/slack/stripe … key | T1552.001 |
| private key | T1552.004 (Private Keys) |
| subdomain takeover | T1584.001 |
| `.git` open/exposed | T1213.003 |
| SQL injection / SQLi | T1190 |
| XSS / cross-site scripting / reflected | T1059.007 (Command & Scripting: JavaScript) |
| open port | T1133 (External Remote Services) |
| SPF / DMARC / DKIM (spoofability) | T1566.001 (Phishing: Spearphishing Attachment) |
| WAF detected | T1190 |
| any `CVE-\d{4}-\d{4,7}` with no explicit mapping | T1190 |

## Class defaults

When nothing matches, map by the nature of the finding:
- remotely exploitable service vulnerability → **T1190**;
- credential or secret problem → **T1552** (pick the sub-technique from context);
- reconnaissance / information disclosure → **T1592/T1595**;
- mail authentication problem → **T1566**.

Do not invent a precise sub-technique when unsure: the parent technique
(`T1552` rather than `T1552.001`) is more honest than a confidently wrong one.
