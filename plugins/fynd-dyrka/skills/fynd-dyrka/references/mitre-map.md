# Маппинг находок на MITRE ATT&CK

Справочник для простановки ATT&CK technique ID на находку. Заказчики и
комплаенс (SOC, red-team отчёты) ожидают ATT&CK-язык, а не произвольный текст.
Применяй как lookup вручную: сначала по типу/шаблону, потом по ключевым словам
в заголовке+описании; не нашёл — ставь по классу (см. дефолты) или оставь пустым.

Приоритет: уже проставленный `mitre_id` не перезаписывать → точный lookup по
типу → keyword-матч → дефолт по классу.

## По типу находки / шаблону

| Тип находки | ATT&CK ID | Техника |
|---|---|---|
| Любой CVE эксплуатации сервиса (`CVE-*`) | T1190 | Exploit Public-Facing Application |
| Subdomain takeover (aws/azure/github/heroku, dangling CNAME) | T1584.001 | Compromise Infrastructure: Domains |
| Default / weak credentials, default-login | T1078 | Valid Accounts |
| phpinfo / debug-страница раскрыта | T1592.004 | Gather Victim Host Info: Client Config |
| Открытый `/.git/config` | T1213.003 | Data from Info Repos: Code Repositories |
| Exposed SQL dump / backup | T1213 | Data from Information Repositories |
| Swagger / GraphQL introspection открыт | T1592.001 | Gather Victim Org Info |
| CORS misconfig, SSRF, XXE, SSTI | T1190 | Exploit Public-Facing Application |
| Open redirect | T1204.001 | User Execution: Malicious Link |
| Weak cipher / expired TLS / bad issuer | T1040 | Network Sniffing |

## По ключевым словам (fallback)

| В заголовке/описании встречается | ATT&CK ID |
|---|---|
| утечка key/secret/token/credential/пароль | T1552.001 (Unsecured Credentials: Creds in Files) |
| aws/github/slack/stripe … key | T1552.001 |
| private key | T1552.004 (Private Keys) |
| subdomain takeover | T1584.001 |
| `.git` open/exposed/открыт | T1213.003 |
| SQL injection / SQLi | T1190 |
| XSS / cross-site scripting / reflected | T1059.007 (Command & Scripting: JavaScript) |
| open port / открытый порт | T1133 (External Remote Services) |
| SPF / DMARC / DKIM (spoofability) | T1566.001 (Phishing: Spearphishing Attachment) |
| WAF detected / WAF обнаружен | T1190 |
| любой `CVE-\d{4}-\d{4,7}` без явного маппинга | T1190 |

## Дефолты по классу

Не подошло ничего — ставь по природе находки:
- удалённо эксплуатируемая уязвимость сервиса → **T1190**;
- проблема с учётками/секретами → **T1552** (нужный саб-техник по контексту);
- разведка/раскрытие информации → **T1592/T1595**;
- проблема почтовой аутентификации → **T1566**.

Не выдумывай точный саб-техник, если не уверен: родительский техник (`T1552`
вместо `T1552.001`) честнее, чем неверный конкретный.
