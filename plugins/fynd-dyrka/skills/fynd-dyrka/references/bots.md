# Auditing a bot as an interface

Read this when the target is a Telegram/Discord bot or a Mini App. A bot differs
from a web service in that **the transport belongs to someone else**: user
authentication is performed by the platform rather than by your code, and the bug
is usually not in the business logic but in how much its result is trusted.

Everything below is a question to ask the code, not a list of good intentions.
"I could not find where this is checked" is already a finding.

## 1. Request authenticity: who is actually talking to the bot

### Webhook

- Is it verified that the request came from Telegram? The mechanism is
  `secret_token` in `setWebhook`, delivered in the
  **`X-Telegram-Bot-Api-Secret-Token`** header.
- The webhook URL is **not a secret**: it leaks into logs, proxies, history. With
  no origin check at all, anyone who knows the URL can send arbitrary `Update`
  objects — on behalf of any `user_id`, including forged `successful_payment` and
  `callback_query`. That is a complete authorisation bypass **without knowing the
  bot token**.
- Compare the secret with `compare_digest`/`timingSafeEqual`, not `==`.

### Mini App `initData`

The algorithm (verified by computation, not from memory):

```
secret_key        = HMAC_SHA256(key="WebAppData", msg=bot_token)
data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields))   # hash excluded
expected          = HEX(HMAC_SHA256(key=secret_key, msg=data_check_string))
```

**The Login Widget derives its key differently** — `secret_key = SHA256(bot_token)`,
with no intermediate HMAC. The two are incompatible: validating Mini App data
with the widget's key always returns `False`. Copy-pasting between them is the
standard source of "the hash never matches", and the usual repair is to weaken
the validation.

What to look for in the code:

- is the `hash` field **excluded** from `data_check_string`? (otherwise it can
  never match);
- keys sorted lexicographically by byte, not locale-aware;
- constant-time comparison rather than `==`/`===`;
- `sha256`, and the key derived through `"WebAppData"`;
- URL-decoding performed exactly once;
- **most important:** what happens in the "did not match" branch? Look for a
  fallback such as "skip in dev" or "if there is no `initData`, take `user_id`
  from the request body". That branch nullifies the entire check — and it is
  usually the finding.

### Replay: `auth_date`

- Is `auth_date` checked for staleness? With no TTL, captured `initData` (logs, a
  screenshotted URL, a WebView) works **forever** — a full auth bypass with the
  original user's rights.
- Telegram does not publicly declare a hard window; practice is ≤3600 s, and
  300–900 s for sensitive operations. No TTL at all is a finding regardless of
  which number you would have picked.

## 2. Authorisation: what can be forged and what cannot

- `from.id` is controlled by Telegram and cannot be forged through a normal
  client — unless §1 is unmet, see the webhook above.
- ⚠️ In groups, anonymous administrators and messages sent on behalf of a channel
  do not carry the `from` the code expects — they carry **`sender_chat`**. A check
  of the form "this is an admin because `from.id` is in the list" does not behave
  as intended there.
- Admin commands (`/broadcast`, `/setprice`, `/grant`) — is there an allowlist by
  `user_id`, or is the protection that nobody knows the command name?
- **`callback_data` is untrusted input.** It comes from the client; third-party
  libraries and MTProto can send an arbitrary string. A bot that embedded a
  `user_id`, an amount or a permission in it (`grant_admin:456`) must re-check
  ownership and rights against `callback_query.from.id`, not against the string's
  contents. Size limit: 1–64 bytes of UTF-8.

## 3. Races on buttons

Two quick taps produce two `callback_query` events before the first is handled.
If the handler does read-modify-write (deduct points, grant a bonus, confirm an
order) that is the same double-spend as on the web.

What counts as a defence and what does not:

- ✅ an atomic conditional update (`UPDATE … WHERE status='pending'` plus a check
  of the affected row count) or `SELECT … FOR UPDATE`;
- ✅ a lock on `(user_id, action)` with a short TTL;
- ⚠️ idempotency on `callback_query.id` only protects against redelivery of **one**
  update, not against two distinct taps;
- ⚠️ `answerCallbackQuery` plus removing the keyboard is a UX layer on top of
  atomicity; on its own it does not close the race.

The "compare similar places" technique (Step 3) pays off especially here: a bot
usually has several button handlers, and typically only one of them is protected.

## 4. Incoming files and dialogue state

- Are the size and MIME type of incoming documents limited? Without that: DoS by
  large files, zip bombs and decompression bombs if the bot unpacks archives or
  processes images.
- Does a user-supplied filename reach the storage path? Path traversal.
- `file_id` is **not an access right**: it is valid only for the issuing bot, but
  is bound to no particular user. A bot that serves a file by `file_id` from the
  request without checking ownership in its own database leaks other people's
  content.
- Dialogue state (FSM): is it keyed by `user_id` **and** `chat_id`? Keying by only
  one of them mixes different people's sessions in groups. Is the state
  transition derived server-side, or dictated by what the client sent (see
  "Skipping process steps" in Step 3)?
