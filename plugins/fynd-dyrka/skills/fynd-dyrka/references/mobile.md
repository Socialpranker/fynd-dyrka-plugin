# Mobile apps and analytics SDKs — Step 3, queue 6b

For a target that ships as an Android/iOS application, or as a library embedded in
someone else's app (an analytics or payments SDK). The attacker is the device
owner, another app on the same device, a network attacker, and — for an SDK — the
**host app's users**, whose data the SDK sees. Much of what matters here lives on
the device at runtime, out of reach of a static read; this file separates the two
so the report never presents "not looked at" as "clean".

**Marking.** **[confirmed]** — read in the cited documentation or repository during
the wave-1 research (through page summaries, not raw text) or reproduced in this
repository's own run. **[assumption]** — general practice, not checked against a
source. **[not confirmed]** — looked for and not found. Carry these marks into the
report.

**Reference frame: OWASP MASVS / MASTG.** MASVS has eight control groups — STORAGE,
CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY **[confirmed]**. The
current MASVS version is v2.1.0 according to MASTG release notes; a newer one was
not found **[confirmed, negative]**. MASTG v2.0.0 (2026-06-30, the first stable
release) marks every test **static / dynamic / network / best-practices**
**[confirmed]**, which is exactly the split below. Cite the control (for example
MASVS-NETWORK-1) in a finding. The MASTG text is CC-BY-SA-4.0 **[confirmed]**:
cite and link, do not paste it into a report.

## 1. What a static review can and cannot say

| Statically, from the repository or a built artifact | Only dynamically — write **"requires manual dynamic testing"** |
|---|---|
| manifest / `Info.plist` / network security config, ATS, backup rules | what the app actually stores after real use (files, databases, `SharedPreferences`, `UserDefaults`) |
| exported components, permissions, deep-link handlers | what really goes over the network, **including what an SDK sends on its own** |
| hardcoded secrets and keys, embedded endpoints | whether pinning holds and how it is bypassed; root/jailbreak detection |
| weak crypto, trust-all `TrustManager` / `HostnameVerifier`, WebView flags | Keychain / Keystore contents; clipboard, screenshots and logs at runtime |
| privacy declarations, dependency versions | whether an exported component is actually exploitable |

Tools that need a device or emulator (Frida, `adb`, `idevicesyslog`, a proxy such
as Burp) belong to the right-hand column. Without a device, the right-hand column
goes into the Coverage section verbatim as **"requires manual dynamic testing"**,
one line per item, never as a finding and never as clean **[confirmed as the
MASTG split; the wording rule is this skill's]**.

## 2. Android

Read `AndroidManifest.xml` (the **merged** one for an app with libraries: a
library adds components and permissions to it) and `res/xml/`:

| Look for | Why |
|---|---|
| `android:debuggable="true"` in a release build | a debugger can attach, dump stack traces and helper classes |
| `android:allowBackup="true"`, and what `backup_rules.xml` excludes | app data copied off via `adb backup`; MASTG-TEST-0262 (Static, MASVS-STORAGE-1) reads `backup_rules.xml` **[confirmed]** |
| `android:usesCleartextTraffic="true"`, `android:networkSecurityConfig` | MASTG-TEST-0235 (Static, MASVS-NETWORK-1) **[confirmed]** |
| `android:exported="true"` with no `android:permission` | any app on the device can start the component; an intent-filter makes `exported` legitimate for the launcher and deep links, so an exported component with an intent-filter is a question, not a verdict **[confirmed as the false-positive source]** |
| permissions the function does not need | excess authority; for an SDK, a permission the host app would then inherit **[assumption]** |
| deep-link handlers, WebView with a JS bridge or file access | the SDK classes in the Oversecured post: exported components and intent redirection, WebView bridges, insecure deep links **[confirmed]** |

**Network security config** (developer.android.com **[confirmed]**): cleartext is
off by default from API 28; `<base-config cleartextTrafficPermitted="true">` or a
`<domain-config>` re-enables it; `<pin-set expiration="yyyy-MM-dd">` — **after the
date the pinning is silently off**; `<certificates src="user"/>` trusts
user-installed CAs; `<debug-overrides>` applies only when the app is
`debuggable`. Check: cleartext permitted anywhere, user CAs trusted in a release
build, a pin-set with an expired date or no backup pin **[assumption on "backup
pin"]**. The config may sit in `res/xml/` under any file name — follow the
manifest attribute rather than guessing the name.

In code (static): a `TrustManager` whose `checkServerTrusted` does nothing, a
`HostnameVerifier` that returns `true`, an `OkHttp` client built with a custom
trust, `http://` literals in endpoint constants **[assumption: the standard
patterns]**.

## 3. iOS

`Info.plist` and the surrounding files:

| Look for | Why |
|---|---|
| `NSAppTransportSecurity` → `NSAllowsArbitraryLoads = true` | turns ATS off for every domain not listed in `NSExceptionDomains` **[confirmed]**. It is often set for web-content or media loading, so ask what needs it before rating it. The exact names of the finer ATS keys (for example the web-content variant) were **not verified** **[not confirmed]** |
| `CFBundleURLTypes` (custom URL schemes), `*UsageDescription` | which entry points exist and which permissions the app can request **[assumption: standard `Info.plist` keys]** |
| `PrivacyInfo.xcprivacy` in the app **and in every embedded SDK** | Apple's privacy manifest holds `NSPrivacyTracking`, `NSPrivacyTrackingDomains`, `NSPrivacyCollectedDataTypes`, `NSPrivacyAccessedAPITypes`; a third-party SDK should carry its own **[confirmed]**. Checking that the declaration matches what the code really does is manual. Enforcement dates and signing of SDK manifests: **[not confirmed]** |
| `URLSessionDelegate` that accepts any challenge; no pinning | `didReceive challenge` without an evaluation is the iOS counterpart of a trust-all `TrustManager` **[assumption]**; pinning effectiveness is dynamic (MASTG-TEST-0068 **[confirmed]**) |

Swift support in Semgrep was "experimental" in an April 2024 post; the current
state is **[not confirmed]**, and Semgrep CE analyses taint inside one function
only **[confirmed]** — Swift and Kotlin results are candidates with more noise
than Python or TypeScript.

## 4. Secrets in built artifacts

A key may never enter git and still ship inside the binary — a different surface
from `gitleaks` over the repository.

- **Unpack, then scan the directory.** An APK, IPA and AAR are ZIP archives; a
  React Native bundle is a JS file **[assumption: general knowledge]**. Then
  `gitleaks dir -v <dir>` — the `dir` subcommand exists **[confirmed]**.
- **apkleaks** — extracts URIs, endpoints and secrets from an APK via jadx plus
  regex; Apache-2.0, `pip3 install apkleaks`, `apkleaks -f app.apk`, custom
  patterns with `-p rules.json`; **needs jadx installed** **[confirmed]**; jadx's
  own licence and install line **[not confirmed]**. Not wired into `scan.py`.
- **False positives are the norm.** Firebase, Google Maps and analytics keys are
  public by design; what makes one dangerous is the absence of restrictions on
  the key **in the provider's console, not in the code** **[assumption: general
  knowledge, source not opened]**. Report "a key present, restrictions not
  verifiable from here", not "leaked secret".

## 5. Checklist for an analytics SDK (code you embed in other people's apps)

The SDK sees identifiers, screens, sometimes text a user typed. What goes wrong is
mostly on the wire and on disk, and the wire part is dynamic.

| Check | What to look at | Static or dynamic |
|---|---|---|
| **Event queue on disk** | the queue's storage — SQLite, a file, `SharedPreferences`, `UserDefaults`, a plist — encrypted or file-protected? Session tokens, device fingerprints, user ids stored beside events (a class from the Oversecured SDK post **[confirmed]**). Which iOS file-protection class or Android Keystore wrapper applies: **[not confirmed]**, verify in the code | static to find the writes; **dynamic** for the actual contents |
| **PII in `track()`** | taint from user fields (login, forms, `identify(email)`) to `track()`/`log()`/the HTTP body; automatic screen or input capture must exclude password fields. Semgrep CE covers a single function only **[confirmed]** | static candidate; **dynamic** to prove what is sent |
| **`http://`** | endpoint constants, remote-config URLs, cleartext permitted in the network config | static |
| **Own trust code** | a custom `TrustManager` / `HostnameVerifier` / `URLSessionDelegate`; pinning absent, or a pin with no backup/expiry (§2) | static; pinning bypass is **dynamic** |
| **Manifest of the SDK** | extra permissions, `exported` components, deep-link handlers with no origin check, a WebView with a JS bridge or file access | static; exploitability is **dynamic** |
| **Keys inside the SDK** | hardcoded keys in wrappers (Oversecured **[confirmed]**); `gitleaks dir` / `apkleaks` over the built AAR / xcframework and its resources (§4) | static |
| **Privacy declaration** | its own `PrivacyInfo.xcprivacy` in the xcframework, with correct `NSPrivacyAccessedAPITypes` / `NSPrivacyCollectedDataTypes` | static presence; match with behaviour is manual |
| **Regression between versions** | a minor update of an analytics library began sending login and password in requests to the vendor's backend — found by capturing traffic and searching for "password" (Cossack Labs **[confirmed]**). Pin the SDK version, diff the payload between versions, scan build artifacts for PII/token patterns, force-update | **dynamic** (Burp or a proxy) |

The last two rows are why "the SDK passed a static scan" is never the whole
answer: the leak that made the news was found by looking at traffic.

## 6. Tools

| Tool | Facts | Status here |
|---|---|---|
| **mobsfscan** | static scanner for Java, Kotlin, Android XML, iOS `Info.plist`, Swift, Objective-C; semgrep + libsast engines, MobSF rules; LGPL-3.0; `pip install mobsfscan`, `mobsfscan <dir>`; JSON / SARIF output **[confirmed]** | wired as `scan_mobsfscan` (layer `sast`); runs only when Android (`AndroidManifest.xml` + `.kt`/`.java`) or iOS (`.swift` / `Info.plist`) sources exist, else `skipped` with the reason |
| **apkleaks** | §4 | recommended, not wired in |
| **MobSF** (the full platform) | APK/IPA/APPX and source, static + dynamic; GPL-3.0; `docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest`; **default login `mobsf`/`mobsf`**; REST API for CI **[confirmed]** | not wired in. If you run it: bind to `127.0.0.1` and change the default password (**recommendation without a source**); do not run its dynamic analysis from this skill |
| **gitleaks** | `dir` subcommand, MIT **[confirmed]** | already the `secrets` layer; use it on unpacked artifacts (§4) |
| Semgrep rule packs by insideapp-oss and akabe1 (Swift) | small repositories; **licences not confirmed** | do not add without reading their `LICENSE` |

What `scan_mobsfscan` does in this repository, observed on small Android and iOS
projects written for the wave: it reports manifest flags (debuggable, backup,
cleartext, exported-activity task hijacking), `ios_ats_arbitrary_loads`, weak
hash usage; it also emits **INFO-level absence rules** (no pinning, no root
detection, no screenshot prevention) that have no file location — treat those as
prompts for the threat-model question, not defects; it reports line 1 for matches
in XML regardless of the real line, so the layer omits the line for `.xml` /
`.plist`; and it scans `node_modules` unless told otherwise, so the layer passes a
config that ignores the vendored directories. It also exits 0 with an empty
result for a path that does not exist, which the layer turns into `error`.

## 7. Flutter and React Native

**No ready-made static scanner for either was found.**

- **React Native** — the logic is a JS bundle plus Hermes.
  What works today: `gitleaks dir` and Semgrep JS/TS over the sources and the
  unpacked bundle; look for tokens in `AsyncStorage` and for `http://` endpoints
  **[assumption]**. Hermes makes reading a built bundle harder (blog posts, not primary sources).
- **Flutter** — release builds compile Dart ahead of time into `libapp.so`;
  Java-oriented analysers do not read the Dart snapshot (blog posts, not primary
  sources **[confirmed as reported]**). What is left is strings extracted from
  `libapp.so` and your own scripts. `blutter` and `reFlutter` appeared in search
  results; their repositories were not opened, so existence, licence and
  behaviour are **[not confirmed]**.

Say so in the report: "Flutter/RN sources reviewed by reading and secret scanning
only; no static mobile scanner covers them".

## 8. What goes into the report

- Findings from the static column with the MASVS control.
- One Coverage line per dynamic item (§1) — **"requires manual dynamic testing"** —
  and, for an SDK, the explicit statement that the payload the SDK sends was not
  captured.
- Keys found in an artifact as "present; restrictions not verifiable from code",
  with the provider's console as the place to check.
