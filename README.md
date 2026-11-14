# Pushover (E2E) – Zabbix media type with end-to-end encryption

[![tests](https://github.com/toffelwurst/zabbix-pushover-e2e/actions/workflows/tests.yml/badge.svg)](https://github.com/toffelwurst/zabbix-pushover-e2e/actions/workflows/tests.yml)

The official Zabbix 8.0 Pushover webhook, extended with optional **end-to-end encryption**
as documented by Pushover (<https://pushover.net/api#e2ee>). With a key configured, Zabbix
encrypts `title`, `message` and `url` before sending (`url_title` is left out, see *Length limits*). Pushover's servers only see
ciphertext, and only your Pushover app (iOS/Android, app version 5.0 or later) can decrypt it.

With `e2e_key` set to `off` the webhook behaves exactly like the official one.

> Status: tested offline, in Zabbix 8.0 (Duktape engine) and live against the Pushover API and app.
> In production use since November 2026 on Zabbix 8.0.0. Small, dependency-free, **not audited by a third party**.

Upstream feature request: [ZBXNEXT-10909](https://support.zabbix.com/browse/ZBXNEXT-10909) – optional e2ee in the
official Pushover media type, with this repository as a proof of concept.

## Why a separate media type?
- The official Zabbix Pushover webhook does not support Pushover e2ee.
- The Zabbix webhook JavaScript engine (Duktape) has no AES, no gzip and no secure random generator
  (Zabbix 8.0 does offer `sha256()`, `hmac()` and `btoa()`, also for binary data).
- This media type therefore ships a small pure-ES5 implementation (`src/pushover_e2e_lib.js`). SHA-256, HMAC and
  Base64 are included as well, so the whole scheme lives in one file that is tested on its own:
  - SHA-256 and HMAC-SHA256 over bytes
  - AES-256-CBC with PKCS#7 padding
  - gzip using deflate *stored* blocks (valid RFC 1952, no compression)
  - Base64
- It is imported under its own name **"Pushover (E2E)"**, next to the official "Pushover". Zabbix upgrades do
  not overwrite media types. The 8.0 upgrade notes say: "templates and media types are not upgraded
  automatically".

## Scheme (per field, as specified by Pushover)
```
gzip(utf8(plaintext))
  -> AES-256-CBC, PKCS#7, 16-byte IV
  -> HMAC-SHA256(key, IV || ciphertext)
  -> base64(IV || ciphertext || HMAC)
```
One 256-bit key (64 hex characters) is used for both AES and HMAC, and the request carries `"encrypted": 1`.

## Installation
1. In the Pushover app (iOS/Android 5.0+), enable end-to-end encryption and note the 64-hex-character key.
2. In Zabbix, go to *Administration → Macros* and create a global macro `{$PUSHOVER.E2E.KEY}`.
   Set its type to **Secret text** and paste the key as the value.
3. Go to *Alerts → Media types → Import* and import `dist/media_pushover_e2e.yaml`.
4. Open the media type "Pushover (E2E)":
   - Set `token` to your Pushover application token.
   - Adjust `priority_*` as needed, e.g. disaster = 2 (emergency).
   - Optional: `priority_resolved` = `-1` sends recovery messages quietly (see below).
   - Enable the media type.
5. Assign the media type to a user: *Send to* = your Pushover user key.
6. Trigger a test problem and check that it arrives (see *Verifying encryption*).

The `e2e_key` parameter defaults to `{$PUSHOVER.E2E.KEY}`.
- **Macro defined:** messages are encrypted.
- **Macro not defined (or renamed, mistyped) or empty:** the webhook **fails** with
  `e2e_key contains an unresolved macro …` or `e2e_key is empty …` and sends nothing. There is no silent fallback
  to plaintext.
- **`e2e_key` set to `off`:** messages are sent unencrypted, exactly like the official media type.

You can also put the key directly into `e2e_key`, but a secret macro keeps it out of the media type
configuration and exports.

### One key per media type
All recipients of this media type must use the same key in their Pushover app. For recipients with different
keys, clone the media type and point each copy's `e2e_key` at its own secret macro.

### Recovery priority (`priority_resolved`)
The upstream script already maps recovery messages to a severity called "resolved" and looks up
`priority_resolved`, but upstream ships no such parameter, so recoveries always use `priority_default`.
This media type adds the parameter (empty = `priority_default`). With `-1` recoveries arrive without sound or
vibration, which pairs well with audible problem notifications.

## Key rotation
1. Create a new key in the Pushover app. From then on the app decrypts only messages encrypted with the new key.
2. Update the secret macro `{$PUSHOVER.E2E.KEY}` right away (*Administration → Macros*, "Set new value").
   Messages sent in between cannot be decrypted by the app.
3. Trigger a test problem.

## Verifying encryption
The Pushover app shows encrypted and plaintext messages the same way, and *Reports → Action log* always shows the
message as Zabbix rendered it (plaintext). To see what actually goes over the wire:
- set the `endpoint` parameter temporarily to a request catcher you control (the test suite ships one:
  `test/echo_server.py`) and look for `"encrypted": 1` and base64 fields, or
- raise the debug level of the alerter and read the webhook request in the Zabbix server log.

## Troubleshooting
| Symptom | Cause |
|---|---|
| `e2e_key contains an unresolved macro {$…}` | The macro does not exist (or has another name). Define it, or set `e2e_key` to `off` to send without encryption. Nothing was sent. |
| `e2e_key is empty` | The macro (or parameter) is empty, e.g. cleared during key rotation. Nothing was sent. |
| `e2e_key must be exactly 64 hexadecimal characters (256 bit)` | The macro or parameter contains something else (spaces inside, wrong copy). Nothing was sent. |
| Pushover API: `title is too long, cannot truncate due to encryption` | Should not happen (fields are shortened before encryption). Please open an issue with the field lengths. |
| Message arrives but the app cannot decrypt it | The key in Zabbix differs from the one in the app (e.g. after rotation). |
| No link in the notification | The URL was longer than 312 bytes and did not fit encrypted. It is dropped instead of being cut into a broken link; the server log shows `URL is longer than 312 bytes …` (level 3). |

## Security notes
- **What is protected:** the way from Zabbix through Pushover's servers to your device. **Not** protected:
  Zabbix itself stores every alert in plaintext in its database (*Reports → Action log*), so anyone with
  access to the Zabbix database or frontend can read them as before.
- **The key is in the Zabbix database, too:** Zabbix stores the resolved webhook parameters of every alert in the
  `alerts` table, including `e2e_key`. It is not shown in the frontend or API, but it is in the database and its
  backups for as long as alerts are kept. This is how Zabbix webhooks work and cannot be changed by the media type.
- **What is encrypted:** `title`, `message`, `url`. `url_title` is not sent at all. **Not encrypted** (Pushover needs them):
  application token, user key, priority, retry/expire, sound, timestamp. Pushover still sees *that* you got a
  notification and how urgent it was, but not what it says.
- **IV generation:** Duktape provides no cryptographically secure random generator. The IV is
  `HMAC-SHA256(ivKey, nonce || gzip(plaintext))[0..15]` with a separate subkey
  `ivKey = HMAC-SHA256(key, "pushover-e2e-iv-key")`; the nonce combines event ID, field, time in ms, a per-run
  counter and `Math.random()`. Different plaintexts therefore get different IVs even if the nonce repeats, and
  the IV cannot be predicted without the key. Identical plaintext with an identical nonce gives an identical IV,
  which only reveals that the two messages are equal.
- **Integrity:** every field carries an HMAC-SHA256 over IV and ciphertext (encrypt-then-MAC), as specified by
  Pushover.
- **Key storage:** use a secret macro. Zabbix does not show secret macro values in the frontend or API. But a
  global macro is resolved in many places: anyone who can configure objects that resolve global macros
  (media types, items, scripts, …) may be able to get the value out. Treat those permissions as access to the key.
- **Side channels:** the AES implementation uses lookup tables and is not constant-time. That matters only if an
  attacker can measure the Zabbix server's execution time of a webhook with high precision, which is not a
  realistic position here; it is mentioned for completeness.
- **Performance:** one alert with maximum-size fields takes about 25-30 ms in Zabbix 8.0's Duktape engine.
- The crypto code is tested against Node's `crypto`/`zlib`, against `openssl`, with a FIPS-197 AES test
  vector and in the real Zabbix engine (see *Tests*). It went through independent automated code reviews,
  but **no human security audit**. To report a vulnerability, see `SECURITY.md`.

## Length limits apply to the encrypted string
Pushover truncates long plaintext fields itself but **rejects encrypted fields that exceed the limits**. The webhook
therefore prepares the plaintext before encryption:

| Field | Pushover limit | Max. plaintext with e2ee | When longer |
|---|---|---|---|
| title | 250 | 104 bytes UTF-8 (~100 ASCII characters) | cut at a whole character (emoji stay intact), "…" appended |
| message | 1024 | 696 bytes | cut, "…" appended |
| url | 512 | 312 bytes | dropped (a cut URL would be broken) |
| url_title | 100 | – | never sent with encryption (see below) |

Empty fields are left out of an encrypted request.

`url_title` (the label shown instead of the link) cannot fit its limit at all: even an empty string encrypts to
108 characters. Pushover accepted that in a live test, but it is not documented, so the webhook does not rely on it
and leaves `url_title` out of encrypted requests. The app then shows the (decrypted) URL itself as the link.
Keep Zabbix message templates short when using encryption.

## Compatibility
| Zabbix | Status |
|---|---|
| 8.0 | tested (8.0.0: offline, integration, live, production) |
| 7.0 LTS and older | not supported as is: `dist/media_pushover_e2e.yaml` is an 8.0 export, which older versions refuse to import. The library itself is plain ES5. |

## Tests
`./run_tests.sh` runs everything offline (needs `node`, `python3` with PyYAML, `openssl`, `xxd`, `gzip`):
1. **Primitives against Node `crypto`/`zlib`:** UTF-8 (incl. unpaired surrogates), Base64, SHA-256, HMAC with
   short and long keys, gzip and AES-256-CBC at many lengths, FIPS-197 C.3 known-answer vector, IV behaviour
   with a frozen clock and RNG, and a boundary sweep of the length fitting.
2. **Webhook script with mocked `HttpRequest`/`Zabbix`, run side by side with the unmodified upstream script:**
   - without a key: request, log lines, return value and errors are identical to upstream (72 combinations)
   - unresolved macro: error, nothing sent
   - with a key: all fields decrypt correctly, empty fields removed, long fields shortened, a too long URL dropped,
     priority, retry, expire, token and user unchanged
   - `priority_resolved` is used for recoveries only, empty falls back to `priority_default`
   - an invalid key gives a clear error
3. **openssl round trip:** every ciphertext is decrypted using only `openssl`, `xxd` and `gzip`, following
   Pushover's documented scheme. The HMAC is verified first, and a tampered sample must be rejected.

**Integration test** in a throwaway Zabbix (podman or docker, ~2 GB of images). GitHub Actions runs it on every
push after the offline suite (job `integration`, docker). Runs the real alert flow in
Zabbix's Duktape engine with a non-ASCII trigger name and with an over-long emoji title (truncation inside
Duktape), checks status, priority and the encrypted flag, and decrypts all fields with openssl:
```bash
test/env.sh up                 # Zabbix 8.0 on http://127.0.0.1:8081 (Admin / zabbix) + fake Pushover endpoint
test/integration_test.sh
test/env.sh down
```
`CONTAINER_ENGINE=docker` switches the engine, `ZBX_TAG` selects the image tag. On hosts whose AppArmor profile
`php-fpm` blocks the frontend container (seen with rootless podman on Fedora/Nobara), build
`test/Containerfile.web-apparmor` and pass it as `WEB_IMAGE`.

**Live test** against the real Pushover API (your own account, same throwaway instance):
`test/live_test.py setup | secrets | check | fire A..E | extended FG|H|I | cleanup`.
`secrets` asks for token, user key and e2e key with hidden input and stores them only in the test instance.

The integration and live tests log in with the default Admin password and create and delete objects. They refuse
any `ZABBIX_URL` that is not on localhost (override only with `ALLOW_NON_LOCAL_ZABBIX=1`, for another throwaway
instance).

## Development
- `upstream_media_pushover_8.0.yaml` is the unmodified official media type, exported from Zabbix 8.0.0.
- `build.py` produces `dist/media_pushover_e2e.yaml` from upstream plus the library. The script patch is a single
  block inserted before `data = JSON.stringify(data);`, plus the parameters `e2e_key` and `priority_resolved`.
- When Zabbix updates its Pushover webhook, replace the upstream file and run `./run_tests.sh`.
  `build.py` fails loudly if a patch anchor has moved.

## License
AGPL-3.0-only (see `LICENSE`), like the Zabbix media type it is derived from. See `NOTICE` for attribution.
