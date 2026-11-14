# Security policy

This project ships its own small implementation of AES-256-CBC, HMAC-SHA256, SHA-256, gzip and Base64
(`src/pushover_e2e_lib.js`), because the Zabbix webhook engine offers no AES and no gzip.
It is tested (see README, *Tests*) but has **not had a human security audit**.

## Reporting a vulnerability
Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting
instead: *Security* tab of this repository → *Report a vulnerability*.

Helpful details: affected version/commit, Zabbix version, what an attacker can learn or do, and a way to
reproduce it (e.g. input values and the resulting request).

You will get an answer as soon as possible; this is a hobby project without guaranteed response times.

## Supported versions
Only the latest release is supported. Fixes are released as a new version; update the media type in Zabbix
afterwards (*Alerts → Media types*, re-import or replace the script).

## Scope
In scope: the encryption and encoding code, the build patch, and anything that could make the media type
send plaintext, leak the key, or produce messages that Pushover/the app would decrypt incorrectly.

Out of scope: weaknesses of Zabbix itself (e.g. alerts and webhook parameters being stored in its database)
and of Pushover's scheme; these are documented in the README under *Security notes*.
