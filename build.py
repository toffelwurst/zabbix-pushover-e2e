#!/usr/bin/env python3
"""Builds dist/media_pushover_e2e.yaml from the official Zabbix Pushover media type
(upstream_media_pushover_8.0.yaml) plus src/pushover_e2e_lib.js.

Changes against upstream (kept minimal so future upstream updates are easy to merge):
  * name "Pushover (E2E)"
  * new parameter e2e_key (default: secret global macro {$PUSHOVER.E2E.KEY}); "off" = plaintext like upstream,
    empty value or unresolved macro = error (fail closed)
  * new parameter priority_resolved (empty = priority_default). The upstream script already maps recoveries
    to severity "resolved" and looks up params.priority_resolved, but upstream ships no such parameter.
  * script: e2ee library prepended; if a key is set, title/message/url are
    encrypted and "encrypted": 1 is sent. With e2e_key "off" it behaves exactly like upstream.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
UPSTREAM = HERE / 'upstream_media_pushover_8.0.yaml'
LIB = HERE / 'src' / 'pushover_e2e_lib.js'
OUT = HERE / 'dist' / 'media_pushover_e2e.yaml'

PATCH_ANCHOR = '\tdata = JSON.stringify(data);\n'
PATCH = '''\t// --- Pushover end-to-end encryption (https://pushover.net/api#e2ee) ---
\t// Fail closed: plaintext only with the explicit value "off". An empty key or an unresolved macro (renamed,
\t// deleted, typo, cleared during rotation) is an error instead of a silent downgrade to plaintext.
\tvar e2eKey = (typeof params.e2e_key === 'string') ? params.e2e_key.trim() : '';

\tif (e2eKey.toLowerCase() !== 'off') {
\t\tif (e2eKey.indexOf('{$') !== -1) {
\t\t\t// report only the macro name, never resolved parts of the value
\t\t\tthrow 'e2e_key contains an unresolved macro ' + (e2eKey.match(/\\{\\$[^}]*\\}?/) || ['{$'])[0]
\t\t\t\t+ ' - define it, or set e2e_key to "off" to send without encryption';
\t\t}
\t\tif (e2eKey === '') {
\t\t\tthrow 'e2e_key is empty - set the 64-hex-character key, or "off" to send without encryption';
\t\t}

\t\tvar hadUrl = (typeof data.url === 'string' && data.url !== '');

\t\t// Pushover applies its length limits to the encrypted string and rejects longer fields
\t\t// ("cannot truncate due to encryption"), so encryptPayload shortens the plaintext first.
\t\tPushoverE2E.encryptPayload(e2eKey, data, params.eventid);

\t\tif (hadUrl && !('url' in data)) {
\t\t\tZabbix.log(3, '[ Pushover Webhook ] URL is longer than 312 bytes and does not fit encrypted - sent without URL');
\t\t}
\t}
\t// --- end of e2ee ---

'''

DESCRIPTION = '''      description: |
        Pushover webhook with optional end-to-end encryption (e2ee, https://pushover.net/api#e2ee).
        Modified version of the official Zabbix Pushover media type (Zabbix 8.0), changed 2026-11 by
        toffelwurst: e2ee added. AGPL-3.0-only. Source: https://github.com/toffelwurst/zabbix-pushover-e2e

        Set token parameter to your Pushover application key.
        When assigning Pushover media to the Zabbix user - add user key into send to field.

        Encryption: create the 64-hex-character key in the Pushover app (iOS/Android, app 5.0+) and store it
        as a secret global macro {$PUSHOVER.E2E.KEY} (or set the e2e_key parameter directly).
        To send without encryption, set e2e_key to "off": then the webhook behaves exactly like upstream.
        An empty key or an undefined macro is an error (no silent fallback to plaintext).
        Encrypted fields: title, message, url. url_title is not sent with encryption (cannot fit its limit).

        priority_resolved: Pushover priority for recovery messages (e.g. -1 = quiet). Empty = priority_default.
'''


def indent(text, n=8):
    return ''.join((' ' * n + line) if line.strip() else (' ' * n + line.lstrip(' \t'))
                   for line in text.splitlines(True))


def check(cond, msg):
    # explicit check instead of assert: asserts are stripped under "python -O"
    if not cond:
        raise SystemExit('build.py: ' + msg)


def main():
    src = UPSTREAM.read_text(encoding='utf-8')
    lib = LIB.read_text(encoding='utf-8')

    # 1. name
    check(src.count('    - name: Pushover\n') == 1, 'media type name anchor not found')
    src = src.replace('    - name: Pushover\n', '    - name: \'Pushover (E2E)\'\n')

    # 2. parameter e2e_key (alphabetical, before endpoint)
    anchor = '        - name: endpoint\n'
    check(src.count(anchor) == 1, 'parameter anchor "endpoint" not found')
    src = src.replace(anchor, "        - name: e2e_key\n          value: '{$PUSHOVER.E2E.KEY}'\n" + anchor)

    # 2b. parameter priority_resolved (alphabetical, before priority_warning)
    anchor = '        - name: priority_warning\n'
    check(src.count(anchor) == 1, 'parameter anchor "priority_warning" not found')
    src = src.replace(anchor, "        - name: priority_resolved\n          value: ''\n" + anchor)

    # 3. script: split out, patch, re-indent
    start = src.index('      script: |\n') + len('      script: |\n')
    end = src.index('      description: |\n')
    script = '\n'.join(line[8:] if line.startswith(' ' * 8) else line.lstrip(' ')
                       for line in src[start:end].split('\n'))
    check(script.count(PATCH_ANCHOR) == 1, 'upstream script changed - check patch anchor')
    script = script.replace(PATCH_ANCHOR, PATCH + PATCH_ANCHOR)
    trailer = "if (typeof module !== 'undefined' && module.exports) {\n\tmodule.exports = PushoverE2E;\n}\n"
    check(lib.count(trailer) == 1, 'module.exports trailer of the library not found')
    lib = lib.replace(trailer, '')
    script = lib.rstrip('\n') + '\n\n' + script.rstrip('\n') + '\n'

    # 4. description
    dend = src.index('      message_templates:\n')
    out = src[:start] + indent(script) + DESCRIPTION + src[dend:]

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(out, encoding='utf-8')
    print(f'wrote {OUT.relative_to(HERE)} ({len(out)} bytes)')


if __name__ == '__main__':
    sys.exit(main())
