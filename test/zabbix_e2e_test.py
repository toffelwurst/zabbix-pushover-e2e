#!/usr/bin/env python3
"""End-to-end test against the throwaway Zabbix test instance (test/env.sh up):
imports dist/media_pushover_e2e.yaml, points it at the local fake Pushover endpoint
(container "zbx-echo"), creates a secret macro with a random test key, an action
and a trigger that fires immediately, then waits for the alert and writes the received
request + key to a samples file for verify_openssl.sh.

Usage: zabbix_e2e_test.py <echo requests.jsonl> <samples-out.json> [setup|cleanup]
"""
import json, pathlib, secrets, sys, time, urllib.request

import os
U = os.environ.get('ZABBIX_URL', 'http://127.0.0.1:8081').rstrip('/') + '/api_jsonrpc.php'


def require_local(url):
    """These tests log in with the default Admin password and create/delete objects: never against production."""
    import os as _os
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ''
    if host not in ('127.0.0.1', 'localhost', '::1') and _os.environ.get('ALLOW_NON_LOCAL_ZABBIX') != '1':
        raise SystemExit(f'refusing to run against {url}: tests are destructive. '
                         'Use the throwaway instance (test/env.sh up) or set ALLOW_NON_LOCAL_ZABBIX=1.')


require_local(U)
HERE = pathlib.Path(__file__).resolve().parent.parent
TAG = 'e2e-test'
# non-ASCII on purpose: umlauts, CJK and an emoji (surrogate pair) must survive Duktape + encryption
TRIGGER = 'E2E test trigger äöü 漢字 🔥'


def call(method, params, tok=None):
    h = {'Content-Type': 'application/json-rpc'}
    if tok:
        h['Authorization'] = 'Bearer ' + tok
    req = urllib.request.Request(U, json.dumps({'jsonrpc': '2.0', 'method': method, 'params': params, 'id': 1}).encode(), h)
    r = json.load(urllib.request.urlopen(req))
    if 'error' in r:
        raise SystemExit(f'{method}: {r["error"]}')
    return r['result']


def cleanup(t):
    for a in call('action.get', {'filter': {'name': ['E2E test action']}, 'output': ['actionid']}, t):
        call('action.delete', [a['actionid']], t)
    for tr in call('trigger.get', {'search': {'description': TRIGGER}, 'output': ['triggerid']}, t):
        call('trigger.delete', [tr['triggerid']], t)
    for m in call('usermacro.get', {'globalmacro': True, 'filter': {'macro': '{$PUSHOVER.E2E.KEY}'}, 'output': ['globalmacroid']}, t):
        call('usermacro.deleteglobal', [m['globalmacroid']], t)
    for mt in call('mediatype.get', {'filter': {'name': ['Pushover (E2E)']}, 'output': ['mediatypeid']}, t):
        call('mediatype.delete', [mt['mediatypeid']], t)


def main():
    log, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else 'run'
    t = call('user.login', {'username': 'Admin', 'password': 'zabbix'})
    cleanup(t)
    if mode == 'cleanup':
        print('cleaned up'); return

    key = secrets.token_hex(32)
    call('configuration.import', {'format': 'yaml', 'source': (HERE / 'dist' / 'media_pushover_e2e.yaml').read_text(),
                                  'rules': {'mediaTypes': {'createMissing': True, 'updateExisting': True}}}, t)
    mt = call('mediatype.get', {'filter': {'name': ['Pushover (E2E)']}, 'output': ['mediatypeid', 'parameters']}, t)[0]
    params = []
    for p in mt['parameters']:
        v = {'endpoint': 'http://echo:8000/1/messages.json', 'tls_verify': 'none', 'token': 'TESTTOKEN',
             'priority_disaster': '2', 'url': 'https://zabbix.example.test'}.get(p['name'], p['value'])
        params.append({'name': p['name'], 'value': v})
    call('mediatype.update', {'mediatypeid': mt['mediatypeid'], 'status': 0, 'parameters': params}, t)
    call('usermacro.createglobal', {'macro': '{$PUSHOVER.E2E.KEY}', 'value': key, 'type': 1,
                                    'description': 'Pushover e2e test key (random, test only)'}, t)
    call('user.update', {'userid': '1', 'medias': [{'mediatypeid': mt['mediatypeid'], 'sendto': 'TESTUSERKEY',
                                                    'active': 0, 'severity': 63, 'period': '1-7,00:00-24:00'}]}, t)
    call('action.create', {'name': 'E2E test action', 'eventsource': 0, 'status': 0, 'esc_period': '1h',
                           'filter': {'evaltype': 0, 'conditions': [{'conditiontype': 3, 'operator': 2, 'value': TRIGGER}]},
                           'operations': [{'operationtype': 0, 'opmessage': {'default_msg': 1, 'mediatypeid': mt['mediatypeid']},
                                           'opmessage_usr': [{'userid': '1'}]}]}, t)
    samples = []
    # 1. normal alert; 2. over-long emoji title -> truncation inside Duktape must keep whole emoji
    for desc in (TRIGGER, TRIGGER + ' ' + '\U0001F525' * 40):
        req, al, tr = fire(t, log, desc)
        expect(req.get('encrypted') == 1, 'encrypted flag set')
        expect(req.get('priority') == '2', 'priority 2 (disaster) passed through')
        expect(al['status'] == '1', f"alert status sent (got {al['status']}: {al.get('error')})")
        title = al['subject']
        if len(title.encode('utf-8')) > 104:
            title = truncate_utf8(title, 104)
            expect('\U0001F525' in title, 'truncated title still contains the emoji')
        url = f"https://zabbix.example.test/tr_events.php?triggerid={tr}&eventid={al['eventid']}"
        samples += [{'plain': title, 'enc': req['title']}, {'plain': al['message'], 'enc': req['message']},
                    {'plain': url, 'enc': req['url']}]
        expect('url_title' not in req, 'url_title not sent with encryption')
    out.write_text(json.dumps({'key': key, 'samples': samples}, ensure_ascii=False, indent=1))
    print('wrote', out)


def expect(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what)
    if not cond:
        raise SystemExit('integration check failed: ' + what)


def truncate_utf8(s, max_bytes):
    """Same rule as the webhook: whole characters, ellipsis (3 bytes) included in max_bytes."""
    out, used = '', 0
    for ch in s:
        b = len(ch.encode('utf-8'))
        if used + b > max_bytes - 3:
            break
        out, used = out + ch, used + b
    return out + '\u2026'


def fire(t, log, desc):
    n_before = len(log.read_text().splitlines()) if log.exists() else 0
    tr = call('trigger.create', {'description': desc, 'priority': 5, 'expression': 'last(/testpc/agent.ping)>=0'},
              t)['triggerids'][0]
    print('waiting for alert:', desc[:40], '...')
    for _ in range(40):
        time.sleep(5)
        lines = log.read_text().splitlines() if log.exists() else []
        if len(lines) > n_before:
            req = json.loads(lines[-1])
            break
    else:
        alerts = call('alert.get', {'output': ['status', 'error'], 'sortfield': 'alertid', 'sortorder': 'DESC', 'limit': 3}, t)
        raise SystemExit(f'no request received; recent alerts: {alerts}')
    # plaintext reference comes from Zabbix itself (alert.get returns the rendered subject/message).
    # The fake endpoint logs the request before Zabbix has written the alert status (alerter -> alert manager
    # -> alert syncer), so wait until the status is final instead of reading it right away.
    for _ in range(30):
        al = call('alert.get', {'output': ['subject', 'message', 'status', 'error', 'eventid'], 'sortfield': 'alertid',
                                'sortorder': 'DESC', 'limit': 1}, t)[0]
        if al['status'] in ('1', '2'):
            break
        time.sleep(2)
    return req, al, tr


if __name__ == '__main__':
    main()
