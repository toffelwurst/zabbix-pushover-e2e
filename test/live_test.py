#!/usr/bin/env python3
"""Live test of "Pushover (E2E)" against the real Pushover API, using the local Zabbix test instance.

  live_test.py setup     import media type, set non-secret parameters, create test actions
  live_test.py secrets   prompts (hidden) for app token, user key and e2e key and stores them in Zabbix
                         (media type token, Admin media "send to", secret macro {$PUSHOVER.E2E.KEY});
                         values are never printed
  live_test.py check     shows which secrets are set (without values)
  live_test.py fire X    fires test case X (A, B, C, D, E) and reports the Zabbix alert status/error
  live_test.py cleanup   removes test triggers, actions, macro, media type

Test cases:
  A  Warning  -> priority 0, umlauts + emoji, encrypted
  B  High     -> priority 1, encrypted
  C  Disaster -> priority 2 (emergency, retry 60 s, expire 300 s), encrypted - acknowledge in the app
  D  Average  -> priority 0, long title (~245 chars) and long message (~1000 chars), encrypted
  E  Warning  -> priority 0, WITHOUT encryption (e2e_key set to "off" for this test only)
"""
import getpass, json, sys, time, urllib.request, pathlib

import os
ZBX = os.environ.get('ZABBIX_URL', 'http://127.0.0.1:8081').rstrip('/')
U = ZBX + '/api_jsonrpc.php'


def require_local(url):
    """These tests log in with the default Admin password and create/delete objects: never against production."""
    import os as _os
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ''
    if host not in ('127.0.0.1', 'localhost', '::1') and _os.environ.get('ALLOW_NON_LOCAL_ZABBIX') != '1':
        raise SystemExit(f'refusing to run against {url}: tests are destructive. '
                         'Use the throwaway instance (test/env.sh up) or set ALLOW_NON_LOCAL_ZABBIX=1.')


require_local(U)
ENGINE = os.environ.get('CONTAINER_ENGINE', 'podman')
HERE = pathlib.Path(__file__).resolve().parent.parent
MT = 'Pushover (E2E)'
PREFIX = 'Live test'

CASES = {
    'A': (2, 'Live test A warning: disk /srv 81 % on testpc – Größe ✓ 🟡'),
    'B': (4, 'Live test B high: container web01 stopped 🔥'),
    'C': (5, 'Live test C disaster: server01 unreachable 🚨'),
    'D': (3, 'Live test D LONG'),
    'E': (2, 'Live test E without encryption (plaintext)'),
}
LONG_SUBJECT = ('Live test D LONG: ' + 'Very long subject with umlauts äöü and emoji 🔥 – ' * 6)[:245]
LONG_MESSAGE = ('Live test D: long message. ' + 'Line with umlauts ÄÖÜß and emoji 🚀✓ to test the length limit. ' * 20)[:1000]


def call(method, params, tok=None):
    h = {'Content-Type': 'application/json-rpc'}
    if tok:
        h['Authorization'] = 'Bearer ' + tok
    r = json.load(urllib.request.urlopen(urllib.request.Request(
        U, json.dumps({'jsonrpc': '2.0', 'method': method, 'params': params, 'id': 1}).encode(), h)))
    if 'error' in r:
        raise SystemExit(f'{method}: {r["error"]}')
    return r['result']


def login():
    return call('user.login', {'username': 'Admin', 'password': 'zabbix'})


def mediatype(t):
    r = call('mediatype.get', {'filter': {'name': [MT]}, 'output': ['mediatypeid', 'parameters', 'status']}, t)
    return r[0] if r else None


def set_params(t, mt, changes):
    params = [{'name': p['name'], 'value': changes.get(p['name'], p['value'])} for p in mt['parameters']]
    call('mediatype.update', {'mediatypeid': mt['mediatypeid'], 'parameters': params}, t)


def macro(t, name):
    r = call('usermacro.get', {'globalmacro': True, 'filter': {'macro': name}, 'output': ['globalmacroid', 'type']}, t)
    return r[0] if r else None


def cleanup(t, keep_mediatype=False):
    for a in call('action.get', {'search': {'name': PREFIX}, 'output': ['actionid']}, t):
        call('action.delete', [a['actionid']], t)
    for tr in call('trigger.get', {'search': {'description': PREFIX}, 'output': ['triggerid']}, t):
        call('trigger.delete', [tr['triggerid']], t)
    if keep_mediatype:
        return
    for m in ('{$PUSHOVER.E2E.KEY}', '{$ZABBIX.URL}'):
        mm = macro(t, m)
        if mm:
            call('usermacro.deleteglobal', [mm['globalmacroid']], t)
    mt = mediatype(t)
    if mt:
        call('mediatype.delete', [mt['mediatypeid']], t)


def setup(t):
    cleanup(t, keep_mediatype=True)
    existing = mediatype(t)
    call('configuration.import', {'format': 'yaml', 'source': (HERE / 'dist' / 'media_pushover_e2e.yaml').read_text(),
                                  'rules': {'mediaTypes': {'createMissing': True, 'updateExisting': True}}}, t)
    mt = mediatype(t)
    changes = {'priority_warning': '0', 'priority_average': '0', 'priority_high': '1', 'priority_disaster': '2',
               'priority_information': '0', 'priority_not_classified': '0', 'priority_default': '0',
               'retry': '60', 'expire': '300', 'tls_verify': 'full'}
    if existing:  # keep a token entered earlier
        old = {p['name']: p['value'] for p in existing['parameters']}
        if old.get('token') and not old['token'].startswith('<'):
            changes['token'] = old['token']
    set_params(t, mt, changes)
    call('mediatype.update', {'mediatypeid': mt['mediatypeid'], 'status': 0}, t)
    if not macro(t, '{$ZABBIX.URL}'):
        call('usermacro.createglobal', {'macro': '{$ZABBIX.URL}', 'value': ZBX}, t)
    common = {'eventsource': 0, 'status': 0, 'esc_period': '1h'}
    call('action.create', dict(common, name=PREFIX + ' Standard', filter={'evaltype': 1, 'conditions': [
        {'conditiontype': 3, 'operator': 2, 'value': PREFIX}, {'conditiontype': 3, 'operator': 3, 'value': 'LONG'}]},
        operations=[{'operationtype': 0, 'opmessage': {'default_msg': 1, 'mediatypeid': mt['mediatypeid']},
                     'opmessage_usr': [{'userid': '1'}]}]), t)
    call('action.create', dict(common, name=PREFIX + ' Long', filter={'evaltype': 0, 'conditions': [
        {'conditiontype': 3, 'operator': 2, 'value': 'LONG'}]},
        operations=[{'operationtype': 0, 'opmessage': {'default_msg': 0, 'subject': LONG_SUBJECT, 'message': LONG_MESSAGE,
                                                        'mediatypeid': mt['mediatypeid']},
                     'opmessage_usr': [{'userid': '1'}]}]), t)
    print('setup done: media type imported and enabled, test actions created.')
    print('next: run "live_test.py secrets" in YOUR terminal to enter token, user key and e2e key.')


def secrets(t):
    mt = mediatype(t) or sys.exit('run setup first')
    print(f'Values are read hidden and sent only to the Zabbix test instance ({ZBX}).')
    token = getpass.getpass('Pushover application API token (Application "Zabbix"): ').strip()
    user = getpass.getpass('Pushover user key: ').strip()
    key = getpass.getpass('E2E key (64 hex characters): ').strip()
    if len(key) != 64 or any(c not in '0123456789abcdefABCDEF' for c in key):
        sys.exit('E2E key must be 64 hex characters - nothing stored.')
    if len(token) != 30 or len(user) != 30:
        print('note: Pushover tokens/user keys are normally 30 characters - please double-check.')
    set_params(t, mt, {'token': token})
    m = macro(t, '{$PUSHOVER.E2E.KEY}')
    if m:
        call('usermacro.updateglobal', {'globalmacroid': m['globalmacroid'], 'value': key, 'type': 1}, t)
    else:
        call('usermacro.createglobal', {'macro': '{$PUSHOVER.E2E.KEY}', 'value': key, 'type': 1,
                                        'description': 'Pushover e2e key (secret)'}, t)
    call('user.update', {'userid': '1', 'medias': [{'mediatypeid': mt['mediatypeid'], 'sendto': user, 'active': 0,
                                                    'severity': 63, 'period': '1-7,00:00-24:00'}]}, t)
    print('stored: token (media type), user key (Admin media), e2e key (secret macro). Run "live_test.py check".')


def check(t):
    mt = mediatype(t)
    if not mt:
        sys.exit('media type missing - run setup')
    p = {x['name']: x['value'] for x in mt['parameters']}
    users = call('user.get', {'userids': ['1'], 'selectMedias': ['mediatypeid', 'sendto']}, t)[0]['medias']
    sendto = [m['sendto'] for m in users if m['mediatypeid'] == mt['mediatypeid']]
    m = macro(t, '{$PUSHOVER.E2E.KEY}')
    print('media type enabled :', mt['status'] == '0')
    print('token set          :', bool(p.get('token')) and not p['token'].startswith('<'), f'({len(p.get("token", ""))} chars)')
    print('user key set       :', bool(sendto and sendto[0]), f'({len(sendto[0]) if sendto else 0} chars)')
    print('e2e macro          :', 'secret' if m and m['type'] == '1' else ('plain!' if m else 'missing'))
    ek = p.get('e2e_key', '')
    print('e2e_key parameter  :', ek if ek.startswith('{$') or ek.strip().lower() in ('', 'off') else f'<literal key, {len(ek)} chars>')
    print('priorities         :', {k[9:]: v for k, v in p.items() if k.startswith('priority_')}, 'retry', p['retry'], 'expire', p['expire'])


def fire(t, case):
    sev, name = CASES[case]
    mt = mediatype(t)
    if case == 'E':
        set_params(t, mt, {'e2e_key': 'off'})
    last = call('alert.get', {'output': ['alertid'], 'sortfield': 'alertid', 'sortorder': 'DESC', 'limit': 1}, t)
    last_id = int(last[0]['alertid']) if last else 0
    for tr in call('trigger.get', {'filter': {'description': [name]}, 'output': ['triggerid']}, t):
        call('trigger.delete', [tr['triggerid']], t)
    call('trigger.create', {'description': name, 'priority': sev, 'expression': 'last(/testpc/agent.ping)>=0'}, t)
    print(f'case {case}: trigger "{name}" (severity {sev}) created, waiting for alert ...')
    try:
        for _ in range(36):
            time.sleep(5)
            al = call('alert.get', {'output': ['alertid', 'status', 'error', 'subject', 'retries'], 'mediatypeids': [mt['mediatypeid']],
                                    'sortfield': 'alertid', 'sortorder': 'DESC', 'limit': 1}, t)
            if al and int(al[0]['alertid']) > last_id and al[0]['status'] in ('1', '2'):
                a = al[0]
                print('  status :', {'1': 'SENT (Pushover accepted)', '2': 'FAILED'}[a['status']])
                if a['error']:
                    print('  error  :', a['error'])
                print('  subject:', a['subject'][:90] + ('…' if len(a['subject']) > 90 else ''), f'({len(a["subject"])} chars)')
                return
            if al and int(al[0]['alertid']) > last_id and al[0]['error']:
                print('  retrying:', al[0]['error'])
        print('  no final alert status within 3 min')
    finally:
        if case == 'E':
            set_params(t, mediatype(t), {'e2e_key': '{$PUSHOVER.E2E.KEY}'})
            print('  e2e_key restored to {$PUSHOVER.E2E.KEY}')


# ---------- extended cases: recovery, update, internal, autoregistration ----------

def new_alerts(t, mtid, after_id, want, timeout=180, source=0, obj=0):
    """Waits until `want` new alerts (final status) exist for the media type; prints and returns them."""
    seen = {}
    end = time.time() + timeout
    while time.time() < end and len(seen) < want:
        time.sleep(5)
        # alert.get only returns trigger alerts unless eventsource/eventobject are given
        for a in call('alert.get', {'output': ['alertid', 'status', 'error', 'subject'], 'mediatypeids': [mtid],
                                    'eventsource': source, 'eventobject': obj,
                                    'sortfield': 'alertid', 'sortorder': 'ASC'}, t):
            if int(a['alertid']) > after_id and a['status'] in ('1', '2') and a['alertid'] not in seen:
                seen[a['alertid']] = a
                st = {'1': 'SENT', '2': 'FAILED'}[a['status']]
                print(f'  [{st}] {a["subject"][:90]}' + (f'\n         error: {a["error"]}' if a['error'] else ''))
    if len(seen) < want:
        print(f'  only {len(seen)} of {want} expected alerts within {timeout}s')
    return list(seen.values())


def last_alert_id(t):
    r = call('alert.get', {'output': ['alertid'], 'sortfield': 'alertid', 'sortorder': 'DESC', 'limit': 1}, t)
    return int(r[0]['alertid']) if r else 0


def msg_op(mtid):
    return {'default_msg': 1, 'mediatypeid': mtid}


def extended(t, which):
    mt = mediatype(t)
    mtid = mt['mediatypeid']
    hostid = call('host.get', {'filter': {'host': ['testpc']}, 'output': ['hostid']}, t)[0]['hostid']

    if which == 'FG':
        name = PREFIX + ' F recovery and update'
        call('action.create', {'name': PREFIX + ' Flow', 'eventsource': 0, 'status': 0, 'esc_period': '1h',
                               'filter': {'evaltype': 0, 'conditions': [{'conditiontype': 3, 'operator': 2, 'value': 'Live test F'}]},
                               'operations': [{'operationtype': 0, 'opmessage': msg_op(mtid), 'opmessage_usr': [{'userid': '1'}]}],
                               'recovery_operations': [{'operationtype': 11, 'opmessage': {'default_msg': 1}}],
                               'update_operations': [{'operationtype': 0, 'opmessage': msg_op(mtid), 'opmessage_usr': [{'userid': '1'}]}]}, t)
        start = last_alert_id(t)
        trig = call('trigger.create', {'description': name, 'priority': 2, 'expression': 'last(/testpc/agent.ping)>=0'}, t)['triggerids'][0]
        print('F1 problem ...')
        new_alerts(t, mtid, start, 1)
        ev = call('problem.get', {'objectids': [trig], 'output': ['eventid']}, t)[0]['eventid']
        start = last_alert_id(t)
        call('event.acknowledge', {'eventids': [ev], 'action': 6, 'message': 'Acknowledged during the live test – looking into it 👀'}, t)
        print('G update (acknowledge + comment) ...')
        new_alerts(t, mtid, start, 1)
        start = last_alert_id(t)
        call('trigger.update', {'triggerid': trig, 'expression': 'last(/testpc/agent.ping)<0'}, t)
        print('F2 recovery (waits for the next agent.ping value, up to ~1 min) ...')
        new_alerts(t, mtid, start, 1)

    elif which == 'H':
        call('action.create', {'name': PREFIX + ' internal', 'eventsource': 3, 'status': 0, 'esc_period': '1h',
                               'filter': {'evaltype': 1, 'conditions': [{'conditiontype': 23, 'operator': 0, 'value': '0'},
                                                                         {'conditiontype': 1, 'operator': 0, 'value': hostid}]},
                               'operations': [{'operationtype': 0, 'opmessage': msg_op(mtid), 'opmessage_usr': [{'userid': '1'}]}]}, t)
        start = last_alert_id(t)
        call('item.create', {'hostid': hostid, 'name': PREFIX + ' H invalid item', 'key_': 'livetest.does.not.exist',
                             'type': 7, 'value_type': 3, 'delay': '30s'}, t)
        print('H internal event (item becomes "not supported", can take 1-2 min) ...')
        new_alerts(t, mtid, start, 1, timeout=240, source=3, obj=4)

    elif which == 'I':
        call('action.create', {'name': PREFIX + ' Autoreg', 'eventsource': 2, 'status': 0,
                               'filter': {'evaltype': 0, 'conditions': [{'conditiontype': 22, 'operator': 2, 'value': 'livetest-autoreg'}]},
                               'operations': [{'operationtype': 0, 'opmessage': msg_op(mtid), 'opmessage_usr': [{'userid': '1'}]}]}, t)
        start = last_alert_id(t)
        import subprocess
        subprocess.run([ENGINE, 'run', '-d', '--name', 'zbx-agent-livetest', '--network', 'zbxtest', '--hostname', 'livetest-autoreg',
                        '-e', 'ZBX_HOSTNAME=livetest-autoreg', '-e', 'ZBX_SERVER_HOST=server', '-e', 'ZBX_PASSIVE_ALLOW=false',
                        '-e', 'ZBX_METADATA=livetest', 'docker.io/zabbix/zabbix-agent2:alpine-8.0-latest'], check=True, capture_output=True)
        print('I autoregistration of new agent "livetest-autoreg" ...')
        new_alerts(t, mtid, start, 1, source=2, obj=3)


def extended_cleanup(t):
    import subprocess
    subprocess.run([ENGINE, 'rm', '-f', 'zbx-agent-livetest'], capture_output=True)
    for h in call('host.get', {'filter': {'host': ['livetest-autoreg']}, 'output': ['hostid']}, t):
        call('host.delete', [h['hostid']], t)
    for i in call('item.get', {'filter': {'key_': 'livetest.does.not.exist'}, 'output': ['itemid']}, t):
        call('item.delete', [i['itemid']], t)
    cleanup(t, keep_mediatype=True)


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    t = login()
    if cmd == 'extended' and len(sys.argv) > 2 and sys.argv[2].upper() in ('FG', 'H', 'I'):
        extended(t, sys.argv[2].upper())
        sys.exit(0)
    if cmd == 'extended-cleanup':
        extended_cleanup(t)
        print('extended test objects removed')
        sys.exit(0)
    if cmd == 'setup':
        setup(t)
    elif cmd == 'secrets':
        secrets(t)
    elif cmd == 'check':
        check(t)
    elif cmd == 'fire' and len(sys.argv) > 2 and sys.argv[2].upper() in CASES:
        fire(t, sys.argv[2].upper())
    elif cmd == 'cleanup':
        cleanup(t)
        print('cleaned up')
    else:
        print(__doc__)
