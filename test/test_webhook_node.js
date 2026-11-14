// Runs the built webhook script (dist/media_pushover_e2e.yaml) AND the unmodified upstream script
// (upstream_media_pushover_8.0.yaml) in Node with mocked Zabbix objects (HttpRequest, Zabbix.log) and checks:
//   - e2e_key "off": request, log lines, return value and errors are identical to upstream
//   - empty key or unresolved macro: error, nothing sent (no silent fallback to plaintext)
//   - with a key: fields encrypted (decrypted again with Node crypto/zlib), empty fields removed,
//     long fields shortened, a too long url dropped together with url_title, priority untouched
//   - priority_resolved for recoveries
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { execFileSync } = require('child_process');

const loadScript = (file) => execFileSync('python3', ['-I', '-c',
	'import yaml,sys;print(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))["zabbix_export"]["media_types"][0]["script"])',
	path.join(__dirname, '..', file)]).toString();
const script = loadScript(path.join('dist', 'media_pushover_e2e.yaml'));
const upstream = loadScript('upstream_media_pushover_8.0.yaml');

function run(src, params, status = 200) {
	const trace = { sent: null, logs: [], headers: [], proxy: null, result: null, error: null };
	function HttpRequest() {
		this.addHeader = (h) => trace.headers.push(h);
		this.setProxy = (p) => { trace.proxy = p; };
		this.post = (url, body) => { trace.sent = { url, body: JSON.parse(body) }; return '{"status":1,"request":"x"}'; };
		this.getStatus = () => status;
	}
	const Zabbix = { log: (lvl, msg) => trace.logs.push([lvl, msg]) };
	try {
		trace.result = new Function('value', 'HttpRequest', 'Zabbix', src)(JSON.stringify(params), HttpRequest, Zabbix);
	} catch (e) {
		trace.error = String(e);
	}
	return trace;
}

function decrypt(keyHex, b64) {
	const key = Buffer.from(keyHex, 'hex'), raw = Buffer.from(b64, 'base64');
	const iv = raw.subarray(0, 16), ct = raw.subarray(16, raw.length - 32), mac = raw.subarray(raw.length - 32);
	const want = crypto.createHmac('sha256', key).update(Buffer.concat([iv, ct])).digest();
	if (!crypto.timingSafeEqual(mac, want)) throw new Error('HMAC mismatch');
	const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
	return zlib.gunzipSync(Buffer.concat([d.update(ct), d.final()])).toString('utf8');
}

const base = {
	endpoint: 'https://api.pushover.net/1/messages.json', eventid: '4711', event_nseverity: '5', event_source: '0',
	event_value: '1', expire: '1200', message: 'Problem: Disk /srv 95% 🔥', priority_average: '0', priority_default: '0',
	priority_disaster: '2', priority_high: '1', priority_information: '0', priority_not_classified: '0', priority_warning: '0',
	retry: '60', title: 'Problem: Disk full on server01', tls_verify: 'full', token: 'T', triggerid: '42',
	url: 'https://zabbix.example', url_title: 'Zabbix', user: 'U'
};
const P = (extra) => Object.assign({}, base, extra);

let fails = 0;
const check = (n, ok) => { console.log((ok ? 'ok   ' : 'FAIL ') + n); if (!ok) fails++; };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// 1. without a key: identical to upstream, over a grid of parameter variations
const variants = [
	{}, { event_value: '0' }, { event_nseverity: '2' }, { event_source: '3' }, { event_source: '2', event_value: '1' },
	{ HTTPProxy: 'http://proxy:3128' }, { priority_disaster: '9' }, { message: '' }, { eventid: 'x' },
	{ title: '', url_title: '' }, { url: 'https://z.example/' + 'p'.repeat(600) }, { event_value: '7' }
];
let grid = 0;
for (const keyCase of [{ e2e_key: 'off' }, { e2e_key: ' OFF ' }]) {
	for (const v of variants) {
		for (const status of [200, 500]) {
			const ours = run(script, P(Object.assign({}, v, keyCase)), status);
			const theirs = run(upstream, P(v), status);
			if (!same(ours, theirs)) {
				check(`no key ${JSON.stringify(keyCase)} ${JSON.stringify(v)} status ${status}: identical to upstream`, false);
			}
			grid++;
		}
	}
}
check(`e2e_key "off": request, logs and errors identical to upstream in ${grid} combinations`, true);

// 2. empty key / unresolved macro -> error, nothing sent, and the error never echoes key material
const key = crypto.randomBytes(32).toString('hex');
for (const k of ['{$PUSHOVER.E2E.KEY}', '{$OTHER}', '{$', 'x{$Y}', key.slice(0, 32) + '{$PART2}']) {
	const r = run(script, P({ e2e_key: k }));
	check(`unresolved macro ${JSON.stringify(k.slice(0, 24))}: error, nothing sent, no key material in error`,
		r.sent === null && /unresolved macro/.test(r.error) && !r.error.includes(key.slice(0, 32)));
}
for (const [label, extra] of [['empty', { e2e_key: '' }], ['whitespace', { e2e_key: '   ' }], ['parameter missing', {}]]) {
	const r = run(script, P(extra));
	check(`${label} key: error, nothing sent`, r.sent === null && /e2e_key is empty/.test(r.error));
}

// 3. with a key
const r = run(script, P({ e2e_key: key }));
check('with key: returns OK', r.result === 'OK');
check('with key: encrypted = 1', r.sent.body.encrypted === 1);
const expectedUrl = 'https://zabbix.example/tr_events.php?triggerid=42&eventid=4711';
check('with key: title, message and url decrypt to the plaintext',
	decrypt(key, r.sent.body.title) === base.title && decrypt(key, r.sent.body.message) === base.message
	&& decrypt(key, r.sent.body.url) === expectedUrl);
check('with key: url_title is not sent (cannot fit its limit encrypted)', !('url_title' in r.sent.body));
check('with key: priority/retry/expire unchanged', r.sent.body.priority === '2' && r.sent.body.retry === '60' && r.sent.body.expire === '1200');
check('with key: token/user untouched', r.sent.body.token === 'T' && r.sent.body.user === 'U');
check('with key: key with surrounding spaces works', run(script, P({ e2e_key: ' ' + key + ' ' })).result === 'OK');

const empty = run(script, P({ e2e_key: key, title: '' })).sent.body;
check('with key: empty title is removed, not sent as ""', !('title' in empty) && empty.encrypted === 1);

const longUrlRun = run(script, P({ e2e_key: key, url: 'https://z.example/' + 'p'.repeat(400) }));
check('with key: url that does not fit is dropped (and logged)',
	!('url' in longUrlRun.sent.body)
	&& longUrlRun.logs.some(([lvl, msg]) => lvl === 3 && /does not fit encrypted/.test(msg)));
// boundary: the url parameter gets "/tr_events.php?triggerid=42&eventid=4711" appended by the webhook
const suffix = '/tr_events.php?triggerid=42&eventid=4711'.length;
const fits = run(script, P({ e2e_key: key, url: 'u'.repeat(312 - suffix) })).sent.body;
const over = run(script, P({ e2e_key: key, url: 'u'.repeat(313 - suffix) })).sent.body;
check('with key: url of exactly 312 bytes kept, 313 dropped', 'url' in fits && fits.url.length <= 512 && !('url' in over));

const longT = run(script, P({ e2e_key: key, title: 'Ü🔥'.repeat(200), message: 'äöü 🚀 '.repeat(400) })).sent.body;
const t = decrypt(key, longT.title), m = decrypt(key, longT.message);
check('with key: long title/message shortened with "…", within limits',
	longT.title.length <= 250 && longT.message.length <= 1024 && t.endsWith('…') && m.endsWith('…'));

const bad = run(script, P({ e2e_key: 'nothex' }));
check('invalid key -> clear error, nothing sent', bad.sent === null && /64 hexadecimal/.test(bad.error));

// 4. priority_resolved: recoveries (event_value 0) use it, empty falls back to priority_default
const rec = (extra) => run(script, P(Object.assign({ e2e_key: 'off', event_value: '0' }, extra))).sent.body.priority;
check('recovery: priority_resolved -1 is used', rec({ priority_resolved: '-1' }) === '-1');
check('recovery: empty priority_resolved -> priority_default', rec({ priority_resolved: '', priority_default: '0' }) === '0');
check('problem: priority_resolved ignored', run(script, P({ e2e_key: 'off', priority_resolved: '-1' })).sent.body.priority === '2');

if (process.argv[2]) {
	const plain = { title: base.title, message: base.message, url: expectedUrl };
	fs.writeFileSync(process.argv[2], JSON.stringify({ key, samples: Object.keys(plain).map((f) => ({ plain: plain[f], enc: r.sent.body[f] })) }));
}

console.log(fails ? fails + ' FAILED' : 'all webhook tests passed');
process.exit(fails ? 1 : 0);
