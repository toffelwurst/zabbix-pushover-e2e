// Unit tests: compare each primitive against Node's crypto/zlib, then emit
// encrypted samples for the openssl round-trip test (verify_openssl.sh).
'use strict';
const crypto = require('crypto');
const zlib = require('zlib');
const path = require('path');
const E2E = require(path.join(__dirname, '..', 'src', 'pushover_e2e_lib.js'));

let fails = 0;
function check(name, ok) {
	console.log((ok ? 'ok   ' : 'FAIL ') + name);
	if (!ok) fails++;
}
const B = (arr) => Buffer.from(arr);
const rnd = (n) => Array.from(crypto.randomBytes(n));

// UTF-8
for (const s of ['', 'abc', 'Größe äöü ß', '€ ✓ 漢字', '🔥 emoji 👍🏽', 'x'.repeat(1024),
	'a\ud83d', '\ude00b', 'x\ud83d\ud83dy', '\udfff\ud800']) {   // last 4: unpaired surrogates -> U+FFFD
	check('utf8 ' + JSON.stringify(s.slice(0, 20)), B(E2E._utf8Encode(s)).equals(Buffer.from(s, 'utf8')));
}

// base64
for (let n = 0; n < 40; n++) {
	const d = rnd(n);
	if (E2E._base64Encode(d) !== B(d).toString('base64')) { check('base64 len ' + n, false); }
}
check('base64 lengths 0..39', true);

// SHA-256 / HMAC
for (const n of [0, 1, 55, 56, 63, 64, 65, 200, 5000]) {
	const d = rnd(n);
	check('sha256 len ' + n, B(E2E._sha256(d)).equals(crypto.createHash('sha256').update(B(d)).digest()));
	for (const kl of [32, 64, 65, 100, 200]) {   // keys longer than the block size are hashed first
		const k = rnd(kl);
		if (!B(E2E._hmacSha256(k, d)).equals(crypto.createHmac('sha256', B(k)).update(B(d)).digest())) {
			check(`hmac len ${n} key ${kl}`, false);
		}
	}
}
check('hmac: key lengths 32/64/65/100/200 x data lengths', true);

// known-answer test: FIPS-197 appendix C.3 (AES-256, single block)
{
	const k = [...Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex')];
	const pt = [...Buffer.from('00112233445566778899aabbccddeeff', 'hex')];
	const ct = B(E2E._aes256CbcEncrypt(k, new Array(16).fill(0), pt)).subarray(0, 16).toString('hex');
	check('aes-256 FIPS-197 C.3 vector', ct === '8ea2b7ca516745bfeafc49904b496089');
}

// CRC32 + gzip (must decode with zlib.gunzipSync)
for (const n of [0, 1, 100, 65535, 65536, 70000]) {
	const d = rnd(n);
	let ok;
	try { ok = zlib.gunzipSync(B(E2E._gzip(d))).equals(B(d)); } catch (e) { ok = false; }
	check('gzip roundtrip len ' + n, ok);
}

// AES-256-CBC vs Node
for (const n of [0, 1, 15, 16, 17, 100, 1040]) {
	const k = rnd(32), iv = rnd(16), d = rnd(n);
	const c = crypto.createCipheriv('aes-256-cbc', B(k), B(iv));
	const ref = Buffer.concat([c.update(B(d)), c.final()]);
	check('aes-256-cbc len ' + n, B(E2E._aes256CbcEncrypt(k, iv, d)).equals(ref));
}

// key validation
let threw = false;
try { E2E.encryptField('abc', 'x', 't'); } catch (e) { threw = true; }
check('rejects short key', threw);

// IV: fresh module per run (as in Zabbix), frozen clock and RNG = worst case for the nonce
const key = crypto.randomBytes(32).toString('hex');
function freshIv(plain) {
	const libPath = path.join(__dirname, '..', 'src', 'pushover_e2e_lib.js');
	const now = Date.now, rand = Math.random;
	delete require.cache[require.resolve(libPath)];
	Date.now = () => 1700000000000; Math.random = () => 0.5;
	try {
		return Buffer.from(require(libPath).encryptField(key, plain, '4711|title'), 'base64').subarray(0, 16);
	} finally {
		Date.now = now; Math.random = rand;
	}
}
check('IV: same nonce, different plaintext -> different IV', !freshIv('Problem A').equals(freshIv('Problem B')));
check('IV: same nonce, same plaintext -> same IV (reveals only what is already equal)', freshIv('X').equals(freshIv('X')));
{
	const a = Buffer.from(E2E.encryptField(key, 'same', 'ctx'), 'base64').subarray(0, 16);
	const b = Buffer.from(E2E.encryptField(key, 'same', 'ctx'), 'base64').subarray(0, 16);
	check('IV differs per call in one run', !a.equals(b));
}

// length fitting: encrypted string must stay within Pushover's limits, plaintext is a cut prefix + "…"
const k2 = crypto.randomBytes(32).toString('hex');
check('maxPlainBytes title=104 message=696 url=312 url_title=-1',
	E2E.maxPlainBytes(250) === 104 && E2E.maxPlainBytes(1024) === 696 && E2E.maxPlainBytes(512) === 312 && E2E.maxPlainBytes(100) === -1);
for (const [limit, text] of [[250, 'Ü🔥'.repeat(200)], [250, 'a'.repeat(104)], [250, 'a'.repeat(105)], [1024, 'äöü 🚀 '.repeat(300)],
	[512, 'https://x/' + 'p'.repeat(600)], [250, '🔥'.repeat(30)]]) {
	let worstLen = 0;
	for (let i = 0; i < 20; i++) {
		worstLen = Math.max(worstLen, E2E.encryptFieldLimited(k2, text, 'c' + i, limit).length);
	}
	const cut = E2E.truncateUtf8(text, E2E.maxPlainBytes(limit));
	const okPrefix = cut === text || (cut.endsWith('…') && text.startsWith(cut.slice(0, -1)));
	const noBrokenSurrogate = !/[\uD800-\uDBFF]$/.test(cut.slice(0, -1));
	check(`fit limit ${limit} len ${text.length}: enc ${worstLen} <= ${limit}, prefix ok, no broken emoji`,
		worstLen <= limit && okPrefix && noBrokenSurrogate);
}
// boundary sweep: every length 0..800 of 1-, 2-, 3- and 4-byte characters stays within each limit
for (const limit of [250, 512, 1024]) {
	let worst = 0;
	for (const ch of ['a', 'ü', '€', '🔥']) {
		for (let n = 0; n <= 800; n += 7) {
			worst = Math.max(worst, E2E.encryptFieldLimited(k2, ch.repeat(n), 'c', limit).length);
		}
	}
	check(`fit sweep limit ${limit}: max encrypted length ${worst}`, worst <= limit);
}
{
	let threw = false;
	try { E2E.encryptFieldLimited(k2, 'x', 'c', 100); } catch (e) { threw = /no plaintext fits/.test(String(e)); }
	check('encryptFieldLimited: impossible limit (100) throws instead of exceeding it', threw);
}
check('truncateUtf8 with less room than the ellipsis cuts without it',
	E2E.truncateUtf8('abcdef', 2) === 'ab' && E2E.truncateUtf8('🔥🔥', 3) === '…' && E2E.truncateUtf8('🔥🔥', 2) === '');

// fitting must not cut more than necessary: one more byte would not fit
{
	const p = 'a'.repeat(E2E.maxPlainBytes(250) + 1);
	const raw = E2E.encryptField(k2, p, 'x');
	check('105-byte title would exceed 250 unencrypted-fit', raw.length > 250);
}

// samples for openssl round trip
if (process.argv[2]) {
	const fs = require('fs');
	const samples = ['hellorld', 'Größe äöü ß – Prüfung', 'Problem: Disk /srv 95% 🔥 on server01', 'x'.repeat(1024), ''];
	const out = samples.map((p) => ({ plain: p, enc: E2E.encryptField(key, p, 'sample') }));
	fs.writeFileSync(process.argv[2], JSON.stringify({ key, samples: out }, null, 1));
	console.log('wrote ' + out.length + ' samples to ' + process.argv[2]);
}

console.log(fails ? fails + ' FAILED' : 'all node tests passed');
process.exit(fails ? 1 : 0);
