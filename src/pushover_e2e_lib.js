/*
 * Pushover end-to-end encryption (e2ee) for Zabbix webhooks.
 *
 * Implements the scheme documented at https://pushover.net/api#e2ee:
 *   per field: gzip(plaintext) -> AES-256-CBC/PKCS7 (16-byte IV)
 *              -> HMAC-SHA256(key, IV || ciphertext)
 *              -> base64(IV || ciphertext || HMAC)
 *   one 256-bit key (64 hex chars) is used for both AES and HMAC.
 *
 * Written in plain ES5 because the Zabbix JavaScript engine (Duktape) offers
 * no AES and no gzip. SHA-256, HMAC and Base64 are implemented here as well, so
 * the whole scheme lives in one small, separately testable file. Byte arrays are
 * plain JS arrays of integers 0..255.
 *
 * gzip: the output uses deflate "stored" blocks (no compression). That is a
 * valid RFC 1951/1952 stream that every gzip decoder accepts; compression is
 * not needed for messages of at most 1024 characters.
 *
 * IV: Duktape has no cryptographically secure random number generator. The
 * IV is therefore derived as HMAC-SHA256(ivKey, nonce || gzip(plaintext))[0..15]
 * with a separate subkey ivKey = HMAC-SHA256(key, "pushover-e2e-iv-key"). The
 * nonce combines event ID, field name, timestamp, a per-run counter and
 * Math.random(). Because the plaintext is an input, two different messages get
 * the same IV only if the nonce repeats AND the HMAC collides; an identical IV
 * for identical plaintext and nonce reveals nothing new. Without the key the IV
 * is unpredictable, which is what CBC requires.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 toffelwurst
 * Derived from the Pushover media type of Zabbix, Copyright (C) 2001-2026 Zabbix SIA, AGPL-3.0-only.
 */

var PushoverE2E = (function () {
	'use strict';

	/* ---------- helpers ---------- */

	function utf8Encode(str) {
		var out = [], i, c, c2;

		str = String(str);

		for (i = 0; i < str.length; i++) {
			c = str.charCodeAt(i);

			if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
				c2 = str.charCodeAt(i + 1);

				if (c2 >= 0xdc00 && c2 <= 0xdfff) {
					c = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
					i++;
				}
			}

			// unpaired surrogate -> U+FFFD (like TextEncoder), otherwise the result would be invalid UTF-8
			if (c >= 0xd800 && c <= 0xdfff) {
				c = 0xfffd;
			}

			if (c < 0x80) {
				out.push(c);
			}
			else if (c < 0x800) {
				out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
			}
			else if (c < 0x10000) {
				out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
			}
			else {
				out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
			}
		}

		return out;
	}

	function hexToBytes(hex) {
		var out = [], i;

		hex = String(hex).trim();

		if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
			throw 'e2e_key must be exactly 64 hexadecimal characters (256 bit)';
		}

		for (i = 0; i < hex.length; i += 2) {
			out.push(parseInt(hex.substr(i, 2), 16));
		}

		return out;
	}

	var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

	function base64Encode(bytes) {
		var out = '', i, n;

		for (i = 0; i + 2 < bytes.length; i += 3) {
			n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			out += B64.charAt(n >> 18) + B64.charAt((n >> 12) & 63) + B64.charAt((n >> 6) & 63) + B64.charAt(n & 63);
		}

		if (bytes.length - i === 1) {
			n = bytes[i] << 16;
			out += B64.charAt(n >> 18) + B64.charAt((n >> 12) & 63) + '==';
		}
		else if (bytes.length - i === 2) {
			n = (bytes[i] << 16) | (bytes[i + 1] << 8);
			out += B64.charAt(n >> 18) + B64.charAt((n >> 12) & 63) + B64.charAt((n >> 6) & 63) + '=';
		}

		return out;
	}

	/* ---------- gzip (stored deflate blocks) ---------- */

	var CRC_TABLE = (function () {
		var t = [], c, n, k;

		for (n = 0; n < 256; n++) {
			c = n;

			for (k = 0; k < 8; k++) {
				c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
			}

			t[n] = c >>> 0;
		}

		return t;
	})();

	function crc32(bytes) {
		var crc = 0xffffffff, i;

		for (i = 0; i < bytes.length; i++) {
			crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
		}

		return (crc ^ 0xffffffff) >>> 0;
	}

	function le32(n) {
		return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
	}

	function gzip(bytes) {
		// header: magic, CM=deflate, FLG=0, MTIME=0, XFL=0, OS=255 (unknown)
		var out = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff],
			pos = 0, len, last, i;

		do {
			len = Math.min(65535, bytes.length - pos);
			last = (pos + len >= bytes.length) ? 1 : 0;
			out.push(last, len & 0xff, len >> 8, (~len) & 0xff, ((~len) >> 8) & 0xff);

			for (i = 0; i < len; i++) {
				out.push(bytes[pos + i]);
			}

			pos += len;
		} while (!last);

		return out.concat(le32(crc32(bytes)), le32(bytes.length >>> 0));
	}

	/* ---------- SHA-256 / HMAC-SHA256 ---------- */

	var K256 = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];

	function rotr(x, n) {
		return (x >>> n) | (x << (32 - n));
	}

	function sha256(bytes) {
		var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
			msg = bytes.slice(0), bitLen = bytes.length * 8, w = [], i, j, a, b, c, d, e, f, g, hh, t1, t2, s0, s1,
			out = [];

		msg.push(0x80);

		while (msg.length % 64 !== 56) {
			msg.push(0);
		}

		// 64-bit big-endian length (messages here are far below 2^32 bits)
		msg.push(0, 0, 0, 0, (bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);

		for (i = 0; i < msg.length; i += 64) {
			for (j = 0; j < 16; j++) {
				w[j] = (msg[i + 4 * j] << 24) | (msg[i + 4 * j + 1] << 16) | (msg[i + 4 * j + 2] << 8) | msg[i + 4 * j + 3];
			}

			for (j = 16; j < 64; j++) {
				s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
				s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
				w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
			}

			a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];

			for (j = 0; j < 64; j++) {
				s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
				t1 = (hh + s1 + ((e & f) ^ (~e & g)) + K256[j] + w[j]) | 0;
				s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
				t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
				hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
			}

			h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
			h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
		}

		for (i = 0; i < 8; i++) {
			out.push((h[i] >>> 24) & 0xff, (h[i] >>> 16) & 0xff, (h[i] >>> 8) & 0xff, h[i] & 0xff);
		}

		return out;
	}

	function hmacSha256(key, data) {
		var k = key.length > 64 ? sha256(key) : key.slice(0), ipad = [], opad = [], i;

		while (k.length < 64) {
			k.push(0);
		}

		for (i = 0; i < 64; i++) {
			ipad.push(k[i] ^ 0x36);
			opad.push(k[i] ^ 0x5c);
		}

		return sha256(opad.concat(sha256(ipad.concat(data))));
	}

	/* ---------- AES-256 (encryption only) ---------- */

	var SBOX = (function () {
		// generate the AES S-box from GF(2^8) inverses and the affine transform
		var sbox = [], p = 1, q = 1, x;

		do {
			p = p ^ ((p << 1) & 0xff) ^ ((p & 0x80) ? 0x1b : 0);
			q ^= q << 1;
			q ^= q << 2;
			q ^= q << 4;
			q &= 0xff;
			if (q & 0x80) {
				q ^= 0x09;
			}
			x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
			sbox[p] = (x ^ 0x63) & 0xff;
		} while (p !== 1);

		sbox[0] = 0x63;

		return sbox;
	})();

	function xtime(b) {
		return ((b << 1) ^ ((b & 0x80) ? 0x1b : 0)) & 0xff;
	}

	function expandKey(key) {
		// AES-256: Nk = 8, Nr = 14 -> 60 words
		var w = [], i, t, rcon = 1;

		for (i = 0; i < 8; i++) {
			w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		}

		for (i = 8; i < 60; i++) {
			t = w[i - 1].slice(0);

			if (i % 8 === 0) {
				t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]];
				rcon = xtime(rcon);
			}
			else if (i % 8 === 4) {
				t = [SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]];
			}

			w[i] = [w[i - 8][0] ^ t[0], w[i - 8][1] ^ t[1], w[i - 8][2] ^ t[2], w[i - 8][3] ^ t[3]];
		}

		return w;
	}

	function encryptBlock(input, w) {
		var s = input.slice(0), round, c, i, t, a0, a1, a2, a3;

		function addRoundKey(r) {
			for (c = 0; c < 4; c++) {
				for (i = 0; i < 4; i++) {
					s[4 * c + i] ^= w[4 * r + c][i];
				}
			}
		}

		addRoundKey(0);

		for (round = 1; round <= 14; round++) {
			// SubBytes
			for (i = 0; i < 16; i++) {
				s[i] = SBOX[s[i]];
			}

			// ShiftRows (state is column-major: s[4*col + row])
			t = s.slice(0);
			for (c = 0; c < 4; c++) {
				for (i = 0; i < 4; i++) {
					s[4 * c + i] = t[4 * ((c + i) % 4) + i];
				}
			}

			// MixColumns (skipped in the final round)
			if (round !== 14) {
				for (c = 0; c < 4; c++) {
					a0 = s[4 * c]; a1 = s[4 * c + 1]; a2 = s[4 * c + 2]; a3 = s[4 * c + 3];
					t = a0 ^ a1 ^ a2 ^ a3;
					s[4 * c] ^= t ^ xtime(a0 ^ a1);
					s[4 * c + 1] ^= t ^ xtime(a1 ^ a2);
					s[4 * c + 2] ^= t ^ xtime(a2 ^ a3);
					s[4 * c + 3] ^= t ^ xtime(a3 ^ a0);
				}
			}

			addRoundKey(round);
		}

		return s;
	}

	function aes256CbcEncrypt(key, iv, data) {
		var w = expandKey(key), pad = 16 - (data.length % 16), buf = data.slice(0), out = [], prev = iv.slice(0),
			block, i, j;

		for (i = 0; i < pad; i++) {
			buf.push(pad);
		}

		for (i = 0; i < buf.length; i += 16) {
			block = [];

			for (j = 0; j < 16; j++) {
				block.push(buf[i + j] ^ prev[j]);
			}

			prev = encryptBlock(block, w);
			out = out.concat(prev);
		}

		return out;
	}

	/* ---------- public API ---------- */

	var counter = 0;

	function deriveIv(key, context, data) {
		var ivKey = hmacSha256(key, utf8Encode('pushover-e2e-iv-key'));

		counter++;

		return hmacSha256(ivKey, utf8Encode('pushover-e2e-iv|' + context + '|' + Date.now() + '|' + counter + '|'
			+ Math.random() + '|' + Math.random() + '|').concat(data)).slice(0, 16);
	}

	/**
	 * Encrypts one field value.
	 * @param {string} keyHex   64 hex characters (the key set in the Pushover app)
	 * @param {string} plaintext
	 * @param {string} context  unique context for IV derivation (e.g. eventid + field name)
	 * @return {string} base64(IV || ciphertext || HMAC)
	 */
	function encryptField(keyHex, plaintext, context) {
		var key = hexToBytes(keyHex), data = gzip(utf8Encode(plaintext)), ct, mac, iv;

		iv = deriveIv(key, context, data);
		ct = aes256CbcEncrypt(key, iv, data);
		mac = hmacSha256(key, iv.concat(ct));

		return base64Encode(iv.concat(ct, mac));
	}

	/**
	 * Largest UTF-8 plaintext (in bytes) whose encrypted form stays within `limit` characters.
	 * Pushover applies its field limits to the encrypted string and rejects (cannot truncate) longer ones.
	 * encrypted length = 4 * ceil((16 IV + CT + 32 HMAC) / 3), CT = 16 * (floor(G / 16) + 1),
	 * G = gzip size = plaintext + 10 header + 8 trailer + 5 per stored block (one block here).
	 * Returns -1 if not even an empty string fits.
	 */
	function maxPlainBytes(limit) {
		var ctMax = Math.floor((Math.floor(limit / 4) * 3 - 48) / 16) * 16,
			max = ctMax - 1 - 23;

		return (max < 0) ? -1 : max;
	}

	/** Cuts a string so that its UTF-8 form is at most maxBytes long (whole characters only), adds "…" if cut. */
	function truncateUtf8(str, maxBytes) {
		var ellipsis = '\u2026', bytes = 0, i = 0, c, n, b;

		str = String(str);

		if (utf8Encode(str).length <= maxBytes) {
			return str;
		}

		if (maxBytes >= 3) {
			maxBytes -= 3; // UTF-8 length of the ellipsis
		}
		else {
			ellipsis = ''; // no room for it
		}
		/*
		 * Walk by index, not with a regex: in Zabbix (Duktape) a character outside the BMP that comes from a
		 * parameter is ONE code unit (charCodeAt > 0xFFFF), in Node it is a surrogate pair. A regex like
		 * [\s\S] does not match the former, which silently dropped every emoji when cutting.
		 */
		while (i < str.length) {
			c = str.charCodeAt(i);
			n = (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length
				&& str.charCodeAt(i + 1) >= 0xdc00 && str.charCodeAt(i + 1) <= 0xdfff) ? 2 : 1;
			b = utf8Encode(str.substr(i, n)).length;

			if (bytes + b > maxBytes) {
				break;
			}

			bytes += b;
			i += n;
		}

		return str.substr(0, i) + ellipsis;
	}

	/**
	 * Like encryptField, but first shortens the plaintext so that the result fits into `limit` characters
	 * (Pushover limits: title 250, message 1024, url 512).
	 */
	function encryptFieldLimited(keyHex, plaintext, context, limit) {
		var max = maxPlainBytes(limit);

		return encryptField(keyHex, (max >= 0) ? truncateUtf8(plaintext, max) : plaintext, context);
	}

	/*
	 * Maximum plaintext bytes per field, from Pushover's limits (250/1024/512 characters) applied to the encrypted
	 * string. url_title (limit 100) cannot fit at all: even an empty string encrypts to 108 characters. It is
	 * therefore never sent with encryption; the app then shows the (encrypted) URL itself as the link.
	 */
	var FIELD_MAX = {title: maxPlainBytes(250), message: maxPlainBytes(1024), url: maxPlainBytes(512)};

	/**
	 * Encrypts title, message and url of a Pushover request object in place and sets encrypted = 1.
	 *  - url_title is removed: it cannot fit its 100-character limit once encrypted
	 *  - empty fields are removed (nothing to encrypt, behaviour of empty encrypted fields is undefined),
	 *    so are non-string values (never sent unencrypted next to encrypted = 1)
	 *  - title and message are shortened to fit ("..." appended)
	 *  - a url that does not fit is removed (a cut URL would be broken)
	 * @param {string} keyHex  64 hex characters
	 * @param {object} data    request object as built by the Zabbix Pushover webhook
	 * @param {string} eventid used in the IV nonce
	 * @return {object} data
	 */
	function encryptPayload(keyHex, data, eventid) {
		var fields = ['title', 'message', 'url'], i, f;

		hexToBytes(keyHex); // validate the key before touching the request

		delete data.url_title;

		for (i = 0; i < fields.length; i++) {
			if (fields[i] in data && (typeof data[fields[i]] !== 'string' || data[fields[i]] === '')) {
				delete data[fields[i]];
			}
		}

		if (typeof data.url === 'string' && utf8Encode(data.url).length > FIELD_MAX.url) {
			delete data.url;
		}

		for (i = 0; i < fields.length; i++) {
			f = fields[i];

			if (typeof data[f] === 'string') {
				data[f] = encryptField(keyHex, truncateUtf8(data[f], FIELD_MAX[f]), eventid + '|' + f);
			}
		}

		data.encrypted = 1;

		return data;
	}

	return {
		encryptField: encryptField,
		encryptFieldLimited: encryptFieldLimited,
		encryptPayload: encryptPayload,
		FIELD_MAX: FIELD_MAX,
		maxPlainBytes: maxPlainBytes,
		truncateUtf8: truncateUtf8,
		// exported for unit tests
		_utf8Encode: utf8Encode,
		_hexToBytes: hexToBytes,
		_base64Encode: base64Encode,
		_gzip: gzip,
		_crc32: crc32,
		_sha256: sha256,
		_hmacSha256: hmacSha256,
		_aes256CbcEncrypt: aes256CbcEncrypt
	};
})();

if (typeof module !== 'undefined' && module.exports) {
	module.exports = PushoverE2E;
}
