#!/bin/bash
# Decrypts encrypted fields exactly the way Pushover's documented scheme works,
# using only openssl/xxd/gzip (independent of our JS code):
#   base64 -> IV(16) | ciphertext | HMAC(32); verify HMAC-SHA256(key, IV|CT); AES-256-CBC decrypt; gunzip
# Usage: verify_openssl.sh samples.json      (JSON: {"key": "<hex>", "samples": [{"plain": ..., "enc": ...}]})
set -euo pipefail
F=${1:?samples.json}
KEY=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["key"])' "$F")
N=$(python3 -I -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["samples"]))' "$F")
[ "$N" -gt 0 ] || { echo "FAIL: no samples in $F"; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fails=0
for i in $(seq 0 $((N-1))); do
	python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]))["samples"][int(sys.argv[2])];open(sys.argv[3],"w").write(d["enc"]);open(sys.argv[4],"wb").write(d["plain"].encode())' "$F" "$i" "$TMP/enc.b64" "$TMP/plain"
	openssl base64 -d -A -in "$TMP/enc.b64" -out "$TMP/raw"
	SIZE=$(stat -c %s "$TMP/raw")
	head -c 16 "$TMP/raw" > "$TMP/iv"
	head -c $((SIZE-32)) "$TMP/raw" | tail -c +17 > "$TMP/ct"
	tail -c 32 "$TMP/raw" > "$TMP/mac"
	IV=$(xxd -p "$TMP/iv" | tr -d '\n')
	MAC_EXP=$(cat "$TMP/iv" "$TMP/ct" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$KEY" -binary | xxd -p | tr -d '\n')
	MAC_GOT=$(xxd -p "$TMP/mac" | tr -d '\n')
	if [ "$MAC_EXP" != "$MAC_GOT" ]; then echo "FAIL sample $i: HMAC mismatch"; fails=$((fails+1)); continue; fi
	if ! openssl enc -d -aes-256-cbc -K "$KEY" -iv "$IV" -in "$TMP/ct" | gzip -dc > "$TMP/dec"; then
		echo "FAIL sample $i: decrypt/gunzip"; fails=$((fails+1)); continue
	fi
	if cmp -s "$TMP/dec" "$TMP/plain"; then echo "ok   sample $i ($(head -c 40 "$TMP/plain"))"; else echo "FAIL sample $i: plaintext differs"; fails=$((fails+1)); fi
done
[ $fails -eq 0 ] && echo "all openssl round trips passed" || { echo "$fails FAILED"; exit 1; }
