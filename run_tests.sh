#!/bin/bash
# Builds the media type and runs all offline tests (no Pushover account needed).
#   1. primitives vs Node crypto/zlib      (test/test_node.js)
#   2. webhook script, with/without key    (test/test_webhook_node.js, mocked Zabbix)
#   3. ciphertexts decrypted with openssl  (test/verify_openssl.sh, independent of our code)
# Integration (needs podman or docker): test/env.sh up && test/integration_test.sh; test/env.sh down
set -euo pipefail
cd "$(dirname "$0")"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
python3 -I build.py
node test/test_node.js "$TMP/lib.json"
test/verify_openssl.sh "$TMP/lib.json"
node test/test_webhook_node.js "$TMP/webhook.json"
test/verify_openssl.sh "$TMP/webhook.json"
echo "=== ALL TESTS PASSED ==="
