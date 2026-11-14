#!/bin/bash
# Real alert flow inside Zabbix (Duktape engine): needs a running throwaway instance (test/env.sh up).
# Imports dist/media_pushover_e2e.yaml, sends a disaster alert to the fake Pushover endpoint and decrypts the
# captured request with openssl only. Cleans up its Zabbix objects afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d); trap 'rm -rf "$TMP"; python3 -I test/zabbix_e2e_test.py test/.echo/requests.jsonl /dev/null cleanup >/dev/null' EXIT
python3 -I test/zabbix_e2e_test.py test/.echo/requests.jsonl "$TMP/zabbix.json"
test/verify_openssl.sh "$TMP/zabbix.json"
echo "=== INTEGRATION TEST PASSED ==="
