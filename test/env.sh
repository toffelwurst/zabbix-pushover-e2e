#!/bin/bash
# Throwaway Zabbix test instance for the integration and live tests.
#
#   test/env.sh up      start PostgreSQL, server, web (http://127.0.0.1:8081, Admin / zabbix), an active agent
#                       "testpc" and a fake Pushover endpoint "echo" (logs requests to test/.echo/requests.jsonl)
#   test/env.sh down    remove containers, volume and network
#
# CONTAINER_ENGINE=podman (default) or docker.  ZBX_TAG=alpine-8.0-latest (default) or e.g. alpine-7.0-latest.
# WEB_IMAGE overrides the frontend image, see test/Containerfile.web-apparmor for hosts whose AppArmor profile
# "php-fpm" blocks php-fpm inside the container (seen on Nobara/Fedora with rootless podman).
# Never point the tests at a production Zabbix: they log in with the default Admin password and create/delete objects.
set -euo pipefail
E=${CONTAINER_ENGINE:-podman}
TAG=${ZBX_TAG:-alpine-8.0-latest}
WEB=${WEB_IMAGE:-docker.io/zabbix/zabbix-web-nginx-pgsql:$TAG}
N=zbxtest
HERE=$(cd "$(dirname "$0")" && pwd)
DB=(-e POSTGRES_USER=zabbix -e POSTGRES_PASSWORD=zabbix -e POSTGRES_DB=zabbix)

down() {
	$E rm -f -v zbx-echo zbx-agent zbx-web zbx-server zbx-db >/dev/null 2>&1 || true  # -v: anonymous volumes too
	$E volume rm -f zbx-db >/dev/null 2>&1 || true
	$E network rm -f $N >/dev/null 2>&1 || true
}

up() {
	$E network inspect $N >/dev/null 2>&1 || $E network create $N >/dev/null
	mkdir -p "$HERE/.echo"
	$E run -d --name zbx-db --network $N --network-alias db "${DB[@]}" -v zbx-db:/var/lib/postgresql \
		docker.io/library/postgres:18-alpine >/dev/null
	$E run -d --name zbx-server --network $N --network-alias server "${DB[@]}" -e DB_SERVER_HOST=db \
		docker.io/zabbix/zabbix-server-pgsql:$TAG >/dev/null
	$E run -d --name zbx-web --network $N -p 127.0.0.1:8081:8080 "${DB[@]}" -e DB_SERVER_HOST=db \
		-e ZBX_SERVER_HOST=server -e PHP_TZ=UTC "$WEB" >/dev/null
	$E run -d --name zbx-echo --network $N --network-alias echo -v "$HERE:/t:ro,Z" -v "$HERE/.echo:/data:Z" \
		docker.io/library/python:3-alpine python3 /t/echo_server.py /data/requests.jsonl >/dev/null
	# the server creates the schema on first start; wait until the API can log in (frontend alone is not enough)
	echo -n 'waiting for Zabbix (schema creation takes a minute) '
	until curl -sf -H 'Content-Type: application/json-rpc' -d '{"jsonrpc":"2.0","method":"user.login","params":{"username":"Admin","password":"zabbix"},"id":1}' \
		http://127.0.0.1:8081/api_jsonrpc.php 2>/dev/null | grep -q '"result"'; do echo -n .; sleep 5; done; echo
	# host "testpc" with an active agent (the tests use its agent.ping item as a trigger target)
	python3 -I - <<'EOF'
import json, urllib.request
U = 'http://127.0.0.1:8081/api_jsonrpc.php'
def call(m, p, t=None):
    h = {'Content-Type': 'application/json-rpc'}
    if t: h['Authorization'] = 'Bearer ' + t
    r = json.load(urllib.request.urlopen(urllib.request.Request(U, json.dumps({'jsonrpc': '2.0', 'method': m, 'params': p, 'id': 1}).encode(), h)))
    if 'error' in r: raise SystemExit(r['error'])
    return r['result']
t = call('user.login', {'username': 'Admin', 'password': 'zabbix'})
g = call('hostgroup.get', {'filter': {'name': ['Linux servers']}, 'output': ['groupid']}, t)[0]['groupid']
tpl = call('template.get', {'filter': {'host': ['Linux by Zabbix agent active']}, 'output': ['templateid']}, t)[0]['templateid']
call('action.create', {'name': 'Autoregister testpc', 'eventsource': 2, 'status': 0,
     'filter': {'evaltype': 0, 'conditions': [{'conditiontype': 22, 'operator': 2, 'value': 'testpc'}]},
     'operations': [{'operationtype': 2}, {'operationtype': 4, 'opgroup': [{'groupid': g}]},
                    {'operationtype': 6, 'optemplate': [{'templateid': tpl}]}]}, t)
EOF
	$E run -d --name zbx-agent --network $N --hostname testpc -e ZBX_HOSTNAME=testpc -e ZBX_SERVER_HOST=server \
		-e ZBX_PASSIVE_ALLOW=false -e ZBX_METADATA=testpc docker.io/zabbix/zabbix-agent2:$TAG >/dev/null
	echo -n 'waiting for autoregistration of testpc '
	until python3 -I -c '
import json,sys,urllib.request
U="http://127.0.0.1:8081/api_jsonrpc.php"
def c(m,p,t=None):
    h={"Content-Type":"application/json-rpc"}
    if t: h["Authorization"]="Bearer "+t
    return json.load(urllib.request.urlopen(urllib.request.Request(U,json.dumps({"jsonrpc":"2.0","method":m,"params":p,"id":1}).encode(),h)))["result"]
t=c("user.login",{"username":"Admin","password":"zabbix"})
sys.exit(0 if c("host.get",{"filter":{"host":["testpc"]},"output":["hostid"]},t) else 1)'; do echo -n .; sleep 5; done; echo
	echo "ready: http://127.0.0.1:8081 (Admin / zabbix), fake Pushover log: $HERE/.echo/requests.jsonl"
}

case "${1:-}" in
	up) up ;;
	down) down ;;
	*) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
