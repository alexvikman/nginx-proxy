#!/usr/bin/env bash
# End-to-end test: runs the nginx-proxy image against real containers and
# checks routing, TLS, path rewriting, event handling and config rollback.
#
# Usage: test/integration.sh [image]   (default: nginx-proxy:test)
set -euo pipefail

IMAGE="${1:-nginx-proxy:test}"
RUN_ID="np-test-$$"
NET="$RUN_ID"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
	local status=$?
	if ((status != 0 || FAIL > 0)); then
		echo "--- proxy logs ---"
		docker logs "$RUN_ID-proxy" 2>&1 | tail -n 60 || true
	fi
	docker ps -aq --filter "label=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

backend() { # name, extra docker args...
	local name="$1"
	shift
	docker run -d --label "$RUN_ID" --name "$RUN_ID-$name" --network "$NET" "$@" \
		docker.io/library/busybox:stable \
		sh -c "mkdir -p /www/api && echo hello-$name > /www/index.html && echo api-$name > /www/api/index.html && exec httpd -f -p 8080 -h /www" >/dev/null
}

# Requests are made from a container on the test network so results do not
# depend on the host's curl/TLS library.
kurl() { docker exec "$RUN_ID-client" curl -sS --max-time 2 "$@" 2>/dev/null || true; }

# check NAME EXPECTED CURL_ARGS... : retries for up to 10 s so event handling
# has time to settle. EXPECTED is a status code or body:<text>.
check() {
	local name="$1" want="$2" got=""
	shift 2
	for _ in $(seq 1 40); do
		got="$(kurl -o /dev/null -w '%{http_code}' "$@")"
		if [[ "$want" == body:* ]]; then
			got="$(kurl "$@")"
			[[ "$got" == "${want#body:}" ]] && break
		else
			[[ "$got" == "$want" ]] && break
		fi
		sleep 0.25
	done
	if [[ "$want" == body:* && "$got" == "${want#body:}" ]] || [[ "$got" == "$want" ]]; then
		echo "ok   $name"
		PASS=$((PASS + 1))
	else
		echo "FAIL $name: want $want, got $got"
		FAIL=$((FAIL + 1))
	fi
}

docker network create "$NET" >/dev/null
mkdir -p "$WORK/certs" "$WORK/vhost.d"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
	-subj "/CN=tls.test" -addext "subjectAltName=DNS:tls.test" \
	-keyout "$WORK/certs/tls.test.key" -out "$WORK/certs/tls.test.crt" 2>/dev/null
chmod 644 "$WORK/certs/"*

# The proxy runs with the reduced privileges the README recommends, so that
# setup is the one that is tested.
docker run -d --label "$RUN_ID" --name "$RUN_ID-proxy" --network "$NET" \
	--cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID --cap-add NET_BIND_SERVICE \
	--security-opt no-new-privileges \
	-v /var/run/docker.sock:/tmp/docker.sock:ro \
	-v "$WORK/certs:/etc/nginx/certs" \
	-v "$WORK/vhost.d:/etc/nginx/vhost.d" \
	-e ENABLE_ACME=false \
	"$IMAGE" >/dev/null
docker run -d --label "$RUN_ID" --name "$RUN_ID-client" --network "$NET" \
	--entrypoint sleep "$IMAGE" infinity >/dev/null
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$RUN_ID-proxy")"
HTTP="$PROXY_IP"

backend a -e VIRTUAL_HOST=a.test -e VIRTUAL_PORT=8080
backend b -e VIRTUAL_HOST=b.test -e VIRTUAL_PORT=8080 -e VIRTUAL_PATH=/b/ -e VIRTUAL_DEST=/
backend tls -e VIRTUAL_HOST=tls.test -e VIRTUAL_PORT=8080
backend evil -e "VIRTUAL_HOST=evil.test;" -e VIRTUAL_PORT=8080
# nginx expands variables in proxy_pass: as a host name this would let the
# client choose where the proxy connects to.
# shellcheck disable=SC2016
backend ssrf -e 'VIRTUAL_HOST=$http_x_target' -e VIRTUAL_PORT=8080
A_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$RUN_ID-a")"

check "routes by Host header" "body:hello-a" -H "Host: a.test" "http://$HTTP/"
check "unknown host gets 503" 503 -H "Host: nope.test" "http://$HTTP/"
check "VIRTUAL_PATH + VIRTUAL_DEST rewrite" "body:api-b" -H "Host: b.test" "http://$HTTP/b/api/"
check "missing root location returns DEFAULT_ROOT" 404 -H "Host: b.test" "http://$HTTP/"
check "HTTP redirects to HTTPS when a cert exists" 301 -H "Host: tls.test" "http://$HTTP/"
check "HTTPS with certificate" "body:hello-tls" -k --resolve "tls.test:443:$PROXY_IP" "https://tls.test/"
check "HTTPS without certificate is rejected" 000 -k --resolve "a.test:443:$PROXY_IP" "https://a.test/"
check "ACME challenge path is served on redirecting hosts" 404 -H "Host: tls.test" "http://$HTTP/.well-known/acme-challenge/missing"
check "unsafe VIRTUAL_HOST is ignored" 503 -H "Host: evil.test;" "http://$HTTP/"
# shellcheck disable=SC2016
check "a variable as VIRTUAL_HOST is ignored" 503 -H 'Host: $http_x_target' -H "X-Target: $A_IP:8080" "http://$HTTP/"

# Load balancing across two containers with the same VIRTUAL_HOST.
backend lb1 -e VIRTUAL_HOST=lb.test -e VIRTUAL_PORT=8080
backend lb2 -e VIRTUAL_HOST=lb.test -e VIRTUAL_PORT=8080
check "new container is picked up from events" 200 -H "Host: lb.test" "http://$HTTP/"
for _ in $(seq 1 40); do
	seen="$(for _ in $(seq 1 10); do kurl -H 'Host: lb.test' "http://$HTTP/"; done | sort -u | tr '\n' ' ')"
	[[ "$seen" == "hello-lb1 hello-lb2 " ]] && break
	sleep 0.25
done
if [[ "$seen" == "hello-lb1 hello-lb2 " ]]; then
	echo "ok   load balances across containers"
	PASS=$((PASS + 1))
else
	echo "FAIL load balances across containers: saw '$seen'"
	FAIL=$((FAIL + 1))
fi

# A container whose values pass validation but are rejected by nginx (here an
# unbalanced regex) must not block hosts that start after it.
backend badre -e 'VIRTUAL_HOST=~^(unbalanced' -e VIRTUAL_PORT=8080
backend late -e VIRTUAL_HOST=late.test -e VIRTUAL_PORT=8080
check "a host nginx rejects does not block later hosts" "body:hello-late" -H "Host: late.test" "http://$HTTP/"
docker rm -f "$RUN_ID-badre" >/dev/null

# A broken vhost.d include must not take the proxy down.
echo "this is not nginx syntax" >"$WORK/vhost.d/broken.test"
backend broken -e VIRTUAL_HOST=broken.test -e VIRTUAL_PORT=8080
sleep 2
check "invalid config is rolled back, other hosts keep working" "body:hello-a" -H "Host: a.test" "http://$HTTP/"
check "host with invalid include is not activated" 503 -H "Host: broken.test" "http://$HTTP/"
rm "$WORK/vhost.d/broken.test"
docker rm -f "$RUN_ID-broken" >/dev/null

docker rm -f "$RUN_ID-a" >/dev/null
check "removed container is dropped" 503 -H "Host: a.test" "http://$HTTP/"

logs="$(docker logs "$RUN_ID-proxy" 2>&1)"
if [[ "$logs" != *"nginx -t rejected"* ]]; then
	echo "FAIL expected a rollback message in the proxy log"
	FAIL=$((FAIL + 1))
fi

echo "passed: $PASS, failed: $FAIL"
((FAIL == 0))
