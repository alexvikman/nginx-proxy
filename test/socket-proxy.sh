#!/usr/bin/env bash
# End-to-end test of the socket-proxy mode: the proxy has no Docker socket and
# reaches the Docker API only through a socket-proxy container on an internal
# network. Checks that routing and events still work, that other containers'
# secrets are filtered out, and that write requests are refused.
#
# Usage: test/socket-proxy.sh [image]   (default: nginx-proxy:test)
set -euo pipefail

IMAGE="${1:-nginx-proxy:test}"
RUN_ID="np-sp-$$"
NET="$RUN_ID"
DOCKER_NET="$RUN_ID-docker"
# Only backends carry this label. The proxy does not, so it can only inspect
# itself because it shares the socket proxy's network.
FILTERS="label=$RUN_ID.route"
PASS=0
FAIL=0

cleanup() {
	local status=$?
	if ((status != 0 || FAIL > 0)); then
		echo "--- proxy logs ---"
		docker logs "$RUN_ID-proxy" 2>&1 | grep -v '\[notice\]' | tail -n 30 || true
		echo "--- socket-proxy logs ---"
		docker logs "$RUN_ID-socket-proxy" 2>&1 | tail -n 30 || true
	fi
	docker ps -aq --filter "label=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network rm "$NET" "$DOCKER_NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok() { echo "ok   $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }

backend() { # name, extra docker args...
	local name="$1"
	shift
	docker run -d --label "$RUN_ID" --label "$RUN_ID.route=yes" --name "$RUN_ID-$name" --network "$NET" "$@" \
		docker.io/library/busybox:stable \
		sh -c "mkdir /www && echo hello-$name > /www/index.html && exec httpd -f -p 8080 -h /www" >/dev/null
}

kurl() { docker exec "$RUN_ID-client" curl -sS --max-time 2 "$@" 2>/dev/null || true; }

# eventually NAME WANT CURL_ARGS... : retries for up to 10 s.
eventually() {
	local name="$1" want="$2" got=""
	shift 2
	for _ in $(seq 1 40); do
		got="$(kurl "$@")"
		[[ "$got" == "$want" ]] && break
		sleep 0.25
	done
	if [[ "$got" == "$want" ]]; then ok "$name"; else fail "$name: want '$want', got '$got'"; fi
}

docker network create "$NET" >/dev/null
docker network create --internal "$DOCKER_NET" >/dev/null

# The only container with the Docker socket. It publishes no port and is only
# on the internal network.
docker run -d --label "$RUN_ID" --name "$RUN_ID-socket-proxy" \
	--network "$DOCKER_NET" --network-alias socket-proxy \
	--cap-drop ALL --security-opt no-new-privileges --read-only \
	-v /var/run/docker.sock:/tmp/docker.sock:ro \
	-e DOCKER_CONTAINER_FILTERS="$FILTERS" \
	"$IMAGE" socket-proxy >/dev/null

# The proxy and a client both join the internal network before they start.
docker create --label "$RUN_ID" --name "$RUN_ID-proxy" --network "$NET" \
	--cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID --cap-add NET_BIND_SERVICE \
	--security-opt no-new-privileges \
	-e DOCKER_HOST=tcp://socket-proxy:2375 -e ENABLE_ACME=false -e DOCKER_CONTAINER_FILTERS="$FILTERS" \
	"$IMAGE" >/dev/null
docker create --label "$RUN_ID" --name "$RUN_ID-client" --network "$NET" \
	--entrypoint sleep "$IMAGE" infinity >/dev/null
docker network connect "$DOCKER_NET" "$RUN_ID-proxy"
docker network connect "$DOCKER_NET" "$RUN_ID-client"
docker start "$RUN_ID-proxy" "$RUN_ID-client" >/dev/null
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$RUN_ID-proxy")"

backend app -e VIRTUAL_HOST=sp.test -e VIRTUAL_PORT=8080 -e DB_PASSWORD=s3cr3t-value \
	--label com.example.token=label-secret

eventually "routes through the socket proxy" hello-app -H "Host: sp.test" "http://$PROXY_IP/"
backend late -e VIRTUAL_HOST=late.test -e VIRTUAL_PORT=8080
eventually "events arrive through the socket proxy" hello-late -H "Host: late.test" "http://$PROXY_IP/"

inspect="$(kurl "http://socket-proxy:2375/containers/$RUN_ID-app/json")"
if [[ "$inspect" == *VIRTUAL_HOST=sp.test* ]]; then ok "inspect passes on VIRTUAL_HOST"; else fail "inspect lost VIRTUAL_HOST: $inspect"; fi
if [[ "$inspect" != *s3cr3t-value* && "$inspect" != *DB_PASSWORD* && "$inspect" != *label-secret* ]]; then
	ok "other variables and labels are filtered out"
else
	fail "inspect passes on secrets: $inspect"
fi

# A container the filters exclude does not exist as far as the proxy can tell.
docker run -d --label "$RUN_ID" --name "$RUN_ID-hidden" --network "$NET" -e VIRTUAL_HOST=hidden.test \
	docker.io/library/busybox:stable sleep 600 >/dev/null
code="$(kurl -o /dev/null -w '%{http_code}' "http://socket-proxy:2375/containers/$RUN_ID-hidden/json")"
if [[ "$code" == 404 ]]; then ok "containers outside DOCKER_CONTAINER_FILTERS cannot be inspected"; else fail "inspect of an excluded container: want 404, got $code"; fi

for req in "POST /containers/create" "POST /containers/$RUN_ID-app/stop" "GET /info" "GET /containers/$RUN_ID-app/logs"; do
	code="$(kurl -o /dev/null -w '%{http_code}' -X "${req% *}" "http://socket-proxy:2375${req#* }")"
	if [[ "$code" == 403 || "$code" == 405 ]]; then ok "refuses $req"; else fail "$req: want 403 or 405, got $code"; fi
done
[[ "$(docker inspect -f '{{.State.Running}}' "$RUN_ID-app")" == true ]] || fail "the backend was stopped"
# A client-chosen filter would tell whether the hidden label has this value.
code="$(kurl -o /dev/null -w '%{http_code}' -G --data-urlencode 'filters={"label":["com.example.token=label-secret"]}' "http://socket-proxy:2375/containers/json")"
if [[ "$code" == 403 ]]; then ok "refuses client-chosen list filters"; else fail "client-chosen list filters: want 403, got $code"; fi

logs="$(docker logs "$RUN_ID-proxy" 2>&1)"
if [[ "$logs" == *"could not determine nginx-proxy's own container"* ]]; then
	fail "the proxy did not find its own container"
fi
if [[ "$logs" == *"socket proxy filters what this proxy reads"* ]]; then
	ok "the proxy recognises a socket proxy of the same version"
else
	fail "the proxy did not check the socket proxy's filter"
fi

echo "passed: $PASS, failed: $FAIL"
((FAIL == 0))
