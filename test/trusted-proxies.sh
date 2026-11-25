#!/usr/bin/env bash
# End-to-end test of TRUSTED_PROXIES: forwarded headers and the client
# address are only believed from the listed proxies. A backend echoes the
# headers it receives; one client stands in for a trusted proxy (such as a
# Cloudflare edge), another for a client that bypasses it.
#
# Usage: test/trusted-proxies.sh [image]   (default: nginx-proxy:test)
set -euo pipefail

IMAGE="${1:-nginx-proxy:test}"
RUN_ID="np-tp-$$"
NET="$RUN_ID"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
	local status=$?
	if ((status != 0 || FAIL > 0)); then
		echo "--- proxy logs ---"
		docker logs "$RUN_ID-proxy" 2>&1 | grep -v '\[notice\]' | tail -n 30 || true
	fi
	docker ps -aq --filter "label=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { echo "ok   $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }

# A /24 that is unlikely to be in use, with fixed addresses for the clients.
SUBNET="10.213.$((RANDOM % 250)).0/24"
PREFIX="${SUBNET%.0/24}"
TRUSTED_IP="$PREFIX.10"
UNTRUSTED_IP="$PREFIX.11"
docker network create --subnet "$SUBNET" "$NET" >/dev/null

# nginx from the image under test, answering with the headers it was sent.
cat >"$WORK/echo.conf" <<'NGINX'
events {}
http {
    server {
        listen 8080;
        location / {
            return 200 "xff=$http_x_forwarded_for real=$http_x_real_ip proto=$http_x_forwarded_proto host=$http_x_forwarded_host port=$http_x_forwarded_port\n";
        }
    }
}
NGINX
chmod 644 "$WORK/echo.conf"
docker run -d --label "$RUN_ID" --name "$RUN_ID-echo" --network "$NET" \
	-e VIRTUAL_HOST=echo.test -e VIRTUAL_PORT=8080 \
	-v "$WORK/echo.conf:/echo.conf:ro" \
	--entrypoint nginx "$IMAGE" -c /echo.conf -g 'daemon off;' >/dev/null

docker run -d --label "$RUN_ID" --name "$RUN_ID-proxy" --network "$NET" \
	--cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID --cap-add NET_BIND_SERVICE \
	--security-opt no-new-privileges \
	-v /var/run/docker.sock:/tmp/docker.sock:ro \
	-e ENABLE_ACME=false -e TRUSTED_PROXIES="cloudflare,$TRUSTED_IP" \
	"$IMAGE" >/dev/null
for name in trusted untrusted; do
	ip="$TRUSTED_IP"
	[[ "$name" == untrusted ]] && ip="$UNTRUSTED_IP"
	docker run -d --label "$RUN_ID" --name "$RUN_ID-$name" --network "$NET" --ip "$ip" \
		--entrypoint sleep "$IMAGE" infinity >/dev/null
done
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$RUN_ID-proxy")"

# ask CLIENT CURL_ARGS... : the backend's answer, retried while the proxy starts.
ask() {
	local client="$1" got=""
	shift
	for _ in $(seq 1 40); do
		got="$(docker exec "$RUN_ID-$client" curl -sS --max-time 2 -H "Host: echo.test" "$@" "http://$PROXY_IP/" 2>/dev/null || true)"
		[[ "$got" == xff=* ]] && break
		sleep 0.25
	done
	echo "$got"
}

expect() { # NAME GOT WANT
	if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1: got '$2', want '$3'"; fi
}

forged=(-H "X-Forwarded-For: 203.0.113.7" -H "X-Forwarded-Proto: https" -H "X-Forwarded-Host: shop.example" -H "X-Forwarded-Port: 443")

expect "a trusted proxy's headers are passed on" \
	"$(ask trusted "${forged[@]}")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=https host=shop.example port=443"

expect "a client that bypasses the proxy cannot forge headers" \
	"$(ask untrusted "${forged[@]}")" \
	"xff=$UNTRUSTED_IP real=$UNTRUSTED_IP proto=http host=echo.test port=80"

# Cloudflare appends the address it saw: what the client wrote in front of it
# is dropped.
expect "addresses a client puts in front are dropped" \
	"$(ask trusted -H "X-Forwarded-For: 198.51.100.1, 203.0.113.7")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=http host=echo.test port=80"

expect "only http and https are believed as the scheme" \
	"$(ask trusted -H "X-Forwarded-For: 203.0.113.7" -H "X-Forwarded-Proto: javascript")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=http host=echo.test port=80"

logs="$(docker logs "$RUN_ID-proxy" 2>&1)"
if [[ "$logs" == *"nginx -t rejected"* ]]; then fail "nginx rejected the generated configuration"; fi

# An invalid TRUSTED_PROXIES must stop the proxy instead of being ignored.
if docker run --rm --label "$RUN_ID" -e TRUSTED_PROXIES=0.0.0.0/0 -v /var/run/docker.sock:/tmp/docker.sock:ro "$IMAGE" >/dev/null 2>&1; then
	fail "TRUSTED_PROXIES=0.0.0.0/0 was accepted"
else
	ok "an invalid TRUSTED_PROXIES stops the proxy"
fi

echo "passed: $PASS, failed: $FAIL"
((FAIL == 0))
