#!/usr/bin/env bash
# End-to-end test of TRUSTED_PROXIES: forwarded headers and the client
# address are only believed from the listed proxies. A backend echoes the
# headers it receives. Clients stand in for a load balancer listed by
# address, a Cloudflare edge (on a network inside Cloudflare's ranges) and a
# client that bypasses both.
#
# Usage: test/trusted-proxies.sh [image]   (default: nginx-proxy:test)
set -euo pipefail

IMAGE="${1:-nginx-proxy:test}"
RUN_ID="np-tp-$$"
NET="$RUN_ID"
EDGE_NET="$RUN_ID-edge"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
	local status=$?
	if ((status != 0 || FAIL > 0)); then
		for p in proxy lbonly; do
			echo "--- $p logs ---"
			docker logs "$RUN_ID-$p" 2>&1 | grep -v '\[notice\]' | tail -n 20 || true
		done
	fi
	docker ps -aq --filter "label=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network rm "$NET" "$EDGE_NET" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

ok() { echo "ok   $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }

# Subnets unlikely to be in use. The edge network lies inside Cloudflare's
# 104.16.0.0/13, so its clients count as Cloudflare.
R=$((RANDOM % 250))
PLAIN="10.213.$R"
EDGE="104.16.$((240 + RANDOM % 10))"
LB_IP="$PLAIN.10"
UNTRUSTED_IP="$PLAIN.11"
docker network create --subnet "$PLAIN.0/24" "$NET" >/dev/null
docker network create --subnet "$EDGE.0/24" "$EDGE_NET" >/dev/null

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

proxy() { # name TRUSTED_PROXIES
	docker create --label "$RUN_ID" --name "$RUN_ID-$1" --network "$NET" \
		--cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID --cap-add NET_BIND_SERVICE \
		--security-opt no-new-privileges \
		-v /var/run/docker.sock:/tmp/docker.sock:ro \
		-e ENABLE_ACME=false -e TRUSTED_PROXIES="$2" \
		"$IMAGE" >/dev/null
}
proxy proxy "cloudflare,$LB_IP"
docker network connect "$EDGE_NET" "$RUN_ID-proxy"
proxy lbonly "$LB_IP"
docker start "$RUN_ID-proxy" "$RUN_ID-lbonly" >/dev/null

client() { # name network ip
	docker run -d --label "$RUN_ID" --name "$RUN_ID-$1" --network "$2" --ip "$3" \
		--entrypoint sleep "$IMAGE" infinity >/dev/null
}
client lb "$NET" "$LB_IP"
client untrusted "$NET" "$UNTRUSTED_IP"
client edge "$EDGE_NET" "$EDGE.10"

ip_on() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$RUN_ID-$1"; }
PROXY="$(ip_on proxy "$NET")"
PROXY_EDGE="$(ip_on proxy "$EDGE_NET")"
LBONLY="$(ip_on lbonly "$NET")"

# ask CLIENT PROXY_IP CURL_ARGS... : the backend's answer, retried while the
# proxy starts.
ask() {
	local client="$1" target="$2" got=""
	shift 2
	for _ in $(seq 1 40); do
		got="$(docker exec "$RUN_ID-$client" curl -sS --max-time 2 -H "Host: echo.test" "$@" "http://$target/" 2>/dev/null || true)"
		[[ "$got" == xff=* ]] && break
		sleep 0.25
	done
	echo "$got"
}

expect() { # NAME GOT WANT
	if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1: got '$2', want '$3'"; fi
}

headers=(-H "CF-Connecting-IP: 203.0.113.7" -H "X-Forwarded-For: 198.51.100.1" -H "X-Forwarded-Proto: https" -H "X-Forwarded-Host: shop.example" -H "X-Forwarded-Port: 443")

# With "cloudflare" trusted, the client address comes from CF-Connecting-IP.
expect "a proxy listed by address has all its headers believed" \
	"$(ask lb "$PROXY" "${headers[@]}")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=https host=shop.example port=443"

# Any Cloudflare customer can send from these addresses: only the client
# address Cloudflare sets and the scheme are believed.
expect "from Cloudflare, host and port are not believed" \
	"$(ask edge "$PROXY_EDGE" "${headers[@]}")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=https host=echo.test port=80"

expect "a client that bypasses the proxies cannot forge headers" \
	"$(ask untrusted "$PROXY" "${headers[@]}")" \
	"xff=$UNTRUSTED_IP real=$UNTRUSTED_IP proto=http host=echo.test port=80"

expect "only http and https are believed as the scheme" \
	"$(ask edge "$PROXY_EDGE" -H "CF-Connecting-IP: 203.0.113.7" -H "X-Forwarded-Proto: javascript")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=http host=echo.test port=80"

# Without Cloudflare the address comes from X-Forwarded-For, where what a
# client wrote in front of the proxy's entry is dropped.
expect "addresses a client puts in front are dropped" \
	"$(ask lb "$LBONLY" -H "X-Forwarded-For: 198.51.100.1, 203.0.113.7")" \
	"xff=203.0.113.7 real=203.0.113.7 proto=http host=echo.test port=80"

for p in proxy lbonly; do
	if [[ "$(docker logs "$RUN_ID-$p" 2>&1)" == *"nginx -t rejected"* ]]; then fail "nginx rejected the configuration of $p"; fi
done

# An invalid TRUSTED_PROXIES must stop the proxy instead of being ignored.
if docker run --rm --label "$RUN_ID" -e TRUSTED_PROXIES=0.0.0.0/0 -v /var/run/docker.sock:/tmp/docker.sock:ro "$IMAGE" >/dev/null 2>&1; then
	fail "TRUSTED_PROXIES=0.0.0.0/0 was accepted"
else
	ok "an invalid TRUSTED_PROXIES stops the proxy"
fi

echo "passed: $PASS, failed: $FAIL"
((FAIL == 0))
