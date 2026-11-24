#!/usr/bin/env bash
# End-to-end test of the built-in ACME client against Pebble, Let's Encrypt's
# test CA. Pebble validates HTTP-01 challenges against the proxy, which is
# reachable on the test network under the requested domain name.
#
# Usage: test/acme.sh [image]   (default: nginx-proxy:test)
set -euo pipefail

IMAGE="${1:-nginx-proxy:test}"
PEBBLE_IMAGE="ghcr.io/letsencrypt/pebble:latest"
RUN_ID="np-acme-$$"
NET="$RUN_ID"
WORK="$(mktemp -d)"
DOMAIN="secure.test"

cleanup() {
	local status=$?
	if ((status != 0)); then
		echo "--- proxy logs ---"
		docker logs "$RUN_ID-proxy" 2>&1 | grep -v '\[notice\]' | tail -n 40 || true
		echo "--- pebble logs ---"
		docker logs "$RUN_ID-pebble" 2>&1 | tail -n 20 || true
	fi
	docker ps -aq --filter "label=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	# The proxy runs as root: what it wrote under certs/ (the 0700 .acme
	# directory in particular) cannot be removed by an unprivileged user.
	docker run --rm -v "$WORK:/work" docker.io/library/busybox:stable rm -rf /work/certs >/dev/null 2>&1 || true
	# A failing command here would become the script's exit status.
	rm -rf "$WORK" || true
}
trap cleanup EXIT

docker network create "$NET" >/dev/null
mkdir -p "$WORK/certs"
# The proxy runs without CAP_DAC_OVERRIDE (see below), so root in the
# container can only write to a directory of another user if everyone can.
# A named volume, as in docker-compose.yml, belongs to root and needs nothing.
chmod 777 "$WORK/certs"
cat >"$WORK/pebble.json" <<'JSON'
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 80,
    "tlsPort": 443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
JSON

docker run -d --label "$RUN_ID" --name "$RUN_ID-pebble" --network "$NET" --network-alias pebble \
	-e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
	-v "$WORK/pebble.json:/test/config/pebble-config.json:ro" \
	"$PEBBLE_IMAGE" -config /test/config/pebble-config.json >/dev/null
docker cp "$RUN_ID-pebble:/test/certs/pebble.minica.pem" "$WORK/pebble-ca.pem" >/dev/null

# With the reduced privileges the README recommends, as in integration.sh.
docker run -d --label "$RUN_ID" --name "$RUN_ID-proxy" --network "$NET" --network-alias "$DOMAIN" \
	--cap-drop ALL --cap-add CHOWN --cap-add SETGID --cap-add SETUID --cap-add NET_BIND_SERVICE \
	--security-opt no-new-privileges \
	-v /var/run/docker.sock:/tmp/docker.sock:ro \
	-v "$WORK/certs:/etc/nginx/certs" \
	-v "$WORK/pebble-ca.pem:/etc/pebble-ca.pem:ro" \
	-e SSL_CERT_FILE=/etc/pebble-ca.pem \
	-e ACME_CA_URI=https://pebble:14000/dir \
	"$IMAGE" >/dev/null

docker run -d --label "$RUN_ID" --name "$RUN_ID-app" --network "$NET" \
	-e VIRTUAL_HOST="$DOMAIN" -e VIRTUAL_PORT=8080 -e LETSENCRYPT_HOST="$DOMAIN" \
	docker.io/library/busybox:stable \
	sh -c "mkdir /www && echo hello-acme > /www/index.html && exec httpd -f -p 8080 -h /www" >/dev/null

echo "waiting for certificate..."
for _ in $(seq 1 60); do
	[[ -s "$WORK/certs/$DOMAIN.crt" ]] && break
	sleep 1
done
[[ -s "$WORK/certs/$DOMAIN.crt" ]] || { echo "FAIL no certificate issued"; exit 1; }
echo "ok   certificate written"

# The new certificate must be picked up and HTTP must now redirect.
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$RUN_ID-proxy")"
docker run -d --label "$RUN_ID" --name "$RUN_ID-client" --network "$NET" --entrypoint sleep "$IMAGE" infinity >/dev/null
body=""
for _ in $(seq 1 40); do
	body="$(docker exec "$RUN_ID-client" curl -sS --max-time 2 -k --resolve "$DOMAIN:443:$PROXY_IP" "https://$DOMAIN/" 2>/dev/null || true)"
	[[ "$body" == "hello-acme" ]] && break
	sleep 0.25
done
[[ "$body" == "hello-acme" ]] || { echo "FAIL HTTPS did not serve the issued certificate (got '$body')"; exit 1; }
echo "ok   HTTPS serves the issued certificate"

issuer="$(docker exec "$RUN_ID-client" curl -sSkv -o /dev/null --resolve "$DOMAIN:443:$PROXY_IP" "https://$DOMAIN/" 2>&1 | grep -i 'issuer:' || true)"
[[ "$issuer" == *Pebble* ]] || { echo "FAIL unexpected issuer: $issuer"; exit 1; }
echo "ok   certificate issued by Pebble"

code="$(docker exec "$RUN_ID-client" curl -sS -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" "http://$PROXY_IP/")"
[[ "$code" == 301 ]] || { echo "FAIL HTTP should redirect once a certificate exists (got $code)"; exit 1; }
echo "ok   HTTP redirects to HTTPS"
echo "acme test passed"
