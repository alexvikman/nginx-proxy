# nginx-proxy

An automated nginx reverse proxy for Docker. Start a container with
`VIRTUAL_HOST=app.example.com` and it is routed. Add
`LETSENCRYPT_HOST=app.example.com` and it gets a TLS certificate.

The configuration format is compatible with
[nginx-proxy/nginx-proxy](https://github.com/nginx-proxy/nginx-proxy), so
existing setups move over by switching the image. The implementation is new:

- **One Go binary** watches the Docker API and renders the nginx config.
  There is no docker-gen, no forego and no third-party image in the
  runtime path, only the official `nginx` image.
- **Built-in ACME (Let's Encrypt).** No acme-companion container is needed.
- **Bad config never goes live.** Every change is checked with `nginx -t`
  before reload. If the check fails, the running configuration stays and the
  error is logged. When a single host is the cause, only that host is left
  out and all others keep being updated.
- **Reviewed and signed releases.** Base images are pinned by digest. Every
  update to them or to a Go dependency arrives as a pull request that runs
  the full test suite and is merged by a maintainer. Every published image
  is signed.

```
ghcr.io/alexvikman/nginx-proxy:latest
```

## Quick start

```yaml
services:
  proxy:
    image: ghcr.io/alexvikman/nginx-proxy:latest
    ports:
      - "80:80"
      - "443:443"
    environment:
      DEFAULT_EMAIL: ops@example.com
      TRUST_DOWNSTREAM_PROXY: "false" # no other proxy in front of this one
      # Behind Cloudflare or a load balancer, use this instead:
      # TRUSTED_PROXIES: cloudflare
    volumes:
      - /var/run/docker.sock:/tmp/docker.sock:ro
      - certs:/etc/nginx/certs
    restart: unless-stopped

  whoami:
    image: traefik/whoami
    environment:
      VIRTUAL_HOST: whoami.example.com
      LETSENCRYPT_HOST: whoami.example.com

volumes:
  certs:
```

The proxy can only reach containers that share a Docker network with it. In
the example above, Compose puts both services on the same default network.

[`docker-compose.yml`](docker-compose.yml) is the same setup with reduced
container privileges. See [Security](#security) before exposing the proxy.

## Moving from nginx-proxy/nginx-proxy

1. Replace the image with `ghcr.io/alexvikman/nginx-proxy:latest`.
2. Keep your volumes. `/etc/nginx/certs`, `vhost.d`, `htpasswd`, `conf.d` and
   `toplevel.conf.d` are read from the same paths.
3. If you use **acme-companion**, either:
   - remove it and let the built-in ACME client take over. Existing
     certificates in `/etc/nginx/certs` are used until they need renewal.
   - or keep it and set `ENABLE_ACME=false` on the proxy.

The differences and missing features are listed under
[Not supported yet](#not-supported-yet).

## Configuration

### Proxied containers

| Variable / label | Default | Description |
|---|---|---|
| `VIRTUAL_HOST` | | Comma-separated host names. Wildcards (`*.example.com`) and regexes (`~^app\..*`) work. Named captures do not. |
| `VIRTUAL_PORT` | single exposed port, else `80` | Port the container listens on. |
| `VIRTUAL_PROTO` | `http` | `http`, `https`, `grpc`, `grpcs`, `uwsgi` or `fastcgi`. |
| `VIRTUAL_PATH` | `/` | Route only this path (or nginx location regex) to the container. |
| `VIRTUAL_DEST` | | Rewrite `VIRTUAL_PATH` to this path prefix (starting with `/`) before proxying. |
| `VIRTUAL_ROOT` | `/var/www/public` | Document root for `fastcgi`. |
| `HTTPS_METHOD` | proxy value | `redirect`, `noredirect`, `nohttp` or `nohttps`. |
| `HSTS` | proxy value | `Strict-Transport-Security` value, or `off`. |
| `SSL_POLICY` | proxy value | `Mozilla-Intermediate`, `Mozilla-Modern` or `Mozilla-Old`. |
| `CERT_NAME` | | Use `/etc/nginx/certs/<CERT_NAME>.crt` instead of the per-host lookup. |
| `NETWORK_ACCESS` | `external` | `internal` only allows clients from `network_internal.conf`. Any other value than `external` is treated as `internal`. |
| `SERVER_TOKENS` | | `server_tokens` for this host. |
| `EXTERNAL_HTTPS_PORT` | `HTTPS_PORT` | Port used in HTTP to HTTPS redirects. |
| `ENABLE_HTTP_ON_MISSING_CERT` | proxy value | Serve HTTP when no certificate exists. |
| `ACME_HTTP_CHALLENGE_LOCATION` | proxy value | Answer ACME challenges for this host. |
| `LETSENCRYPT_HOST` | | Comma-separated host names to obtain certificates for. Each must also be in the container's `VIRTUAL_HOST`. |
| `LETSENCRYPT_EMAIL` | `DEFAULT_EMAIL` | ACME account contact. |
| `LETSENCRYPT_TEST` | `false` | Use the Let's Encrypt staging CA. When containers sharing a host disagree, `ACME_CA_URI` wins. |
| label `com.github.nginx-proxy.nginx-proxy.keepalive` | `auto` | Upstream keepalive: `auto` (2 × servers), a number, or `disabled`. |
| label `com.github.nginx-proxy.nginx-proxy.loadbalance` | | Upstream directive, e.g. `least_conn;`. |
| label `com.github.nginx-proxy.nginx-proxy.http2.enable` | proxy value | HTTP/2 for this host. |
| label `com.github.nginx-proxy.nginx-proxy.non-get-redirect` | proxy value | `307` or `308` for non-GET HTTPS redirects. |
| label `com.github.nginx-proxy.nginx-proxy.trust-default-cert` | proxy value | Fall back to `default.crt`. |

Containers are not trusted to write nginx configuration. A value that could
change its structure is refused with a warning: an unsafe `VIRTUAL_HOST`
entry is skipped, and any other unsafe value makes the proxy ignore the
container.

- Plain and wildcard host names consist of letters, digits, `.`, `-`, `_`
  and `*`. Write internationalized names in Punycode.
- Regex hosts and regex paths (those starting with `~`) must not contain
  whitespace, `;`, `{`, `}`, quotes or `#`, and must not end in a backslash.
  Named captures (`(?<name>...)`) are refused, because a named capture
  defines an nginx variable for every host, replacing any other variable of
  that name.
- Other `VIRTUAL_*` values must not contain whitespace, `;`, `{`, `}`,
  quotes, `#` or a backslash. `VIRTUAL_DEST` and `VIRTUAL_ROOT` must be
  absolute paths without `$`.

Host names that look like generated upstream names (40 hex digits, optionally
after a `-`) are ignored, and host names that differ only in case are one
host.

Every container that can set `VIRTUAL_HOST` is trusted to serve that host,
just as with nginx-proxy/nginx-proxy: two containers with the same host are
load balanced. Use `DOCKER_CONTAINER_FILTERS` to limit which containers the
proxy considers when not everyone who starts containers is trusted.

A container that uses another container's network namespace
(`network_mode: service:<name>` or `container:<name>`) is reached through
that container, which must be visible to the proxy.

### Proxy container

| Variable | Default | Description |
|---|---|---|
| `DOCKER_HOST` | `unix:///tmp/docker.sock` | Docker API endpoint (`unix://` or plain `tcp://`). |
| `DOCKER_CONTAINER_FILTERS` | | Comma-separated `key=value` Docker list filters. |
| `DEFAULT_HOST` | | Host served for unknown host names. |
| `DEFAULT_ROOT` | `404` | `return` value when no container serves `/`, or `none`. |
| `HTTPS_METHOD` | `redirect` | Default for all hosts. |
| `HSTS` | `max-age=31536000` | Default for all hosts. |
| `SSL_POLICY` | `Mozilla-Intermediate` | Default for all hosts. |
| `HTTP_PORT` / `HTTPS_PORT` | `80` / `443` | Ports nginx listens on inside the container. |
| `ENABLE_HTTP2` | `true` | |
| `ENABLE_IPV6` | `false` | Also listen on `[::]`. |
| `PREFER_IPV6_NETWORK` | `false` | Reach containers over IPv6 when they have an address. |
| `TRUSTED_PROXIES` | | Addresses and CIDR ranges of the proxies in front, separated by commas, and `cloudflare` for [Cloudflare's ranges](https://www.cloudflare.com/ips/). Only requests from these get their client address and `X-Forwarded-*` headers believed; from Cloudflare, only the client address and scheme. Replaces `TRUST_DOWNSTREAM_PROXY`. See [Behind a CDN or load balancer](#behind-a-cdn-or-load-balancer). |
| `REAL_IP_HEADER` | `CF-Connecting-IP` with `cloudflare` in `TRUSTED_PROXIES`, else `X-Forwarded-For` | Header the trusted proxies put the client address in. |
| `TRUST_DOWNSTREAM_PROXY` | `true` | Forward client-supplied `X-Forwarded-*` headers. Set to `false` unless another proxy sits in front: the headers, `X-Forwarded-For` included, are then set from the connection alone. Ignored when `TRUSTED_PROXIES` is set. |
| `TRUST_DEFAULT_CERT` | `true` | Use `default.crt` for hosts without their own certificate. |
| `ENABLE_HTTP_ON_MISSING_CERT` | `true` | |
| `NON_GET_REDIRECT` | `301` | |
| `RESOLVERS` | | nginx `resolver` value. |
| `LOG_FORMAT` / `LOG_FORMAT_ESCAPE` / `LOG_JSON` | | Access log format. |
| `DISABLE_ACCESS_LOGS` | `false` | |
| `SHA1_UPSTREAM_NAME` | `false` | Hash upstream names. |
| `ACME_HTTP_CHALLENGE_LOCATION` | `true` | Answer `/.well-known/acme-challenge/`. |
| `ACME_HTTP_CHALLENGE_ACCEPT_UNKNOWN_HOST` | `false` | Also answer challenges for unknown hosts. |
| `ENABLE_ACME` | `true` | Built-in ACME client. |
| `ACME_CA_URI` | Let's Encrypt production | ACME directory URL. |
| `DEFAULT_EMAIL` | | ACME account contact. |

### Behind a CDN or load balancer

When Cloudflare, a load balancer or another proxy sits in front, list it in
`TRUSTED_PROXIES` instead of setting `TRUST_DOWNSTREAM_PROXY=true`:

```yaml
    environment:
      TRUSTED_PROXIES: cloudflare            # or e.g. 10.0.0.0/8,192.0.2.10
```

For a request from a proxy **listed by address or range** (your own load
balancer), the proxy:

- takes the client address from `X-Forwarded-For` (or `REAL_IP_HEADER`),
  skipping trusted addresses from the right, so addresses a client put in
  front are ignored. It becomes `$remote_addr`, so the access log,
  `NETWORK_ACCESS=internal` and the `X-Real-IP` and `X-Forwarded-For` headers
  sent to your application all show the real client;
- passes on `X-Forwarded-Proto` (`http` or `https` only), `-Host` and `-Port`.

**`cloudflare`** trusts less, because Cloudflare's addresses are shared by
every Cloudflare customer: anyone can add a zone of their own that points at
your server's address and send requests from Cloudflare with headers of
their choosing. From these addresses the proxy only believes what Cloudflare
sets itself: the client address in `CF-Connecting-IP` (the default
`REAL_IP_HEADER` when `cloudflare` is listed) and `X-Forwarded-Proto`.
`X-Forwarded-Host` and `-Port` come from the request itself.

Any other request, such as one sent straight to your server's address to get
around Cloudflare, gets its own address and this server's scheme, host and
port, whatever headers it sends. Your application receives a single address
in `X-Forwarded-For`: the client's, not the chain of proxies.

To accept traffic only from your own Cloudflare zone, not from Cloudflare in
general, use [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
or turn on [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
with a certificate for your zone and require it in `vhost.d/<host>`:

```nginx
ssl_client_certificate /etc/nginx/certs/cloudflare-origin-pull.pem;
ssl_verify_client on;
```

Use the SSL/TLS mode *Full (strict)*. In *Flexible* mode Cloudflare connects
over plain HTTP, the proxy redirects it to HTTPS, and browsers end up in a
redirect loop. The built-in Cloudflare ranges are updated in this repository
when Cloudflare announces a change.

### Files

| Path | Purpose |
|---|---|
| `/etc/nginx/certs/<host>.crt`, `.key` | Certificate for a host. The parent domain's certificate is used for one subdomain level. `default.crt` is the fallback. |
| `/etc/nginx/certs/<host>.chain.pem`, `<host>.dhparam.pem`, `dhparam.pem` | Optional TLS extras. |
| `/etc/nginx/vhost.d/<host>` or `default` | Included in the host's `server` block. |
| `/etc/nginx/vhost.d/<host>[_<sha1(path)>]_location` or `default_location` | Included in the `location` block. |
| `/etc/nginx/vhost.d/<host>[_<sha1(path)>]_location_override` | Replaces the generated `location` block. |
| `/etc/nginx/htpasswd/<host>[_<sha1(path)>]` | Basic authentication. |
| `/etc/nginx/proxy.conf` | Replaces the default `proxy_set_header` settings. |
| `/etc/nginx/conf.d/*.conf` | Extra `http` configuration. `default.conf` is generated. |
| `/etc/nginx/toplevel.conf.d/*.conf` | Extra top-level configuration, e.g. `stream {}`. |
| `/etc/nginx/network_internal.conf` | Allow list for `NETWORK_ACCESS=internal`. |
| `/usr/share/nginx/html/errors/50x.html` | Custom error page. |

For regex hosts, `<host>` is the SHA-1 of the regex. Other hosts are looked
up as the container wrote them and then in lower case, so the files for
`app.example.com` also apply to a container that announces
`App.Example.com`. Changes to any of these files are picked up within 30
seconds, and certificate renewals within seconds.

## TLS and ACME

When a container sets `LETSENCRYPT_HOST`, the proxy:

1. serves the host over HTTP with `/.well-known/acme-challenge/` answered
   from `/usr/share/nginx/html`;
2. checks that it can fetch its own challenge through nginx before asking
   the CA to validate, so a misconfigured host does not burn the CA's
   failed-validation rate limit;
3. writes `<host>.crt` (full chain), `<host>.key` and `<host>.chain.pem` to
   `/etc/nginx/certs` and reloads nginx. HTTP then redirects to HTTPS;
4. renews 30 days before expiry. Failures back off from 10 minutes up to 24
   hours.

Certificates use ECDSA P-256 keys. Mount `/etc/nginx/certs` on a volume so
certificates and the ACME account key survive container restarts. Wildcard
certificates need DNS-01, which is not supported. Provide them as files
instead.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

**Trust.** The proxy's environment and the files mounted into it are trusted.
A container the proxy sees is trusted to serve the hosts it announces, and to
get certificates for them, but not to write nginx configuration. If not
everyone who can start containers should be able to claim a host name, limit
what the proxy considers with `DOCKER_CONTAINER_FILTERS`.

**Docker socket.** The proxy only reads from the Docker API: `GET /_ping`,
`/containers/json`, `/containers/<id>/json` and `/events`. Mounting the socket
with `:ro` does not limit the API, and access to it amounts to root on the
host. The proxy process and the nginx master run as root. The nginx workers,
which handle the traffic, run as the `nginx` user and must not be able to
open the socket: the proxy logs a warning at startup when they can, which is
the case for a world-writable socket or a socket group with the id of the
image's `nginx` group. To limit what a compromised proxy could do, put a
filtering socket proxy in front that only allows those four requests, and
point `DOCKER_HOST` (`tcp://host:port`) at it over a network that only the
two share: the connection is not encrypted.

**Container privileges.** The proxy needs four capabilities: to bind ports
80 and 443, and to start the nginx workers as an unprivileged user.

```yaml
    cap_drop: [ALL]
    cap_add: [CHOWN, SETGID, SETUID, NET_BIND_SERVICE]
    security_opt: ["no-new-privileges:true"]
```

The end-to-end tests run the proxy this way. Without `DAC_OVERRIDE`, root in
the container can only write certificates to a directory it owns. That is the
case for a named volume. A bind-mounted directory of another user needs a
`chown` to root, or `DAC_OVERRIDE` added.

**Forwarded headers.** With the default `TRUST_DOWNSTREAM_PROXY=true`, the
`X-Forwarded-Proto`, `-Host`, `-Port` and `-For` values any client sends
reach your application, which may use them for redirects, links or the
client address. With a CDN or load balancer in front, set `TRUSTED_PROXIES`
instead, so only it is believed (see
[Behind a CDN or load balancer](#behind-a-cdn-or-load-balancer)). Without
one, set `TRUST_DOWNSTREAM_PROXY=false`.

**`NETWORK_ACCESS=internal`** compares the address nginx sees with
`network_internal.conf`. Where Docker does not preserve the client address
(Docker Desktop, rootless Docker, a load balancer in front), every client
arrives from a private address and is let in. Check the access log for real
client addresses before relying on it.

## Not supported yet

- `VIRTUAL_HOST_MULTIPORTS` (a warning is logged and `VIRTUAL_HOST` is used)
- mTLS client certificates (`ca.crt`, `crl.pem`, `ssl_verify_client`)
- HTTP/3, OCSP stapling, PROXY protocol, the debug endpoint
- AWS `SSL_POLICY` presets (anything other than the Mozilla policies falls
  back to `Mozilla-Intermediate`)
- the separate-containers (docker-gen) mode
- Docker API over TLS (`DOCKER_TLS_VERIFY`)

Differences from upstream: `server_tokens` defaults to `off`, and no DH
parameters are generated at startup. Provide `dhparam.pem` if you need DHE
ciphers. ECDHE is used otherwise. Container values are validated more
strictly (see [Proxied containers](#proxied-containers)), an unknown
`NETWORK_ACCESS` value restricts instead of being ignored, and
`TRUST_DOWNSTREAM_PROXY=false` also replaces `X-Forwarded-For`.

## Releases and updates

Images are published to GitHub Container Registry for `linux/amd64` and
`linux/arm64`, with SBOM and provenance attestations, and signed with
[cosign](https://github.com/sigstore/cosign).

| Tag | Updated |
|---|---|
| `latest` | every merge to `main` |
| `sha-<commit>` | every build |
| `<version>`, `<major>.<minor>` | on `v*` git tags |

Dependabot checks the nginx and Go base images and Go modules daily and
opens a pull request for each update. The unit, end-to-end and ACME tests run
on it, and a maintainer reviews and merges it: nothing is merged
automatically. A merge publishes a new image right away.

The nginx and Go base images are pinned by digest in the `Dockerfile`, so
an image tag that is published again with new content, for instance with
patched Alpine packages, also arrives as a pull request. There is no
scheduled rebuild: what an image contains was reviewed.

To check that an image was built by this repository's release workflow:

```bash
cosign verify ghcr.io/alexvikman/nginx-proxy:latest \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/alexvikman/nginx-proxy/\.github/workflows/release\.yml@refs/(heads/main|tags/v.+)$'
```

## Development

```bash
go test ./...                       # unit tests
docker build -t nginx-proxy:test .  # image
test/integration.sh                 # routing, TLS, events, rollback
test/acme.sh                        # ACME against Pebble
test/trusted-proxies.sh             # forwarded headers from TRUSTED_PROXIES
```

Code layout:

- `cmd/nginx-proxy`: wiring, event loop, signal handling
- `internal/docker`: minimal Docker Engine API client
- `internal/proxy`: containers to config model, plus the nginx template
- `internal/nginx`: nginx process, `nginx -t` with rollback, reload
- `internal/acme`: HTTP-01 certificate issuance and renewal

## License

MIT
