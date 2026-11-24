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
- **Fast security updates.** Base-image and Go dependency updates are merged
  automatically once the full test suite passes. The image is also rebuilt
  daily on the latest base image layers.

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
| `VIRTUAL_HOST` | | Comma-separated host names. Wildcards (`*.example.com`) and regexes (`~^app\..*`) work. |
| `VIRTUAL_PORT` | single exposed port, else `80` | Port the container listens on. |
| `VIRTUAL_PROTO` | `http` | `http`, `https`, `grpc`, `grpcs`, `uwsgi` or `fastcgi`. |
| `VIRTUAL_PATH` | `/` | Route only this path (or nginx location regex) to the container. |
| `VIRTUAL_DEST` | | Rewrite `VIRTUAL_PATH` to this prefix before proxying. |
| `VIRTUAL_ROOT` | `/var/www/public` | Document root for `fastcgi`. |
| `HTTPS_METHOD` | proxy value | `redirect`, `noredirect`, `nohttp` or `nohttps`. |
| `HSTS` | proxy value | `Strict-Transport-Security` value, or `off`. |
| `SSL_POLICY` | proxy value | `Mozilla-Intermediate`, `Mozilla-Modern` or `Mozilla-Old`. |
| `CERT_NAME` | | Use `/etc/nginx/certs/<CERT_NAME>.crt` instead of the per-host lookup. |
| `NETWORK_ACCESS` | `external` | `internal` only allows clients from `network_internal.conf`. |
| `SERVER_TOKENS` | | `server_tokens` for this host. |
| `EXTERNAL_HTTPS_PORT` | `HTTPS_PORT` | Port used in HTTP to HTTPS redirects. |
| `ENABLE_HTTP_ON_MISSING_CERT` | proxy value | Serve HTTP when no certificate exists. |
| `ACME_HTTP_CHALLENGE_LOCATION` | proxy value | Answer ACME challenges for this host. |
| `LETSENCRYPT_HOST` | | Comma-separated host names to obtain certificates for. |
| `LETSENCRYPT_EMAIL` | `DEFAULT_EMAIL` | ACME account contact. |
| `LETSENCRYPT_TEST` | `false` | Use the Let's Encrypt staging CA. |
| label `com.github.nginx-proxy.nginx-proxy.keepalive` | `auto` | Upstream keepalive: `auto` (2 × servers), a number, or `disabled`. |
| label `com.github.nginx-proxy.nginx-proxy.loadbalance` | | Upstream directive, e.g. `least_conn;`. |
| label `com.github.nginx-proxy.nginx-proxy.http2.enable` | proxy value | HTTP/2 for this host. |
| label `com.github.nginx-proxy.nginx-proxy.non-get-redirect` | proxy value | `307` or `308` for non-GET HTTPS redirects. |
| label `com.github.nginx-proxy.nginx-proxy.trust-default-cert` | proxy value | Fall back to `default.crt`. |

Containers whose `VIRTUAL_*` values contain whitespace, `;`, `{`, `}`, quotes,
`#` or a backslash are ignored with a warning, so a container cannot inject
nginx directives. Backslashes are allowed in regex hosts and regex paths
(those starting with `~`), except as the last character.

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
| `TRUST_DOWNSTREAM_PROXY` | `true` | Forward client-supplied `X-Forwarded-*` headers. Set to `false` unless another proxy sits in front. |
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

For regex hosts, `<host>` is the SHA-1 of the regex. Changes to any of these
files are picked up within 30 seconds, and certificate renewals within
seconds.

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
ciphers. ECDHE is used otherwise.

## Releases and updates

Images are published to GitHub Container Registry for `linux/amd64` and
`linux/arm64`, with SBOM and provenance attestations.

| Tag | Updated |
|---|---|
| `latest` | every merge to `main`, and daily on the newest base image |
| `sha-<commit>` | every build |
| `<version>`, `<major>.<minor>` | on `v*` git tags |

Dependabot checks the nginx and Go base images and Go modules daily. Patch
and minor updates are merged automatically once the unit, end-to-end and
ACME tests pass, and a new image is published right away.

## Development

```bash
go test ./...                       # unit tests
docker build -t nginx-proxy:test .  # image
test/integration.sh                 # routing, TLS, events, rollback
test/acme.sh                        # ACME against Pebble
```

Code layout:

- `cmd/nginx-proxy`: wiring, event loop, signal handling
- `internal/docker`: minimal Docker Engine API client
- `internal/proxy`: containers to config model, plus the nginx template
- `internal/nginx`: nginx process, `nginx -t` with rollback, reload
- `internal/acme`: HTTP-01 certificate issuance and renewal

## License

MIT
