# Base images are pinned by digest as well as by tag: a tag can be pushed
# again with different content, a digest cannot. Dependabot updates both, so
# every change to what the image is built from arrives as a pull request.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/nginx-proxy ./cmd/nginx-proxy

FROM docker.io/library/nginx:1.31.9-alpine@sha256:fb4658584bd9a916ffb6f6e365f97c25cfdb2923801f551ea08356e695f14ff7
ARG VERSION=dev
ENV NGINX_PROXY_VERSION=${VERSION} \
    DOCKER_HOST=unix:///tmp/docker.sock

RUN rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/certs /etc/nginx/vhost.d /etc/nginx/htpasswd \
       /etc/nginx/toplevel.conf.d /etc/nginx/dhparam \
       /usr/share/nginx/html/errors /usr/share/nginx/html/.well-known/acme-challenge

COPY rootfs/ /
COPY --from=build /out/nginx-proxy /usr/local/bin/nginx-proxy

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/nginx-proxy"]
