# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/nginx-proxy ./cmd/nginx-proxy

FROM docker.io/library/nginx:1.31.9-alpine
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
