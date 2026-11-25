package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexvikman/nginx-proxy/internal/docker"
	"github.com/alexvikman/nginx-proxy/internal/proxy"
	"github.com/alexvikman/nginx-proxy/internal/socketproxy"
)

// runSocketProxy serves the Docker API requests nginx-proxy makes, filtered,
// so that the proxy container does not need the Docker socket. It runs in a
// container of its own that has the socket and no published port.
func runSocketProxy() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}
	listen := os.Getenv("SOCKET_PROXY_LISTEN")
	if listen == "" {
		listen = ":2375"
	}
	h, err := socketproxy.New(dockerHost, socketproxy.Options{
		EnvKeys:          proxy.ContainerEnv,
		LabelPrefix:      proxy.LabelPrefix,
		ContainerFilters: docker.ParseFilters(os.Getenv("DOCKER_CONTAINER_FILTERS")),
		Version:          os.Getenv("NGINX_PROXY_VERSION"),
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		// No WriteTimeout: the events stream stays open.
		IdleTimeout: 2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("socket proxy started", "version", os.Getenv("NGINX_PROXY_VERSION"), "listen", ln.Addr().String(), "docker", dockerHost,
		"container_filters", os.Getenv("DOCKER_CONTAINER_FILTERS"))
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// filterCheck logs an error when a socket proxy in front of the Docker API
// filters container variables differently from what this proxy reads, as
// happens when the two run different image versions.
type filterCheck struct {
	want    string // the FilterID of this binary
	version string
	last    string // the FilterID last seen, "" without a socket proxy
}

func newFilterCheck(version string) *filterCheck {
	return &filterCheck{want: socketproxy.FilterID(proxy.ContainerEnv, proxy.LabelPrefix), version: version}
}

func (f *filterCheck) run(ctx context.Context, cli *docker.Client) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	hdr, err := cli.Ping(ctx)
	if err != nil {
		return
	}
	got := hdr.Get(socketproxy.FilterHeader)
	if got == f.last {
		return
	}
	f.last = got
	switch got {
	case "":
		// Talking to Docker directly, or to another kind of proxy.
	case f.want:
		slog.Info("socket proxy filters what this proxy reads", "socket_proxy_version", hdr.Get(socketproxy.VersionHeader))
	default:
		slog.Error("the socket proxy runs another version and passes on different container variables, so some container settings may be missing; run both from the same image tag",
			"proxy_version", f.version, "socket_proxy_version", hdr.Get(socketproxy.VersionHeader))
	}
}
