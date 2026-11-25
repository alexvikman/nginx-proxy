// Command nginx-proxy runs nginx and keeps its configuration in sync with the
// running Docker containers.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alexvikman/nginx-proxy/internal/acme"
	"github.com/alexvikman/nginx-proxy/internal/docker"
	"github.com/alexvikman/nginx-proxy/internal/nginx"
	"github.com/alexvikman/nginx-proxy/internal/proxy"
)

const (
	debounce       = 250 * time.Millisecond
	resyncInterval = 30 * time.Second

	// workerUser is the "user" of rootfs/etc/nginx/nginx.conf: the nginx
	// workers, which handle the traffic, run as this user.
	workerUser = "nginx"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("nginx-proxy stopped", "err", err)
		os.Exit(1)
	}
}

func environ() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	env := environ()
	settings, err := proxy.SettingsFromEnv(env)
	if err != nil {
		return err
	}
	if t := settings.TrustedProxies; !t.Empty() {
		slog.Info("forwarded headers are only believed from TRUSTED_PROXIES",
			"ranges", len(t.Ranges), "cloudflare", len(t.Cloudflare) > 0, "client_address_from", settings.RealIPHeader)
	}
	dockerHost := env["DOCKER_HOST"]
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}
	filters := docker.ParseFilters(env["DOCKER_CONTAINER_FILTERS"])
	if socket, ok := strings.CutPrefix(dockerHost, "unix://"); ok {
		if open, known := docker.SocketOpenTo(socket, workerUser); known && open {
			slog.Warn("the nginx workers can open the Docker socket, so a compromised worker would control the Docker host; "+
				"restrict the socket to root or put a filtering socket proxy in front", "socket", socket, "user", workerUser)
		}
	}

	cli, err := docker.New(dockerHost)
	if err != nil {
		return err
	}
	if err := waitForDocker(ctx, cli); err != nil {
		return err
	}
	selfID := docker.SelfID(ctx, cli)
	if selfID == "" {
		slog.Warn("could not determine nginx-proxy's own container; every container network will be considered reachable")
	}

	srv := &nginx.Server{Bin: "nginx", ConfPath: "/etc/nginx/conf.d/default.conf"}
	trigger := make(chan struct{}, 1)
	kick := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}

	var certs *acme.Manager
	if settings.ACMEEnabled {
		certs = &acme.Manager{
			CertDir:      proxy.CertDir,
			ChallengeDir: proxy.HTMLDir + "/.well-known/acme-challenge",
			OnChange:     kick,
			LocalHTTP:    "127.0.0.1:" + settings.HTTPPort,
		}
		go certs.Run(ctx)
	}

	rejected := &quarantine{}
	sync := func() {
		if err := reconcile(ctx, cli, srv, settings, selfID, filters, certs, rejected); err != nil {
			slog.Error("update failed", "err", err)
		}
	}

	// Render once before nginx starts, so it comes up with a real config.
	sync()
	if err := srv.Start(); err != nil {
		return err
	}
	slog.Info("nginx-proxy started", "version", settings.Version, "docker", dockerHost)

	go watchEvents(ctx, cli, kick)
	ticker := time.NewTicker(resyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return ignoreSignalExit(srv.Stop())
		case err := <-srv.Done():
			if err == nil {
				return errors.New("nginx exited unexpectedly")
			}
			return fmt.Errorf("nginx exited: %w", err)
		case <-ticker.C:
			sync()
		case <-trigger:
			// Collapse bursts of events (e.g. compose up) into one render.
			timer := time.NewTimer(debounce)
		drain:
			for {
				select {
				case <-trigger:
				case <-timer.C:
					break drain
				}
			}
			sync()
		}
	}
}

func reconcile(ctx context.Context, cli *docker.Client, srv *nginx.Server, s proxy.Settings, selfID string, filters map[string][]string, certs *acme.Manager, rejected *quarantine) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	containers, err := cli.RunningContainers(ctx, filters)
	if err != nil {
		return err
	}
	var self *docker.Container
	if selfID != "" {
		for _, c := range containers {
			if c.ID == selfID {
				self = c
			}
		}
		if self == nil {
			// Filters may exclude the proxy itself.
			if self, err = cli.Inspect(ctx, selfID); err != nil {
				return err
			}
		}
	}

	cfg, changed, err := apply(srv, proxy.Build(s, containers, self, proxy.OSFS{}), rejected)
	if err != nil {
		return err
	}
	if changed {
		slog.Info("nginx reloaded", "vhosts", len(cfg.VHosts), "upstreams", len(cfg.Upstreams))
	}
	if certs != nil {
		certs.Want(cfg.ACME)
	}
	return nil
}

// quarantine remembers which virtual hosts nginx rejected and for which
// configuration, so the search for them is not repeated on every resync.
type quarantine struct {
	key   string // identifies the full configuration that was rejected
	hosts []string
}

// apply hands the configuration to nginx and returns the configuration that
// is now live. When nginx rejects it because of some virtual hosts, those are
// left out so that every other host keeps being updated.
func apply(srv *nginx.Server, full *proxy.Config, q *quarantine) (*proxy.Config, bool, error) {
	conf, err := proxy.Render(full)
	if err != nil {
		return nil, false, fmt.Errorf("render: %w", err)
	}
	fp := fingerprint(srv, full)
	sum := sha256.Sum256(conf)
	key := hex.EncodeToString(sum[:]) + fp

	if key != q.key {
		changed, err := srv.Apply(conf, fp)
		var checkErr *nginx.CheckError
		if !errors.As(err, &checkErr) {
			if err == nil && len(q.hosts) > 0 {
				slog.Info("nginx accepts the full configuration again", "hosts", q.hosts)
			}
			*q = quarantine{}
			return full, changed, err
		}
		bad := proxy.Isolate(full, func(c *proxy.Config) error {
			candidate, err := proxy.Render(c)
			if err != nil {
				return err
			}
			return srv.Check(candidate)
		})
		if len(bad) == 0 {
			// Not caused by a virtual host: nothing to leave out.
			*q = quarantine{}
			return nil, false, err
		}
		slog.Error("nginx -t rejected the configuration, serving without the hosts that cause it", "hosts", bad, "err", checkErr.Output)
		*q = quarantine{key: key, hosts: bad}
	}

	cfg := full.Without(q.hosts)
	if conf, err = proxy.Render(cfg); err != nil {
		return nil, false, fmt.Errorf("render: %w", err)
	}
	changed, err := srv.Apply(conf, fingerprint(srv, cfg))
	if err != nil {
		*q = quarantine{}
		return nil, false, err
	}
	return cfg, changed, nil
}

// fingerprint covers every file nginx reads for cfg whose content is not
// part of the rendered configuration.
func fingerprint(srv *nginx.Server, cfg *proxy.Config) string {
	return nginx.Fingerprint(append(cfg.Files(), userConfFiles(srv.ConfPath)...))
}

// userConfFiles lists the configuration files nginx.conf includes next to
// the generated one. The model does not know them, but nginx has to be
// reloaded when one is added, edited or removed.
func userConfFiles(generated string) []string {
	var files []string
	for _, pattern := range []string{"/etc/nginx/conf.d/*.conf", "/etc/nginx/toplevel.conf.d/*.conf"} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if m != generated {
				files = append(files, m)
			}
		}
	}
	return files
}

func watchEvents(ctx context.Context, cli *docker.Client, kick func()) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := cli.Events(ctx, func(docker.Event) { kick() })
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		slog.Warn("docker events stream interrupted, reconnecting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
		kick() // we may have missed events while disconnected
	}
}

func waitForDocker(ctx context.Context, cli *docker.Client) error {
	for i := 0; ; i++ {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := cli.Ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if i == 0 {
			slog.Warn("waiting for docker daemon (is the socket mounted?)", "err", err)
		}
		if i >= 30 {
			return fmt.Errorf("docker daemon unreachable: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// ignoreSignalExit treats nginx exiting because we asked it to as success.
func ignoreSignalExit(err error) error {
	var exitErr interface{ ExitCode() int }
	if err == nil || (errors.As(err, &exitErr) && exitErr.ExitCode() <= 0) {
		return nil
	}
	return err
}
