package proxy

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/alexvikman/nginx-proxy/internal/docker"
)

type fakeFS map[string]bool

func (f fakeFS) Exists(p string) bool { return f[p] }

func ctr(name string, env map[string]string, labels map[string]string, nets map[string]string, exposed ...string) *docker.Container {
	c := &docker.Container{ID: name + "-id", Name: "/" + name}
	for k, v := range env {
		c.Config.Env = append(c.Config.Env, k+"="+v)
	}
	c.Config.Labels = labels
	c.Config.ExposedPorts = map[string]struct{}{}
	for _, p := range exposed {
		c.Config.ExposedPorts[p] = struct{}{}
	}
	c.State.Running = true
	c.NetworkSettings.Networks = map[string]docker.Endpoint{}
	for n, ip := range nets {
		c.NetworkSettings.Networks[n] = docker.Endpoint{IPAddress: ip}
	}
	return c
}

func defaults() Settings { return SettingsFromEnv(map[string]string{}) }

func render(t *testing.T, cfg *Config) string {
	t.Helper()
	out, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestPortSelection(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	cases := []struct {
		name string
		c    *docker.Container
		want string
	}{
		{"virtual port wins", ctr("a", map[string]string{"VIRTUAL_HOST": "a.test", "VIRTUAL_PORT": "9000"}, nil, map[string]string{"web": "172.20.0.3"}, "8080/tcp"), "172.20.0.3:9000"},
		{"single exposed port", ctr("b", map[string]string{"VIRTUAL_HOST": "b.test"}, nil, map[string]string{"web": "172.20.0.4"}, "8080/tcp"), "172.20.0.4:8080"},
		{"several exposed ports default to 80", ctr("c", map[string]string{"VIRTUAL_HOST": "c.test"}, nil, map[string]string{"web": "172.20.0.5"}, "8080/tcp", "9090/tcp"), "172.20.0.5:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Build(defaults(), []*docker.Container{self, tc.c}, self, fakeFS{})
			if got := cfg.Upstreams[0].Servers; len(got) != 1 || got[0] != tc.want {
				t.Fatalf("servers = %v, want [%s]", got, tc.want)
			}
		})
	}
}

func TestOnlySharedNetworksAreUsed(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"front": "172.20.0.2"})
	other := ctr("app", map[string]string{"VIRTUAL_HOST": "app.test"}, nil, map[string]string{"back": "172.30.0.3"})
	cfg := Build(defaults(), []*docker.Container{self, other}, self, fakeFS{})
	if len(cfg.Upstreams[0].Servers) != 0 {
		t.Fatalf("expected no reachable servers, got %v", cfg.Upstreams[0].Servers)
	}
	if !strings.Contains(render(t, cfg), "server 127.0.0.1 down;") {
		t.Fatal("empty upstream must contain a down placeholder")
	}
}

func TestLoadBalancingAndKeepalive(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	env := map[string]string{"VIRTUAL_HOST": "app.test"}
	a := ctr("app-1", env, map[string]string{labelPrefix + "loadbalance": "least_conn;"}, map[string]string{"web": "172.20.0.3"})
	b := ctr("app-2", env, nil, map[string]string{"web": "172.20.0.4"})
	cfg := Build(defaults(), []*docker.Container{b, a, self}, self, fakeFS{})
	up := cfg.Upstreams[0]
	if len(up.Servers) != 2 || up.Keepalive != "4" || up.LoadBalance != "least_conn;" {
		t.Fatalf("unexpected upstream %+v", up)
	}
}

func TestCertificateSelection(t *testing.T) {
	fs := fakeFS{
		CertDir + "/exact.test.crt": true, CertDir + "/exact.test.key": true,
		CertDir + "/parent.test.crt": true, CertDir + "/parent.test.key": true,
		CertDir + "/shared.crt": true, CertDir + "/shared.key": true,
		CertDir + "/nokey.test.crt": true,
	}
	cases := map[string]struct {
		host, certName, want string
	}{
		"exact":             {"exact.test", "", "exact.test"},
		"parent":            {"sub.parent.test", "", "parent.test"},
		"only one level up": {"a.sub.parent.test", "", ""},
		"CERT_NAME":         {"other.test", "shared", "shared"},
		"bad CERT_NAME":     {"exact.test", "missing", ""},
		"missing key":       {"nokey.test", "", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := selectCert(fs, tc.host, tc.certName); got != tc.want {
				t.Fatalf("selectCert(%q, %q) = %q, want %q", tc.host, tc.certName, got, tc.want)
			}
		})
	}
}

func TestHTTPSMethods(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	fs := fakeFS{CertDir + "/app.test.crt": true, CertDir + "/app.test.key": true}
	cases := []struct {
		method, cert                string
		http, https, redirect, hsts bool
	}{
		{"redirect", "app.test", true, true, true, true},
		{"noredirect", "app.test", true, true, false, false},
		{"nohttp", "app.test", false, true, false, true},
		{"nohttps", "app.test", true, false, false, true},
		// No certificate: HTTP is forced on, as upstream does.
		{"redirect", "", true, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.method+"/"+tc.cert, func(t *testing.T) {
			host := "app.test"
			if tc.cert == "" {
				host = "nocert.test"
			}
			c := ctr("app", map[string]string{"VIRTUAL_HOST": host, "HTTPS_METHOD": tc.method}, nil, map[string]string{"web": "172.20.0.3"})
			vh := Build(defaults(), []*docker.Container{self, c}, self, fs).VHosts[0]
			if vh.ServeHTTP != tc.http || vh.ServeHTTPS != tc.https || vh.Redirect != tc.redirect || (vh.HSTS != "") != tc.hsts {
				t.Fatalf("got http=%v https=%v redirect=%v hsts=%q", vh.ServeHTTP, vh.ServeHTTPS, vh.Redirect, vh.HSTS)
			}
		})
	}
}

func TestPathsAndDest(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	api := ctr("api", map[string]string{"VIRTUAL_HOST": "site.test", "VIRTUAL_PATH": "/api/", "VIRTUAL_DEST": "/"}, nil, map[string]string{"web": "172.20.0.3"})
	cfg := Build(defaults(), []*docker.Container{self, api}, self, fakeFS{})
	out := render(t, cfg)
	for _, want := range []string{
		"location /api/ {",
		"proxy_pass http://site.test-" + sha1hex("/api/") + "/;",
		"return 404;", // DEFAULT_ROOT for the missing "/" location
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config is missing %q", want)
		}
	}
}

func TestUnsafeValuesAreRejected(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	evil := ctr("evil", map[string]string{"VIRTUAL_HOST": "a.test; include /etc/passwd"}, nil, map[string]string{"web": "172.20.0.3"})
	evilPath := ctr("evil2", map[string]string{"VIRTUAL_HOST": "b.test", "VIRTUAL_PATH": "/ { return 200; }"}, nil, map[string]string{"web": "172.20.0.4"})
	cfg := Build(defaults(), []*docker.Container{self, evil, evilPath}, self, fakeFS{})
	if len(cfg.VHosts) != 0 {
		t.Fatalf("unsafe containers must be ignored, got %d vhosts", len(cfg.VHosts))
	}
}

func TestVhostIncludesAndAuth(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	c := ctr("app", map[string]string{"VIRTUAL_HOST": "*.wild.test"}, nil, map[string]string{"web": "172.20.0.3"})
	fs := fakeFS{
		VhostDir + "/*.wild.test":          true,
		VhostDir + "/*.wild.test_location": true,
		HtpasswdDir + "/*.wild.test":       true,
	}
	out := render(t, Build(defaults(), []*docker.Container{self, c}, self, fs))
	for _, want := range []string{
		`include /etc/nginx/vhost.d/\*.wild.test;`,
		`include /etc/nginx/vhost.d/\*.wild.test_location;`,
		`auth_basic_user_file /etc/nginx/htpasswd/*.wild.test;`,
		"upstream " + sha1hex("*.wild.test") + " {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config is missing %q", want)
		}
	}
}

func TestACMERequests(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	c := ctr("app", map[string]string{
		"VIRTUAL_HOST": "app.test", "LETSENCRYPT_HOST": "app.test, *.app.test", "LETSENCRYPT_EMAIL": "ops@app.test",
	}, nil, map[string]string{"web": "172.20.0.3"})
	cfg := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{})
	if len(cfg.ACME) != 1 || cfg.ACME[0].Domain != "app.test" || cfg.ACME[0].Email != "ops@app.test" || cfg.ACME[0].DirectoryURL != LetsEncryptProduction {
		t.Fatalf("unexpected ACME requests %+v", cfg.ACME)
	}
	// The HTTP server must answer challenges while there is no certificate yet.
	if out := render(t, cfg); !strings.Contains(out, "location ^~ /.well-known/acme-challenge/") {
		t.Fatal("missing ACME challenge location")
	}
}

func TestDefaultHost(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	c := ctr("app", map[string]string{"VIRTUAL_HOST": "app.test"}, nil, map[string]string{"web": "172.20.0.3"})
	s := defaults()
	s.DefaultHost = "app.test"
	out := render(t, Build(s, []*docker.Container{self, c}, self, fakeFS{}))
	if strings.Contains(out, "server_name _;\n    listen 80 default_server;") {
		t.Fatal("fallback HTTP server must not be generated when DEFAULT_HOST is served")
	}
	if !strings.Contains(out, "server_name app.test;\n    listen 80 default_server;") {
		t.Fatal("DEFAULT_HOST must be the default_server")
	}
}

func TestContainerValuesAreValidated(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	base := func(extra map[string]string, labels map[string]string) *docker.Container {
		env := map[string]string{"VIRTUAL_HOST": "app.test"}
		for k, v := range extra {
			env[k] = v
		}
		return ctr("app", env, labels, map[string]string{"web": "172.20.0.3"})
	}
	rejected := map[string]*docker.Container{
		"SERVER_TOKENS directive":    base(map[string]string{"SERVER_TOKENS": "off; include /etc/passwd"}, nil),
		"SERVER_TOKENS unknown":      base(map[string]string{"SERVER_TOKENS": "maybe"}, nil),
		"EXTERNAL_HTTPS_PORT text":   base(map[string]string{"EXTERNAL_HTTPS_PORT": "443$request_uri"}, nil),
		"VIRTUAL_PORT text":          base(map[string]string{"VIRTUAL_PORT": "80abc"}, nil),
		"VIRTUAL_ROOT directive":     base(map[string]string{"VIRTUAL_ROOT": "/www; autoindex on"}, nil),
		"SSL_POLICY unknown":         base(map[string]string{"SSL_POLICY": "AWS-2015-05"}, nil),
		"HSTS quote":                 base(map[string]string{"HSTS": `max-age=1"; return 200 "x`}, nil),
		"CERT_NAME traversal":        base(map[string]string{"CERT_NAME": "../../etc/ssl/private/key"}, nil),
		"VIRTUAL_PROTO unknown":      base(map[string]string{"VIRTUAL_PROTO": "gopher"}, nil),
		"VIRTUAL_PATH backslash":     base(map[string]string{"VIRTUAL_PATH": `/x\`}, nil),
		"regex VIRTUAL_PATH escape":  base(map[string]string{"VIRTUAL_PATH": `~^/x\`}, nil),
		"VIRTUAL_DEST backslash":     base(map[string]string{"VIRTUAL_DEST": `/\`}, nil),
		"VIRTUAL_ROOT backslash":     base(map[string]string{"VIRTUAL_ROOT": `/www\`}, nil),
		"loadbalance directive":      base(nil, map[string]string{labelPrefix + "loadbalance": "least_conn; } server { listen 81;"}),
		"non-get-redirect directive": base(nil, map[string]string{labelPrefix + "non-get-redirect": "307 https://evil.test"}),
	}
	for name, c := range rejected {
		t.Run(name, func(t *testing.T) {
			if cfg := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{}); len(cfg.VHosts) != 0 {
				t.Fatal("container should have been rejected")
			}
		})
	}

	accepted := base(map[string]string{
		"HSTS": "max-age=31536000; includeSubDomains; preload", "SERVER_TOKENS": "build",
		"SSL_POLICY": "Mozilla-Modern", "EXTERNAL_HTTPS_PORT": "8443", "CERT_NAME": "shared",
	}, map[string]string{labelPrefix + "loadbalance": "hash $remote_addr consistent;", labelPrefix + "non-get-redirect": "308"})
	if cfg := Build(defaults(), []*docker.Container{self, accepted}, self, fakeFS{}); len(cfg.VHosts) != 1 {
		t.Fatal("valid container was rejected")
	}
}

func TestACMEDomainsMustBePlainNames(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	c := ctr("app", map[string]string{
		"VIRTUAL_HOST": "app.test", "LETSENCRYPT_HOST": "../../etc/evil,app.test,bad_name.test,x/y.test",
	}, nil, map[string]string{"web": "172.20.0.3"})
	cfg := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{})
	if len(cfg.ACME) != 1 || cfg.ACME[0].Domain != "app.test" {
		t.Fatalf("only app.test should be requested, got %+v", cfg.ACME)
	}
}

func TestBackslashOnlyInRegexHosts(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	// A trailing backslash would escape the ";" after server_name.
	c := ctr("app", map[string]string{"VIRTUAL_HOST": `evil.test\,~^re\.test$,~^bad\`}, nil, map[string]string{"web": "172.20.0.3"})
	cfg := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{})
	if len(cfg.VHosts) != 1 || cfg.VHosts[0].Host != `~^re\.test$` {
		t.Fatalf("got %+v", cfg.VHosts)
	}
}

func TestVirtualPortIsNormalized(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	for _, port := range []string{" 8080", "8080 ", "+8080", "08080"} {
		c := ctr("app", map[string]string{"VIRTUAL_HOST": "app.test", "VIRTUAL_PORT": port}, nil, map[string]string{"web": "172.20.0.3"})
		cfg := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{})
		if got := cfg.Upstreams[0].Servers; len(got) != 1 || got[0] != "172.20.0.3:8080" {
			t.Errorf("VIRTUAL_PORT=%q: servers = %v, want [172.20.0.3:8080]", port, got)
		}
	}
}

func TestSharedNetworkNamespace(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	vpn := ctr("vpn", nil, nil, map[string]string{"web": "172.20.0.3"})
	cases := map[string]struct {
		mode string
		want []string
	}{
		"other container":   {"container:vpn-id", []string{"172.20.0.3:8080"}},
		"the proxy itself":  {"container:proxy-id", []string{"127.0.0.1:8080"}},
		"unknown container": {"container:gone-id", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Like the real thing, the container has no networks of its own.
			app := ctr("app", map[string]string{"VIRTUAL_HOST": "app.test", "VIRTUAL_PORT": "8080"}, nil, nil)
			app.HostConfig.NetworkMode = tc.mode
			cfg := Build(defaults(), []*docker.Container{self, vpn, app}, self, fakeFS{})
			if got := cfg.Upstreams[0].Servers; !slices.Equal(got, tc.want) {
				t.Fatalf("servers = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTrustDefaultCertLabel(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	fs := fakeFS{CertDir + "/default.crt": true, CertDir + "/default.key": true}
	label := func(v string) map[string]string { return map[string]string{labelPrefix + "trust-default-cert": v} }
	cases := map[string]struct {
		proxy  bool
		labels map[string]string
		want   string
	}{
		"proxy on":             {true, nil, "default"},
		"proxy on, label off":  {true, label("false"), ""},
		"proxy off":            {false, nil, ""},
		"proxy off, label on":  {false, label("true"), "default"},
		"proxy off, label off": {false, label("false"), ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := defaults()
			s.TrustDefaultCert = tc.proxy
			c := ctr("app", map[string]string{"VIRTUAL_HOST": "app.test"}, tc.labels, map[string]string{"web": "172.20.0.3"})
			cfg := Build(s, []*docker.Container{self, c}, self, fs)
			if got := cfg.VHosts[0].Cert; got != tc.want {
				t.Fatalf("cert = %q, want %q", got, tc.want)
			}
			// The fallback server for unknown hosts follows the proxy setting only.
			if cfg.DefaultCert != tc.proxy {
				t.Fatalf("DefaultCert = %v, want %v", cfg.DefaultCert, tc.proxy)
			}
		})
	}
}

func TestInternalAllowListIsTracked(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	for access, want := range map[string]bool{"internal": true, "": false} {
		c := ctr("app", map[string]string{"VIRTUAL_HOST": "app.test", "NETWORK_ACCESS": access}, nil, map[string]string{"web": "172.20.0.3"})
		files := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{}).Files()
		if got := slices.Contains(files, NetworkInternalConf); got != want {
			t.Errorf("NETWORK_ACCESS=%q: tracked = %v, want %v", access, got, want)
		}
	}
}

func TestIsolate(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	containers := []*docker.Container{self}
	for _, h := range []string{"a.test", "bad1.test", "c.test", "d.test", "bad2.test", "f.test", "g.test"} {
		containers = append(containers, ctr(h, map[string]string{"VIRTUAL_HOST": h, "VIRTUAL_PATH": "/api/"}, nil, map[string]string{"web": "172.20.0.3"}))
	}
	s := defaults()
	s.DefaultHost = "bad1.test"
	cfg := Build(s, containers, self, fakeFS{})

	checks := 0
	check := func(c *Config) error {
		checks++
		if len(c.Upstreams) != len(c.VHosts) {
			t.Fatalf("%d upstreams for %d vhosts", len(c.Upstreams), len(c.VHosts))
		}
		for _, vh := range c.VHosts {
			if strings.HasPrefix(vh.Host, "bad") {
				return errors.New("rejected")
			}
		}
		return nil
	}
	bad := Isolate(cfg, check)
	slices.Sort(bad)
	if !slices.Equal(bad, []string{"bad1.test", "bad2.test"}) {
		t.Fatalf("isolated %v", bad)
	}
	if checks > 12 {
		t.Errorf("%d checks for 7 hosts, expected a bisection", checks)
	}

	if !cfg.DefaultHTTPSet {
		t.Fatal("test setup: DEFAULT_HOST should be served")
	}
	reduced := cfg.Without(bad)
	if len(reduced.VHosts) != 5 || check(reduced) != nil {
		t.Fatalf("reduced config still has %d vhosts", len(reduced.VHosts))
	}
	if reduced.DefaultHTTPSet || reduced.DefaultTLSSet {
		t.Fatal("fallback servers must return when the DEFAULT_HOST is left out")
	}
	if len(cfg.VHosts) != 7 {
		t.Fatal("Without must not modify the original config")
	}

	// Rejected even without any host: the cause is elsewhere.
	if got := Isolate(cfg, func(*Config) error { return errors.New("rejected") }); got != nil {
		t.Fatalf("isolated %v from a config that fails without hosts", got)
	}
}

func TestWarningsAreNotRepeated(t *testing.T) {
	var logged []string
	d := &dedupe{log: func(msg string, _ ...any) { logged = append(logged, msg) }}
	round := func(msgs ...string) {
		for _, m := range msgs {
			d.warn(m, "container", "app")
		}
		d.rotate()
	}
	round("a", "a") // logs a once
	round("a")      // still there: quiet
	round("a", "b") // logs b
	round()         // both gone
	round("a")      // back again: logs a
	if want := []string{"a", "b", "a"}; !slices.Equal(logged, want) {
		t.Fatalf("logged %v, want %v", logged, want)
	}
}

func TestHostsWithSlashesAreIgnored(t *testing.T) {
	self := ctr("proxy", nil, nil, map[string]string{"web": "172.20.0.2"})
	c := ctr("app", map[string]string{"VIRTUAL_HOST": "../../etc/passwd,ok.test"}, nil, map[string]string{"web": "172.20.0.3"})
	cfg := Build(defaults(), []*docker.Container{self, c}, self, fakeFS{})
	if len(cfg.VHosts) != 1 || cfg.VHosts[0].Host != "ok.test" {
		t.Fatalf("got %+v", cfg.VHosts)
	}
}
