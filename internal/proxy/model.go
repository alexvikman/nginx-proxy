package proxy

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/alexvikman/nginx-proxy/internal/docker"
)

// Paths used inside the container. They match upstream nginx-proxy so that
// existing volume mounts keep working.
const (
	CertDir     = "/etc/nginx/certs"
	VhostDir    = "/etc/nginx/vhost.d"
	HtpasswdDir = "/etc/nginx/htpasswd"
	HTMLDir     = "/usr/share/nginx/html"

	// NetworkInternalConf is the allow list included for NETWORK_ACCESS=internal.
	NetworkInternalConf = "/etc/nginx/network_internal.conf"
)

// FS answers whether optional config files exist. It is an interface so the
// model can be tested without touching the real filesystem.
type FS interface {
	Exists(path string) bool
}

// OSFS checks the real filesystem.
type OSFS struct{}

// Exists reports whether path exists.
func (OSFS) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Config is everything the nginx template needs.
type Config struct {
	Settings
	Upstreams      []*Upstream
	VHosts         []*VHost
	DefaultCert    bool   // default.crt and default.key exist and TRUST_DEFAULT_CERT is on
	ProxyConf      bool   // /etc/nginx/proxy.conf replaces the default proxy settings
	DHParam        string // path to a dhparam file, if any
	ErrorPage      bool   // custom 50x page exists
	DefaultHTTPSet bool   // a vhost is the default_server on the HTTP port
	DefaultTLSSet  bool   // a vhost is the default_server on the HTTPS port

	// ACME lists the certificates the built-in ACME client should obtain.
	ACME []ACMERequest
}

// ACMERequest is one domain that should get a certificate.
type ACMERequest struct {
	Domain       string
	Email        string
	DirectoryURL string
}

// Upstream is an nginx upstream{} block.
type Upstream struct {
	Name        string
	VHost       string // host of the VHost this upstream belongs to
	Servers     []string
	Keepalive   string // "disabled" or a number
	LoadBalance string
}

// VHost is one server_name with its locations.
type VHost struct {
	Host              string
	FileKey           string // host, or sha1 of the host for regex hosts
	IsRegex           bool
	Default           bool
	ServeHTTP         bool
	ServeHTTPS        bool
	Redirect          bool
	HSTS              string // "" when disabled
	SSLPolicy         string
	HTTP2             bool
	Cert              string // certificate base name in CertDir, "" when HTTPS has no usable cert
	ChainFile         bool
	DHParam           string
	ServerTokens      string
	NonGetRedirect    string
	ExternalHTTPSPort string
	ACMEChallenge     bool
	Include           string // server-level include file, "" when none
	Locations         []*Location
	DefaultRoot       string // return value for "location /" when no container serves "/"
}

// Location is one location{} block inside a vhost.
type Location struct {
	Path      string
	Override  string // include file that replaces the whole block
	Proto     string
	Upstream  string
	Dest      string
	Root      string
	Internal  bool
	Keepalive bool
	AuthFile  string
	AuthRealm string
	Include   string
}

type backend struct {
	ctr  *docker.Container
	env  map[string]string
	addr string // ip:port, "" when unreachable
}

// Build creates the nginx model from the running containers. self is the
// proxy's own container, or nil when it is unknown.
func Build(s Settings, containers []*docker.Container, self *docker.Container, fs FS) *Config {
	defer warnings.rotate()
	cfg := &Config{Settings: s}
	cfg.ProxyConf = fs.Exists("/etc/nginx/proxy.conf")
	cfg.ErrorPage = fs.Exists(HTMLDir + "/errors/50x.html")
	// Whether the default certificate is used is decided per host: a
	// container label can turn it on or off regardless of the proxy setting.
	defaultCertOK := certUsable(fs, "default")
	cfg.DefaultCert = s.TrustDefaultCert && defaultCertOK
	for _, p := range []string{"/etc/nginx/dhparam/dhparam.pem", CertDir + "/dhparam.pem"} {
		if fs.Exists(p) {
			cfg.DHParam = p
			break
		}
	}

	containers = slices.Clone(containers)
	slices.SortFunc(containers, func(a, b *docker.Container) int { return strings.Compare(a.Name, b.Name) })

	selfNets := map[string]bool{}
	selfHost := false
	if self != nil {
		selfHost = self.HostConfig.NetworkMode == "host"
		for name := range self.NetworkSettings.Networks {
			selfNets[name] = true
		}
	}

	// host -> path -> backends, keeping first-seen order for determinism.
	type pathGroup struct {
		path     string
		backends []backend
	}
	type hostGroup struct {
		host  string
		paths []*pathGroup
	}
	var hosts []*hostGroup
	byHost := map[string]*hostGroup{}
	acmeIdx := map[string]int{} // hostKey -> index in cfg.ACME

	for _, ctr := range containers {
		if self != nil && ctr.ID == self.ID {
			continue
		}
		env := ctr.Env()
		if len(splitList(env["VIRTUAL_HOST"])) == 0 {
			continue
		}
		if err := validateContainer(env, ctr.Config.Labels); err != nil {
			warn("ignoring container with unsafe configuration", "container", ctr.ShortName(), "err", err)
			continue
		}
		vhosts := slices.DeleteFunc(splitList(env["VIRTUAL_HOST"]), func(h string) bool {
			if !safeMatcher(h) || strings.Contains(h, "/") {
				warn("ignoring unsafe VIRTUAL_HOST entry", "container", ctr.ShortName(), "host", h)
				return true
			}
			if reservedHost(h) {
				warn("ignoring VIRTUAL_HOST entry that looks like a generated upstream name", "container", ctr.ShortName(), "host", h)
				return true
			}
			return false
		})
		if len(vhosts) == 0 {
			continue
		}
		if env["VIRTUAL_HOST_MULTIPORTS"] != "" {
			warn("VIRTUAL_HOST_MULTIPORTS is not supported yet, using VIRTUAL_HOST", "container", ctr.ShortName())
		}
		b := backend{ctr: ctr, env: env, addr: address(ctr, env, containers, self, selfNets, selfHost, s.PreferIPv6Network)}
		if b.addr == "" {
			warn("container shares no network with nginx-proxy, skipping", "container", ctr.ShortName())
		}
		path := env["VIRTUAL_PATH"]
		if path == "" {
			path = "/"
		}
		for _, h := range vhosts {
			// nginx compares server and upstream names without regard to
			// case, so A.test and a.test are one host. The first spelling
			// seen names it, which keeps vhost.d and cert file names working.
			key := hostKey(h)
			hg := byHost[key]
			if hg == nil {
				hg = &hostGroup{host: h}
				byHost[key] = hg
				hosts = append(hosts, hg)
			}
			var pg *pathGroup
			for _, p := range hg.paths {
				if p.path == path {
					pg = p
				}
			}
			if pg == nil {
				pg = &pathGroup{path: path}
				hg.paths = append(hg.paths, pg)
			}
			pg.backends = append(pg.backends, b)
		}

		if s.ACMEEnabled {
			dir := s.ACMECAURI
			if parseBool(env, "LETSENCRYPT_TEST", false) {
				dir = LetsEncryptStaging
			}
			email := env["LETSENCRYPT_EMAIL"]
			if email == "" {
				email = s.DefaultEmail
			}
			for _, d := range splitList(env["LETSENCRYPT_HOST"]) {
				if strings.ContainsAny(d, "*~") {
					warn("wildcard and regex hosts cannot use HTTP-01 ACME, skipping", "host", d)
					continue
				}
				if !ValidDomain(d) {
					warn("ignoring invalid LETSENCRYPT_HOST entry", "container", ctr.ShortName(), "host", d)
					continue
				}
				// A container only gets certificates for hosts it serves.
				if !slices.ContainsFunc(vhosts, func(h string) bool { return hostKey(h) == hostKey(d) }) {
					warn("ignoring LETSENCRYPT_HOST entry that is not in the container's VIRTUAL_HOST", "container", ctr.ShortName(), "host", d)
					continue
				}
				req := ACMERequest{Domain: byHost[hostKey(d)].host, Email: email, DirectoryURL: dir}
				// When containers disagree on the CA, the proxy's own CA
				// wins, so a LETSENCRYPT_TEST container cannot put a staging
				// certificate on a host another container serves.
				if i, ok := acmeIdx[hostKey(d)]; ok {
					if cfg.ACME[i].DirectoryURL != s.ACMECAURI && dir == s.ACMECAURI {
						cfg.ACME[i] = req
					}
					continue
				}
				acmeIdx[hostKey(d)] = len(cfg.ACME)
				cfg.ACME = append(cfg.ACME, req)
			}
		}
	}

	for _, hg := range hosts {
		first := hg.paths[0].backends[0]
		vh := &VHost{
			Host:    hg.host,
			IsRegex: strings.HasPrefix(hg.host, "~"),
		}
		vh.FileKey = hg.host
		if vh.IsRegex {
			vh.FileKey = sha1hex(hg.host)
		}
		vh.Default = s.DefaultHost != "" && hostKey(hg.host) == hostKey(s.DefaultHost)
		vh.SSLPolicy = envOr(first.env, "SSL_POLICY", s.SSLPolicy)
		vh.ServerTokens = first.env["SERVER_TOKENS"]
		vh.HTTP2 = labelBool(first.ctr, "http2.enable", s.EnableHTTP2)
		vh.NonGetRedirect = labelOr(first.ctr, "non-get-redirect", s.NonGetRedirect)
		vh.ExternalHTTPSPort = envOr(first.env, "EXTERNAL_HTTPS_PORT", s.HTTPSPort)
		vh.ACMEChallenge = envOr(first.env, "ACME_HTTP_CHALLENGE_LOCATION", strconv.FormatBool(s.ACMEChallenge)) != "false"

		// Certificate selection, in the same order as upstream nginx-proxy.
		if !vh.IsRegex {
			vh.Cert = selectCert(fs, hg.host, first.env["CERT_NAME"])
		}
		if vh.Cert == "" && defaultCertOK && labelBool(first.ctr, "trust-default-cert", s.TrustDefaultCert) {
			vh.Cert = "default"
		}
		if vh.Cert != "" {
			vh.ChainFile = fs.Exists(CertDir + "/" + vh.Cert + ".chain.pem")
			if p := CertDir + "/" + vh.Cert + ".dhparam.pem"; fs.Exists(p) {
				vh.DHParam = p
			}
		}

		method := httpsMethod(envOr(first.env, "HTTPS_METHOD", s.HTTPSMethod))
		if vh.Cert == "" && (method == "redirect" || method == "nohttp") &&
			parseBool(first.env, "ENABLE_HTTP_ON_MISSING_CERT", s.EnableHTTPOnMissingCert) {
			method = "noredirect"
		}
		vh.ServeHTTP = method != "nohttp"
		vh.ServeHTTPS = method != "nohttps"
		vh.Redirect = method == "redirect"
		if hsts := envOr(first.env, "HSTS", s.HSTS); hsts != "off" && method != "noredirect" && vh.Cert != "" {
			vh.HSTS = hsts
		}

		if p := VhostDir + "/" + vh.FileKey; fs.Exists(p) {
			vh.Include = p
		} else if fs.Exists(VhostDir + "/default") {
			vh.Include = VhostDir + "/default"
		}

		hasRoot := false
		for _, pg := range hg.paths {
			if pg.path == "/" {
				hasRoot = true
			}
			up := buildUpstream(s, hg.host, pg.path, pg.backends)
			cfg.Upstreams = append(cfg.Upstreams, up)
			vh.Locations = append(vh.Locations, buildLocation(fs, vh, pg.path, up, pg.backends[0]))
		}
		if !hasRoot && s.DefaultRoot != "none" {
			vh.DefaultRoot = s.DefaultRoot
		}

		if vh.Default {
			cfg.DefaultHTTPSet = vh.ServeHTTP
			cfg.DefaultTLSSet = vh.ServeHTTPS
		}
		cfg.VHosts = append(cfg.VHosts, vh)
	}
	return cfg
}

// Files lists the optional files the rendered configuration refers to.
// Their content is read by nginx, not rendered, so a change to any of them
// needs a reload even when the generated configuration is unchanged.
func (c *Config) Files() []string {
	var files []string
	add := func(p string) {
		if p != "" {
			files = append(files, p)
		}
	}
	add(c.DHParam)
	if c.ProxyConf {
		add("/etc/nginx/proxy.conf")
	}
	if c.DefaultCert {
		add(CertDir + "/default.crt")
		add(CertDir + "/default.key")
	}
	for _, vh := range c.VHosts {
		if vh.Cert != "" {
			add(CertDir + "/" + vh.Cert + ".crt")
			add(CertDir + "/" + vh.Cert + ".key")
		}
		add(vh.DHParam)
		add(vh.Include)
		for _, l := range vh.Locations {
			add(l.Override)
			add(l.AuthFile)
			add(l.Include)
			if l.Internal {
				add(NetworkInternalConf)
			}
		}
	}
	slices.Sort(files)
	return slices.Compact(files)
}

func buildUpstream(s Settings, host, path string, backends []backend) *Upstream {
	name := host
	if path != "/" {
		name += "-" + sha1hex(path)
	}
	if s.SHA1UpstreamName || strings.ContainsAny(host, "*~") {
		name = sha1hex(name)
	}
	up := &Upstream{Name: name, VHost: host}
	seen := map[string]bool{}
	for _, b := range backends {
		if b.addr != "" && !seen[b.addr] {
			seen[b.addr] = true
			up.Servers = append(up.Servers, b.addr)
		}
		if lb := strings.TrimSpace(b.ctr.Config.Labels[labelPrefix+"loadbalance"]); lb != "" && up.LoadBalance == "" {
			up.LoadBalance = lb
		}
	}
	keepalive := labelOr(backends[0].ctr, "keepalive", "auto")
	switch {
	case keepalive == "disabled" || len(up.Servers) == 0:
		up.Keepalive = "disabled"
	case keepalive == "auto":
		up.Keepalive = strconv.Itoa(2 * len(up.Servers))
	default:
		if n, err := strconv.Atoi(keepalive); err == nil && n > 0 {
			up.Keepalive = keepalive
		} else {
			warn("invalid keepalive label, using auto", "value", keepalive)
			up.Keepalive = strconv.Itoa(2 * len(up.Servers))
		}
	}
	return up
}

func buildLocation(fs FS, vh *VHost, path string, up *Upstream, b backend) *Location {
	hash := sha1hex(path)
	if p := VhostDir + "/" + vh.FileKey + "_" + hash + "_location_override"; fs.Exists(p) {
		return &Location{Path: path, Override: p}
	}
	if p := VhostDir + "/" + vh.FileKey + "_location_override"; path == "/" && fs.Exists(p) {
		return &Location{Path: path, Override: p}
	}
	proto := envOr(b.env, "VIRTUAL_PROTO", "http")
	switch proto {
	case "http", "https", "uwsgi", "fastcgi", "grpc", "grpcs":
	default:
		warn("unknown VIRTUAL_PROTO, using http", "host", vh.Host, "proto", proto)
		proto = "http"
	}
	loc := &Location{
		Path:      path,
		Proto:     proto,
		Upstream:  up.Name,
		Dest:      b.env["VIRTUAL_DEST"],
		Root:      envOr(b.env, "VIRTUAL_ROOT", "/var/www/public"),
		Internal:  b.env["NETWORK_ACCESS"] == "internal",
		Keepalive: up.Keepalive != "disabled",
	}
	switch {
	case fs.Exists(HtpasswdDir + "/" + vh.FileKey + "_" + hash):
		loc.AuthFile = HtpasswdDir + "/" + vh.FileKey + "_" + hash
		loc.AuthRealm = "Restricted " + vh.Host + path
	case fs.Exists(HtpasswdDir + "/" + vh.FileKey):
		loc.AuthFile = HtpasswdDir + "/" + vh.FileKey
		loc.AuthRealm = "Restricted " + vh.Host
		if vh.IsRegex {
			loc.AuthRealm = "Restricted access"
		}
	}
	for _, p := range []string{
		VhostDir + "/" + vh.FileKey + "_" + hash + "_location",
		VhostDir + "/" + vh.FileKey + "_location",
		VhostDir + "/default_location",
	} {
		if fs.Exists(p) {
			loc.Include = p
			break
		}
	}
	return loc
}

// selectCert implements upstream's certificate selection: CERT_NAME, exact
// host, then parent domain (one level only).
func selectCert(fs FS, host, certName string) string {
	if certName != "" {
		if certUsable(fs, certName) {
			return certName
		}
		return ""
	}
	if certUsable(fs, host) {
		return host
	}
	if _, parent, ok := strings.Cut(host, "."); ok && strings.Contains(parent, ".") && certUsable(fs, parent) {
		return parent
	}
	return ""
}

func certUsable(fs FS, name string) bool {
	return fs.Exists(CertDir+"/"+name+".crt") && fs.Exists(CertDir+"/"+name+".key")
}

// address picks the ip:port nginx should use to reach ctr.
func address(ctr *docker.Container, env map[string]string, all []*docker.Container, self *docker.Container, selfNets map[string]bool, selfHost, preferV6 bool) string {
	port := virtualPort(ctr, env)

	// A container that joined another container's network namespace
	// (network_mode "container:<id>", which is what Compose turns
	// "service:<name>" into) has no networks of its own. It is reached
	// through the container that owns the namespace.
	netCtr := ctr
	if ref, ok := strings.CutPrefix(ctr.HostConfig.NetworkMode, "container:"); ok {
		if self != nil && isContainer(self, ref) {
			return net.JoinHostPort("127.0.0.1", port)
		}
		netCtr = nil
		for _, c := range all {
			if isContainer(c, ref) {
				netCtr = c
			}
		}
		if netCtr == nil {
			return ""
		}
	}

	if netCtr.HostConfig.NetworkMode == "host" {
		if self == nil || selfHost {
			return net.JoinHostPort("127.0.0.1", port)
		}
		// Reach the host through the gateway of one of our own networks.
		for _, name := range sortedKeys(self.NetworkSettings.Networks) {
			if gw := self.NetworkSettings.Networks[name].Gateway; gw != "" {
				return net.JoinHostPort(gw, port)
			}
		}
		return ""
	}

	for _, name := range sortedKeys(netCtr.NetworkSettings.Networks) {
		if self != nil && !selfHost && !selfNets[name] {
			continue
		}
		ep := netCtr.NetworkSettings.Networks[name]
		ip := ep.IPAddress
		if (preferV6 && ep.GlobalIPv6Address != "") || ip == "" {
			ip = ep.GlobalIPv6Address
		}
		if ip != "" {
			return net.JoinHostPort(ip, port)
		}
	}
	return ""
}

// virtualPort returns the port the container is proxied to: VIRTUAL_PORT,
// else its only exposed port, else 80.
func virtualPort(ctr *docker.Container, env map[string]string) string {
	// Render the parsed number, not the raw value: validateContainer accepts
	// surrounding whitespace and a sign, which nginx does not.
	if n, err := strconv.Atoi(strings.TrimSpace(env["VIRTUAL_PORT"])); err == nil {
		return strconv.Itoa(n)
	}
	port := "80"
	if len(ctr.Config.ExposedPorts) == 1 {
		for p := range ctr.Config.ExposedPorts {
			port, _, _ = strings.Cut(p, "/")
		}
	}
	return port
}

// isContainer reports whether ref, the part after "container:" in a network
// mode, names c.
func isContainer(c *docker.Container, ref string) bool {
	return c.ID == ref || c.ShortName() == ref
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func envOr(env map[string]string, key, def string) string {
	if v := strings.TrimSpace(env[key]); v != "" {
		return v
	}
	return def
}

func labelOr(ctr *docker.Container, name, def string) string {
	if v := strings.TrimSpace(ctr.Config.Labels[labelPrefix+name]); v != "" {
		return v
	}
	return def
}

func labelBool(ctr *docker.Container, name string, def bool) bool {
	v := ctr.Config.Labels[labelPrefix+name]
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

var (
	domainRe      = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	pathRe        = regexp.MustCompile(`^(/[A-Za-z0-9._~%/:@!&=+,-]*)?$`)
	generatedRe   = regexp.MustCompile(`(?i)(^|-)[0-9a-f]{40}$`)
	loadBalanceRe = regexp.MustCompile(`^(least_conn|ip_hash|random(\s+two(\s+least_conn)?)?|hash\s+[^\s;{}'"#\\]+(\s+consistent)?)\s*;$`)
	sslPolicies   = []string{"", "Mozilla-Modern", "Mozilla-Intermediate", "Mozilla-Old"}
	protos        = []string{"", "http", "https", "uwsgi", "fastcgi", "grpc", "grpcs"}
)

// ValidDomain reports whether d is a plain DNS name, safe to use as a file name.
func ValidDomain(d string) bool { return len(d) <= 253 && domainRe.MatchString(d) }

// validateContainer checks every container-supplied value that reaches the
// nginx config or the filesystem. Containers are not trusted to write nginx
// directives, so values outside a strict format reject the whole container.
func validateContainer(env, labels map[string]string) error {
	if !safeMatcher(env["VIRTUAL_PATH"]) {
		return fmt.Errorf("VIRTUAL_PATH contains characters that are not allowed")
	}
	// VIRTUAL_DEST is appended to the upstream name in proxy_pass: anything
	// but a path would change the host nginx connects to (".evil.test/").
	// "$" is refused in both, as nginx expands variables there.
	if !pathRe.MatchString(env["VIRTUAL_DEST"]) {
		return fmt.Errorf("VIRTUAL_DEST must be empty or a path starting with \"/\", got %q", env["VIRTUAL_DEST"])
	}
	if !pathRe.MatchString(env["VIRTUAL_ROOT"]) {
		return fmt.Errorf("VIRTUAL_ROOT must be empty or an absolute path, got %q", env["VIRTUAL_ROOT"])
	}
	for _, k := range []string{"VIRTUAL_PORT", "EXTERNAL_HTTPS_PORT", "EXTERNAL_HTTP_PORT"} {
		if v := strings.TrimSpace(env[k]); v != "" {
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("%s must be a port number, got %q", k, v)
			}
		}
	}
	if v := strings.TrimSpace(env["VIRTUAL_PROTO"]); !slices.Contains(protos, v) {
		return fmt.Errorf("unknown VIRTUAL_PROTO %q", v)
	}
	if v := strings.TrimSpace(env["SSL_POLICY"]); !slices.Contains(sslPolicies, v) {
		return fmt.Errorf("unsupported SSL_POLICY %q", v)
	}
	if v := strings.TrimSpace(env["SERVER_TOKENS"]); !slices.Contains([]string{"", "on", "off", "build"}, v) {
		return fmt.Errorf("SERVER_TOKENS must be on, off or build, got %q", v)
	}
	if strings.ContainsAny(env["HSTS"], "\"\\$\r\n{}#") {
		return fmt.Errorf("HSTS contains characters that are not allowed")
	}
	if v := env["CERT_NAME"]; v != "" && (!safeToken(v) || strings.Contains(v, "/") || strings.Contains(v, "..")) {
		return fmt.Errorf("CERT_NAME must be a plain file name, got %q", v)
	}
	if v := strings.TrimSpace(labels[labelPrefix+"non-get-redirect"]); !slices.Contains([]string{"", "301", "302", "307", "308"}, v) {
		return fmt.Errorf("non-get-redirect label must be 301, 302, 307 or 308, got %q", v)
	}
	if v := strings.TrimSpace(labels[labelPrefix+"loadbalance"]); v != "" && !loadBalanceRe.MatchString(v) {
		return fmt.Errorf("loadbalance label %q is not a supported directive", v)
	}
	return nil
}

// safeToken reports whether s can be placed in the nginx config without
// changing its structure. Values come from container environments, which
// should never be able to inject directives. A backslash is refused because
// nginx reads it as an escape: at the end of a value it would swallow the
// ";" that closes the directive.
func safeToken(s string) bool {
	return !strings.ContainsAny(s, " \t\r\n;{}'\"#\\")
}

// safeMatcher is safeToken for server names and locations, which may be
// nginx regular expressions (a leading "~"). Those need backslashes, so
// there one is only refused as the last character.
func safeMatcher(s string) bool {
	if !strings.HasPrefix(s, "~") {
		return safeToken(s)
	}
	return !strings.ContainsAny(s, " \t\r\n;{}'\"#") && !strings.HasSuffix(s, `\`)
}

// hostKey is the name nginx sees for host: server and upstream names are
// matched without regard to case. Regular expressions are kept as they are.
func hostKey(h string) string {
	if strings.HasPrefix(h, "~") {
		return h
	}
	return strings.ToLower(h)
}

// reservedHost reports whether h has the shape of a generated upstream name
// (a SHA-1, or a host followed by "-" and the SHA-1 of a path). Such a host
// would get the same upstream name as another host and path, and the
// duplicate upstream would make nginx reject the whole configuration.
func reservedHost(h string) bool {
	return !strings.HasPrefix(h, "~") && generatedRe.MatchString(h)
}

func sha1hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
