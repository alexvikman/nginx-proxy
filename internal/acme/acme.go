// Package acme obtains and renews TLS certificates with the ACME HTTP-01
// challenge. Challenge files are written to a directory nginx serves under
// /.well-known/acme-challenge/, and certificates are written using the same
// file layout as acme-companion (<domain>.crt, .key, .chain.pem), so the
// rest of nginx-proxy needs no special handling for them.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/alexvikman/nginx-proxy/internal/proxy"
)

const (
	renewBefore   = 30 * 24 * time.Hour
	checkInterval = 12 * time.Hour
	minBackoff    = 10 * time.Minute
	maxBackoff    = 24 * time.Hour
	orderTimeout  = 3 * time.Minute
)

// tokenRe is the base64url alphabet that RFC 8555 section 8.3 limits
// challenge tokens to.
var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Manager keeps certificates for the wanted domains valid.
type Manager struct {
	CertDir      string
	ChallengeDir string
	OnChange     func() // called after a certificate was written
	// LocalHTTP is the address nginx listens on for plain HTTP (e.g.
	// "127.0.0.1:80"). Before asking the CA to validate, the challenge is
	// fetched through nginx locally. This waits out config reloads and
	// avoids spending the CA's failed-validation rate limit on a
	// misconfigured host.
	LocalHTTP string

	mu       sync.Mutex
	wanted   []proxy.ACMERequest
	failures map[string]failure
	clients  map[string]*acme.Client
	wake     chan struct{}
	once     sync.Once
}

type failure struct {
	count int
	retry time.Time
}

func (m *Manager) init() {
	m.once.Do(func() {
		m.wake = make(chan struct{}, 1)
		m.failures = map[string]failure{}
		m.clients = map[string]*acme.Client{}
	})
}

// Want sets the domains that should have certificates. It is cheap to call
// on every configuration update; work only happens when something changed.
func (m *Manager) Want(reqs []proxy.ACMERequest) {
	m.init()
	reqs = slices.Clone(reqs)
	slices.SortFunc(reqs, func(a, b proxy.ACMERequest) int {
		if a.Domain < b.Domain {
			return -1
		}
		if a.Domain > b.Domain {
			return 1
		}
		return 0
	})
	reqs = slices.CompactFunc(reqs, func(a, b proxy.ACMERequest) bool { return a.Domain == b.Domain })

	m.mu.Lock()
	changed := !slices.Equal(m.wanted, reqs)
	m.wanted = reqs
	m.mu.Unlock()
	if changed {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
}

// Run processes certificate work until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	m.init()
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	retry := time.NewTimer(time.Hour)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-ticker.C:
		case <-retry.C:
		}
		next := m.pass(ctx)
		retry.Reset(next)
	}
}

// pass issues or renews every certificate that needs it and returns how long
// until the next failed domain may be retried.
func (m *Manager) pass(ctx context.Context) time.Duration {
	m.mu.Lock()
	wanted := slices.Clone(m.wanted)
	m.mu.Unlock()

	next := checkInterval
	for _, req := range wanted {
		if ctx.Err() != nil {
			return next
		}
		if !m.needsCert(req) {
			delete(m.failures, req.Domain)
			continue
		}
		if f, ok := m.failures[req.Domain]; ok && time.Now().Before(f.retry) {
			next = min(next, time.Until(f.retry))
			continue
		}
		slog.Info("requesting certificate", "domain", req.Domain, "ca", req.DirectoryURL)
		if err := m.obtain(ctx, req); err != nil {
			f := m.failures[req.Domain]
			f.count++
			wait := backoff(f.count)
			f.retry = time.Now().Add(wait)
			m.failures[req.Domain] = f
			next = min(next, wait)
			slog.Error("certificate request failed", "domain", req.Domain, "err", err, "retry_in", wait)
			continue
		}
		delete(m.failures, req.Domain)
		slog.Info("certificate issued", "domain", req.Domain)
		if m.OnChange != nil {
			m.OnChange()
		}
	}
	return max(next, time.Minute)
}

// backoff returns how long to wait after the given number of consecutive
// failures: minBackoff, doubled for every further failure, up to maxBackoff.
func backoff(failures int) time.Duration {
	// The exponent is capped as well as the result: an unbounded shift
	// overflows to zero or below, which would retry without any wait.
	return min(minBackoff<<min(max(failures-1, 0), 16), maxBackoff)
}

// needsCert reports whether the domain lacks a certificate that covers it
// and is valid for longer than renewBefore, or has one that this proxy
// obtained from a different CA than the one now requested (for example a
// staging certificate once LETSENCRYPT_TEST is removed). Certificates the
// proxy did not obtain itself are left alone until they need renewal.
func (m *Manager) needsCert(req proxy.ACMERequest) bool {
	domain := req.Domain
	if ca, err := os.ReadFile(m.issuerPath(domain)); err == nil && strings.TrimSpace(string(ca)) != req.DirectoryURL {
		return true
	}
	data, err := os.ReadFile(filepath.Join(m.CertDir, domain+".crt"))
	if err != nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(m.CertDir, domain+".key")); err != nil {
		return true
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	if leaf.VerifyHostname(domain) != nil {
		return true
	}
	return time.Until(leaf.NotAfter) < renewBefore
}

func (m *Manager) client(ctx context.Context, req proxy.ACMERequest) (*acme.Client, error) {
	if c, ok := m.clients[req.DirectoryURL]; ok {
		return c, nil
	}
	sum := sha256.Sum256([]byte(req.DirectoryURL))
	keyPath := filepath.Join(m.CertDir, ".acme", hex.EncodeToString(sum[:8]), "account.key")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	c := &acme.Client{Key: key, DirectoryURL: req.DirectoryURL, UserAgent: "nginx-proxy"}
	acct := &acme.Account{}
	if req.Email != "" {
		acct.Contact = []string{"mailto:" + req.Email}
	}
	if _, err := c.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register account: %w", err)
	}
	m.clients[req.DirectoryURL] = c
	return c, nil
}

func (m *Manager) obtain(ctx context.Context, req proxy.ACMERequest) error {
	// Domains become file names in CertDir; never trust them blindly.
	if !proxy.ValidDomain(req.Domain) {
		return fmt.Errorf("refusing invalid domain %q", req.Domain)
	}
	ctx, cancel := context.WithTimeout(ctx, orderTimeout)
	defer cancel()

	c, err := m.client(ctx, req)
	if err != nil {
		return err
	}
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(req.Domain))
	if err != nil {
		return fmt.Errorf("create order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		if err := m.authorize(ctx, c, u, req.Domain); err != nil {
			return err
		}
	}
	// Some CAs omit the Location header on later order responses, so keep
	// the URLs from the original order.
	orderURI, finalizeURL := order.URI, order.FinalizeURL
	if _, err := c.WaitOrder(ctx, orderURI); err != nil {
		return fmt.Errorf("wait for order: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Domain},
		DNSNames: []string{req.Domain},
	}, certKey)
	if err != nil {
		return err
	}
	der, _, err := c.CreateCertFromOrder(ctx, &acme.Order{URI: orderURI, FinalizeURL: finalizeURL}, csr, true)
	if err != nil {
		return fmt.Errorf("finalize order: %w", err)
	}
	return m.store(req.Domain, req.DirectoryURL, certKey, der)
}

// authorize answers the http-01 challenge of one authorization of the order
// for domain. What the CA sends is not trusted beyond what the protocol
// allows: it decides a file name here.
func (m *Manager) authorize(ctx context.Context, c *acme.Client, url, domain string) error {
	z, err := c.GetAuthorization(ctx, url)
	if err != nil {
		return fmt.Errorf("get authorization: %w", err)
	}
	if !strings.EqualFold(z.Identifier.Value, domain) {
		return fmt.Errorf("CA asked to authorize %q in an order for %s", z.Identifier.Value, domain)
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, ch := range z.Challenges {
		if ch.Type == "http-01" {
			chal = ch
		}
	}
	if chal == nil {
		return fmt.Errorf("CA offered no http-01 challenge for %s", domain)
	}
	// The token becomes a file name, and the start of that file's content.
	// With a path separator in it, the CA could write outside ChallengeDir,
	// for instance into the directories nginx reads its configuration from.
	if !tokenRe.MatchString(chal.Token) {
		return fmt.Errorf("CA sent an invalid http-01 token for %s", domain)
	}
	body, err := c.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	path := filepath.Join(m.ChallengeDir, chal.Token)
	if err := os.MkdirAll(m.ChallengeDir, 0o755); err != nil {
		return err
	}
	if err := writeFile(path, []byte(body), 0o644); err != nil {
		return err
	}
	defer os.Remove(path)

	if err := m.selfCheck(ctx, domain, chal.Token, body); err != nil {
		return err
	}
	if _, err := c.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}
	if _, err := c.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("authorization for %s: %w", domain, err)
	}
	return nil
}

// selfCheck fetches the challenge through nginx until it answers with the
// expected key authorization, for up to 30 seconds.
func (m *Manager) selfCheck(ctx context.Context, domain, token, want string) error {
	if m.LocalHTTP == "" {
		return nil
	}
	url := "http://" + m.LocalHTTP + "/.well-known/acme-challenge/" + token
	client := &http.Client{
		Timeout: 3 * time.Second,
		// A redirect means the challenge location is missing.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Host = domain
		resp, err := client.Do(req)
		if err == nil {
			got, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(got)) == want {
				return nil
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("nginx does not serve the ACME challenge for %s (last result: %s); not asking the CA to validate", domain, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// issuerPath is where the directory URL of the CA that issued the domain's
// certificate is recorded.
func (m *Manager) issuerPath(domain string) string {
	return filepath.Join(m.CertDir, ".acme", "issuer", domain)
}

func (m *Manager) store(domain, directoryURL string, key *ecdsa.PrivateKey, der [][]byte) error {
	if len(der) == 0 {
		return errors.New("CA returned an empty certificate chain")
	}
	// Check the certificate before it replaces the one in use: nginx would
	// refuse a certificate that does not belong to the key, and the host
	// would be left out until the next attempt.
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("CA returned an unreadable certificate: %w", err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return fmt.Errorf("CA returned a certificate for another name: %w", err)
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("CA returned a certificate for another key")
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	var full, chain []byte
	for i, b := range der {
		p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		full = append(full, p...)
		if i > 0 {
			chain = append(chain, p...)
		}
	}
	base := filepath.Join(m.CertDir, domain)
	// Write the key first: nginx only picks up the pair once .crt exists.
	if err := writeFile(base+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeFile(base+".chain.pem", chain, 0o644); err != nil {
		return err
	}
	if err := writeFile(base+".crt", full, 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.issuerPath(domain)), 0o700); err != nil {
		return err
	}
	return writeFile(m.issuerPath(domain), []byte(directoryURL+"\n"), 0o600)
}

func loadOrCreateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: no PEM data", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	// Only a missing key is replaced: after any other error (permissions,
	// I/O) a new key would silently abandon the existing ACME account.
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return key, writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// writeFile replaces path atomically. The temporary file gets a random name
// and is created exclusively, so nothing planted in a shared certificate
// volume (a symbolic link in particular) is written through, and it is
// private until the content is complete: perm is applied last.
func writeFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // fails harmlessly after the rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
