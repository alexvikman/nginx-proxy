package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexvikman/nginx-proxy/internal/proxy"
)

func TestBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		1: 10 * time.Minute,
		2: 20 * time.Minute,
		8: 1280 * time.Minute,
		9: maxBackoff,
	} {
		if got := backoff(failures); got != want {
			t.Errorf("backoff(%d) = %v, want %v", failures, got, want)
		}
	}
	// A domain can keep failing for months; the wait must never shrink.
	prev := time.Duration(0)
	for failures := 1; failures <= 1000; failures++ {
		got := backoff(failures)
		if got < prev || got < minBackoff || got > maxBackoff {
			t.Fatalf("backoff(%d) = %v after %v", failures, got, prev)
		}
		prev = got
	}
}

func TestNeedsCertWhenCAChanges(t *testing.T) {
	m := &Manager{CertDir: t.TempDir()}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.test"},
		DNSNames:     []string{"app.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store("app.test", proxy.LetsEncryptStaging, key, [][]byte{der}); err != nil {
		t.Fatal(err)
	}
	prod := proxy.ACMERequest{Domain: "app.test", DirectoryURL: proxy.LetsEncryptProduction}
	staging := proxy.ACMERequest{Domain: "app.test", DirectoryURL: proxy.LetsEncryptStaging}
	if m.needsCert(staging) {
		t.Error("a valid certificate from the requested CA must be kept")
	}
	if !m.needsCert(prod) {
		t.Error("a certificate from another CA must be replaced")
	}
	// Certificates the proxy did not obtain itself, e.g. from acme-companion.
	if err := os.Remove(filepath.Join(m.CertDir, ".acme", "issuer", "app.test")); err != nil {
		t.Fatal(err)
	}
	if m.needsCert(prod) {
		t.Error("a valid certificate of unknown origin must be kept")
	}
}

// selfSigned returns a certificate for domain and key, signed by key.
func selfSigned(t *testing.T, domain string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestChallengeTokensAreFileNames(t *testing.T) {
	for _, bad := range []string{
		"", ".", "..", "../../../../etc/nginx/conf.d/evil.conf", "a/b", `a\b`, "a b", "a\nb", "a.conf", "a;b", "tok\x00en",
	} {
		if tokenRe.MatchString(bad) {
			t.Errorf("token %q must be refused", bad)
		}
	}
	// As issued by Let's Encrypt and Pebble: base64url.
	for _, good := range []string{"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "a_b-C9"} {
		if !tokenRe.MatchString(good) {
			t.Errorf("token %q must be accepted", good)
		}
	}
}

func TestStoreRefusesForeignCertificates(t *testing.T) {
	m := &Manager{CertDir: t.TempDir()}
	key := newKey(t)
	if err := m.store("app.test", proxy.LetsEncryptProduction, key, [][]byte{selfSigned(t, "app.test", key)}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(m.CertDir, "app.test.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"another name": selfSigned(t, "other.test", key),
		"another key":  selfSigned(t, "app.test", newKey(t)),
		"not DER":      []byte("garbage"),
	} {
		if err := m.store("app.test", proxy.LetsEncryptProduction, key, [][]byte{der}); err == nil {
			t.Errorf("%s: certificate was stored", name)
		}
	}
	// The certificate in use must have survived the refused ones.
	after, err := os.ReadFile(filepath.Join(m.CertDir, "app.test.crt"))
	if err != nil || string(after) != string(before) {
		t.Fatalf("the working certificate was replaced (err=%v)", err)
	}
}

func TestWriteFileDoesNotFollowLinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	// What the old fixed temporary name and the target could be replaced by
	// in a certificate volume shared with another container.
	for _, name := range []string{"app.test.key", "app.test.key.tmp"} {
		if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "app.test.key")
	if err := writeFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(outside); string(got) != "untouched" {
		t.Fatalf("wrote through a symbolic link: %q", got)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("want a regular 0600 file, got %v (err=%v)", fi.Mode(), err)
	}
	if got, _ := os.ReadFile(path); string(got) != "secret" {
		t.Fatalf("content = %q", got)
	}
	// No temporary file is left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("left %s behind", e.Name())
		}
	}
}

func TestAccountKeyIsNotReplacedWhenUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acct", "account.key")
	first, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadOrCreateKey(path)
	if err != nil || !first.Public().(*ecdsa.PublicKey).Equal(again.Public()) {
		t.Fatalf("the stored key was not reused (err=%v)", err)
	}
	// Something other than "missing": here the path is a directory.
	blocked := filepath.Join(t.TempDir(), "account.key")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(blocked); err == nil {
		t.Fatal("a key that cannot be read must be an error, not a reason to make a new one")
	}
}
