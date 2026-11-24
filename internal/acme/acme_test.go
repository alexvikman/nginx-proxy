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
