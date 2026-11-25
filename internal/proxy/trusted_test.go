package proxy

import (
	"slices"
	"strings"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.5, 192.168.1.0/24 2001:db8::1\tcloudflare,10.0.0.5/32,10.1.2.3/16")
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"10.0.0.5/32", "192.168.1.0/24", "2001:db8::1/128"}, CloudflareRanges...)
	want = append(want, "10.1.0.0/16")
	if !slices.Equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if got, err := ParseTrustedProxies(""); err != nil || got != nil {
		t.Fatalf("empty: got %v, %v", got, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "example.com", "10.0.0.0/33", "10.0.0.1;", "fe80::1%eth0", "cloudflare;deny all"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestParseRealIPHeader(t *testing.T) {
	for in, want := range map[string]string{"": "X-Forwarded-For", "CF-Connecting-IP": "CF-Connecting-IP", " X-Real-IP ": "X-Real-IP"} {
		if got, err := ParseRealIPHeader(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"X-Forwarded-For;", "a b", "X_Real_IP", strings.Repeat("a", 65)} {
		if _, err := ParseRealIPHeader(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestSettingsRefuseInvalidTrustedProxies(t *testing.T) {
	if _, err := SettingsFromEnv(map[string]string{"TRUSTED_PROXIES": "0.0.0.0/0"}); err == nil {
		t.Fatal("an invalid TRUSTED_PROXIES must stop the proxy, not be ignored")
	}
}

func TestTrustedProxiesReplaceDownstreamTrust(t *testing.T) {
	s, err := SettingsFromEnv(map[string]string{"TRUSTED_PROXIES": "10.0.0.5,cloudflare", "TRUST_DOWNSTREAM_PROXY": "true"})
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, Build(s, nil, nil, fakeFS{}))
	for _, want := range []string{
		"set_real_ip_from 10.0.0.5/32;",
		"set_real_ip_from 173.245.48.0/20;",
		"set_real_ip_from 2400:cb00::/32;",
		"real_ip_header X-Forwarded-For;",
		"real_ip_recursive on;",
		"geo $realip_remote_addr $proxy_from_trusted {",
		"    10.0.0.5/32 1;",
		`map "$proxy_from_trusted:$http_x_forwarded_proto" $proxy_x_forwarded_proto {`,
		`"~^1:(https?)$" $1;`,
		"proxy_set_header X-Forwarded-For $remote_addr;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config is missing %q", want)
		}
	}
	// Untrusted clients must never get their own headers through.
	for _, unwanted := range []string{"$proxy_add_x_forwarded_for", "default $http_x_forwarded_proto", "default $http_x_forwarded_host"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("rendered config contains %q", unwanted)
		}
	}
	if n := strings.Count(out, "proxy_set_header X-Forwarded-For"); n != 1 {
		t.Errorf("want one X-Forwarded-For header, got %d", n)
	}
}
