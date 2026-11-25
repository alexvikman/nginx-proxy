package proxy

import (
	"slices"
	"strings"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.5, 192.168.1.0/24 2001:db8::1\tcloudflare,10.0.0.5/32,10.1.2.3/16,104.16.0.0/13")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.5/32", "192.168.1.0/24", "2001:db8::1/128", "10.1.0.0/16", "104.16.0.0/13"}; !slices.Equal(got.Ranges, want) {
		t.Fatalf("ranges: got %v\nwant %v", got.Ranges, want)
	}
	// A range listed explicitly is fully trusted, and not listed twice.
	if len(got.Cloudflare) != len(CloudflareRanges)-1 || slices.Contains(got.Cloudflare, "104.16.0.0/13") {
		t.Fatalf("cloudflare: got %v", got.Cloudflare)
	}
	if got, err := ParseTrustedProxies(""); err != nil || !got.Empty() {
		t.Fatalf("empty: got %v, %v", got, err)
	}
	if got, _ := ParseTrustedProxies("Cloudflare"); len(got.Ranges) != 0 || len(got.Cloudflare) != len(CloudflareRanges) {
		t.Fatalf("the keyword alone must only trust Cloudflare: %v", got)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "example.com", "10.0.0.0/33", "10.0.0.1;", "fe80::1%eth0", "cloudflare;deny all"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestParseRealIPHeader(t *testing.T) {
	lb, _ := ParseTrustedProxies("10.0.0.5")
	cf, _ := ParseTrustedProxies("cloudflare")
	both, _ := ParseTrustedProxies("cloudflare,10.0.0.5")
	for _, tc := range []struct {
		in      string
		trusted TrustedProxies
		want    string
	}{
		{"", lb, "X-Forwarded-For"},
		// Behind Cloudflare, X-Forwarded-For keeps what the sender wrote.
		{"", cf, "CF-Connecting-IP"},
		{"X-Real-IP", cf, "X-Real-IP"},
		{" CF-Connecting-IP ", lb, "CF-Connecting-IP"},
		{"X-Forwarded-For", both, "X-Forwarded-For"},
		{"CF-Connecting-IP", both, "CF-Connecting-IP"},
	} {
		if got, err := ParseRealIPHeader(tc.in, tc.trusted); err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v, want %q", tc.in, got, err, tc.want)
		}
	}
	// Each default can be forged in a mixed setup: the operator must choose.
	if _, err := ParseRealIPHeader("", both); err == nil {
		t.Error("cloudflare with other proxies must require REAL_IP_HEADER")
	}
	for _, bad := range []string{"X-Forwarded-For;", "a b", "X_Real_IP", strings.Repeat("a", 65)} {
		if _, err := ParseRealIPHeader(bad, lb); err == nil {
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
	s, err := SettingsFromEnv(map[string]string{"TRUSTED_PROXIES": "10.0.0.5,cloudflare", "REAL_IP_HEADER": "CF-Connecting-IP", "TRUST_DOWNSTREAM_PROXY": "true"})
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, Build(s, nil, nil, fakeFS{}))
	for _, want := range []string{
		"set_real_ip_from 10.0.0.5/32;",
		"set_real_ip_from 173.245.48.0/20;",
		"set_real_ip_from 2400:cb00::/32;",
		"real_ip_header CF-Connecting-IP;",
		"real_ip_recursive on;",
		"geo $realip_remote_addr $proxy_from_trusted {",
		"    173.245.48.0/20 1;",
		"    10.0.0.5/32 2;",
		`"~^[12]:(https?)$" $1;`,
		// Host and port are only believed from proxies listed by address.
		`"~^2:(.+)$"  $1;`,
		`"~^2:([0-9]{1,5})$" $1;`,
		"proxy_set_header X-Forwarded-For $remote_addr;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config is missing %q", want)
		}
	}
	// Untrusted clients must never get their own headers through.
	for _, unwanted := range []string{"$proxy_add_x_forwarded_for", "default $http_x_forwarded_proto", "default $http_x_forwarded_host", `"~^[12]:(.+)$"`} {
		if strings.Contains(out, unwanted) {
			t.Errorf("rendered config contains %q", unwanted)
		}
	}
	if n := strings.Count(out, "proxy_set_header X-Forwarded-For"); n != 1 {
		t.Errorf("want one X-Forwarded-For header, got %d", n)
	}
}
