package proxy

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// CloudflareRanges are the addresses Cloudflare connects to origins from,
// as published at https://www.cloudflare.com/ips/ (checked 2026-11-25).
// "cloudflare" in TRUSTED_PROXIES stands for these. Cloudflare announces
// changes in advance; update this list in a pull request.
var CloudflareRanges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// TrustedProxies is the parsed TRUSTED_PROXIES.
type TrustedProxies struct {
	// Ranges are the proxies listed by address or range: the operator's
	// own load balancers. Every X-Forwarded-* header they send is believed.
	Ranges []string
	// Cloudflare holds CloudflareRanges when the "cloudflare" keyword was
	// given, minus any range also listed in Ranges. These addresses are
	// shared by every Cloudflare customer, so anyone can send requests from
	// them with headers of their choosing, through a zone of their own that
	// points at this server. Only what Cloudflare sets itself is believed
	// from them: the client address in CF-Connecting-IP and the scheme.
	Cloudflare []string
}

// ParseTrustedProxies reads TRUSTED_PROXIES: addresses and CIDR ranges of
// the proxies in front of this one, separated by commas or spaces, and the
// keyword "cloudflare". Ranges are normalised and de-duplicated.
func ParseTrustedProxies(v string) (TrustedProxies, error) {
	var t TrustedProxies
	cloudflare := false
	for item := range strings.FieldsFuncSeq(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if strings.EqualFold(item, "cloudflare") {
			cloudflare = true
			continue
		}
		var p netip.Prefix
		if strings.Contains(item, "/") {
			var err error
			if p, err = netip.ParsePrefix(item); err != nil {
				return TrustedProxies{}, fmt.Errorf("TRUSTED_PROXIES: %q is not an address or CIDR range", item)
			}
		} else {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return TrustedProxies{}, fmt.Errorf("TRUSTED_PROXIES: %q is not an address or CIDR range", item)
			}
			if a.Zone() != "" {
				return TrustedProxies{}, fmt.Errorf("TRUSTED_PROXIES: %q has a zone, which nginx does not accept", item)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() == 0 {
			// Every client would be believed: the same as
			// TRUST_DOWNSTREAM_PROXY=true, but with a forgeable client
			// address on top. Refuse rather than guess.
			return TrustedProxies{}, fmt.Errorf("TRUSTED_PROXIES: %q trusts every client; list the proxies in front instead", item)
		}
		if r := p.Masked().String(); !slices.Contains(t.Ranges, r) {
			t.Ranges = append(t.Ranges, r)
		}
	}
	if cloudflare {
		t.Cloudflare = slices.DeleteFunc(slices.Clone(CloudflareRanges), func(r string) bool { return slices.Contains(t.Ranges, r) })
	}
	return t, nil
}

// Empty reports whether no proxy is trusted.
func (t TrustedProxies) Empty() bool { return len(t.Ranges) == 0 && len(t.Cloudflare) == 0 }

// ParseRealIPHeader reads REAL_IP_HEADER, the request header a trusted
// proxy puts the client address in. The default is CF-Connecting-IP when
// Cloudflare is trusted: Cloudflare sets it to the address it saw, whereas
// X-Forwarded-For keeps whatever the sender wrote in front of it.
func ParseRealIPHeader(v string, t TrustedProxies) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		if len(t.Cloudflare) > 0 {
			return "CF-Connecting-IP", nil
		}
		return "X-Forwarded-For", nil
	}
	if !headerName.MatchString(v) {
		return "", fmt.Errorf("REAL_IP_HEADER: %q is not a header name", v)
	}
	return v, nil
}
