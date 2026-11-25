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

// ParseTrustedProxies reads TRUSTED_PROXIES: addresses and CIDR ranges of
// the proxies in front of this one, separated by commas or spaces, and the
// keyword "cloudflare". It returns normalised, de-duplicated ranges.
func ParseTrustedProxies(v string) ([]string, error) {
	var out []string
	for item := range strings.FieldsFuncSeq(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if strings.EqualFold(item, "cloudflare") {
			out = append(out, CloudflareRanges...)
			continue
		}
		var p netip.Prefix
		if strings.Contains(item, "/") {
			var err error
			if p, err = netip.ParsePrefix(item); err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an address or CIDR range", item)
			}
		} else {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an address or CIDR range", item)
			}
			if a.Zone() != "" {
				return nil, fmt.Errorf("TRUSTED_PROXIES: %q has a zone, which nginx does not accept", item)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() == 0 {
			// Every client would be believed: the same as
			// TRUST_DOWNSTREAM_PROXY=true, but with a forgeable client
			// address on top. Refuse rather than guess.
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q trusts every client; list the proxies in front instead", item)
		}
		out = append(out, p.Masked().String())
	}
	seen := map[string]bool{}
	return slices.DeleteFunc(out, func(p string) bool {
		if seen[p] {
			return true
		}
		seen[p] = true
		return false
	}), nil
}

// ParseRealIPHeader reads REAL_IP_HEADER, the request header a trusted
// proxy puts the client address in.
func ParseRealIPHeader(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "X-Forwarded-For", nil
	}
	if !headerName.MatchString(v) {
		return "", fmt.Errorf("REAL_IP_HEADER: %q is not a header name", v)
	}
	return v, nil
}
