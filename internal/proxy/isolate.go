package proxy

// Without returns a copy of c that leaves out the given virtual hosts and
// their upstreams.
func (c *Config) Without(hosts []string) *Config {
	drop := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		drop[h] = true
	}
	return c.without(drop)
}

func (c *Config) without(drop map[string]bool) *Config {
	out := *c
	out.VHosts, out.Upstreams = nil, nil
	for _, vh := range c.VHosts {
		if !drop[vh.Host] {
			out.VHosts = append(out.VHosts, vh)
			continue
		}
		if vh.Default {
			// The fallback servers take over again.
			out.DefaultHTTPSet, out.DefaultTLSSet = false, false
		}
	}
	for _, up := range c.Upstreams {
		if !drop[up.VHost] {
			out.Upstreams = append(out.Upstreams, up)
		}
	}
	return &out
}

// Isolate finds the virtual hosts that make check fail, so that one
// container with a value nginx rejects does not block every other host.
// check is called with candidate configurations, O(bad hosts × log hosts)
// times. The result is nil when check fails even without any virtual host:
// then the cause lies elsewhere and leaving hosts out would not help.
func Isolate(cfg *Config, check func(*Config) error) []string {
	drop := make(map[string]bool, len(cfg.VHosts))
	for _, vh := range cfg.VHosts {
		drop[vh.Host] = true
	}
	if check(cfg.without(drop)) != nil {
		return nil
	}

	var bad []string
	// admit adds group to the accepted hosts, splitting it until the hosts
	// that cannot be added are found.
	var admit func(group []*VHost)
	admit = func(group []*VHost) {
		for _, vh := range group {
			delete(drop, vh.Host)
		}
		if check(cfg.without(drop)) == nil {
			return
		}
		for _, vh := range group {
			drop[vh.Host] = true
		}
		if len(group) == 1 {
			bad = append(bad, group[0].Host)
			return
		}
		admit(group[:len(group)/2])
		admit(group[len(group)/2:])
	}
	admit(cfg.VHosts)
	return bad
}
