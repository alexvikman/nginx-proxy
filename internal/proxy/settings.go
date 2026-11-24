// Package proxy turns running containers into an nginx configuration.
package proxy

import (
	"strconv"
	"strings"
)

// Label prefix shared with upstream nginx-proxy, kept for drop-in compatibility.
const labelPrefix = "com.github.nginx-proxy.nginx-proxy."

// Settings are the proxy-wide options, read from the proxy container's environment.
type Settings struct {
	Version string

	DefaultHost             string
	DefaultRoot             string
	HTTPSMethod             string
	HSTS                    string
	SSLPolicy               string
	HTTPPort                string
	HTTPSPort               string
	NonGetRedirect          string
	Resolvers               string
	LogFormat               string
	LogFormatEscape         string
	ACMEChallenge           bool
	ACMEAcceptUnknownHost   bool
	EnableHTTP2             bool
	EnableIPv6              bool
	EnableHTTPOnMissingCert bool
	EnableAccessLog         bool
	LogJSON                 bool
	TrustDefaultCert        bool
	TrustDownstreamProxy    bool
	PreferIPv6Network       bool
	SHA1UpstreamName        bool

	// Built-in ACME client.
	ACMEEnabled  bool
	ACMECAURI    string
	DefaultEmail string
}

// LetsEncrypt production and staging directories.
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// SettingsFromEnv reads Settings from an environment map, using the same
// variable names and defaults as upstream nginx-proxy.
func SettingsFromEnv(env map[string]string) Settings {
	str := func(k, def string) string {
		if v := strings.TrimSpace(env[k]); v != "" {
			return v
		}
		return def
	}
	return Settings{
		Version:                 str("NGINX_PROXY_VERSION", "dev"),
		DefaultHost:             str("DEFAULT_HOST", ""),
		DefaultRoot:             str("DEFAULT_ROOT", "404"),
		HTTPSMethod:             httpsMethod(str("HTTPS_METHOD", "redirect")),
		HSTS:                    strings.ReplaceAll(str("HSTS", "max-age=31536000"), `"`, ""),
		SSLPolicy:               str("SSL_POLICY", "Mozilla-Intermediate"),
		HTTPPort:                str("HTTP_PORT", "80"),
		HTTPSPort:               str("HTTPS_PORT", "443"),
		NonGetRedirect:          str("NON_GET_REDIRECT", "301"),
		Resolvers:               str("RESOLVERS", ""),
		LogFormat:               str("LOG_FORMAT", ""),
		LogFormatEscape:         str("LOG_FORMAT_ESCAPE", "default"),
		ACMEChallenge:           str("ACME_HTTP_CHALLENGE_LOCATION", "true") != "false",
		ACMEAcceptUnknownHost:   parseBool(env, "ACME_HTTP_CHALLENGE_ACCEPT_UNKNOWN_HOST", false),
		EnableHTTP2:             parseBool(env, "ENABLE_HTTP2", true),
		EnableIPv6:              parseBool(env, "ENABLE_IPV6", false),
		EnableHTTPOnMissingCert: parseBool(env, "ENABLE_HTTP_ON_MISSING_CERT", true),
		EnableAccessLog:         !parseBool(env, "DISABLE_ACCESS_LOGS", false),
		LogJSON:                 parseBool(env, "LOG_JSON", false),
		TrustDefaultCert:        parseBool(env, "TRUST_DEFAULT_CERT", true),
		TrustDownstreamProxy:    parseBool(env, "TRUST_DOWNSTREAM_PROXY", true),
		PreferIPv6Network:       parseBool(env, "PREFER_IPV6_NETWORK", false),
		SHA1UpstreamName:        parseBool(env, "SHA1_UPSTREAM_NAME", false),
		ACMEEnabled:             parseBool(env, "ENABLE_ACME", true),
		ACMECAURI:               str("ACME_CA_URI", LetsEncryptProduction),
		DefaultEmail:            str("DEFAULT_EMAIL", ""),
	}
}

func parseBool(env map[string]string, key string, def bool) bool {
	v := strings.TrimSpace(env[key])
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		warn("ignoring invalid boolean", "var", key, "value", v)
		return def
	}
	return b
}

func httpsMethod(v string) string {
	switch v {
	case "redirect", "noredirect", "nohttp", "nohttps":
		return v
	}
	warn("unknown HTTPS_METHOD, using redirect", "value", v)
	return "redirect"
}
