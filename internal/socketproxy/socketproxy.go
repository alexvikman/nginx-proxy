// Package socketproxy serves the few Docker Engine API requests nginx-proxy
// makes, and nothing else, so the proxy container does not need the Docker
// socket.
//
// Access to the Docker socket amounts to root on the host. With this proxy in
// between, a compromised nginx-proxy can only make four read requests. The
// responses are rebuilt from the fields nginx-proxy reads, so it does not see
// other containers' secrets either: environment variables and labels are
// limited to the ones it uses, and fields such as mounts are left out.
package socketproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/alexvikman/nginx-proxy/internal/docker"
)

const (
	// maxInFlight bounds concurrent requests, event streams included, so a
	// compromised client cannot tie up the Docker daemon.
	maxInFlight = 32
	// requestTimeout applies to everything but the events stream.
	requestTimeout = 30 * time.Second
	// maxResponse bounds a single JSON response read from Docker.
	maxResponse = 16 << 20
)

// Every response carries these headers, so nginx-proxy can tell whether the
// socket proxy filters the same way it reads.
const (
	FilterHeader  = "X-Nginx-Proxy-Filter"
	VersionHeader = "X-Nginx-Proxy-Version"
)

// FilterID identifies what passes the filter: the container variables and
// the label prefix. Two versions with the same FilterID are interchangeable.
func FilterID(envKeys []string, labelPrefix string) string {
	keys := slices.Sorted(slices.Values(envKeys))
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n") + "\n\n" + labelPrefix))
	return hex.EncodeToString(sum[:6])
}

// containerRef is a container ID or name, as nginx-proxy passes them to
// inspect: no slashes, dots only after the first character.
var containerRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Handler forwards allowed requests to the Docker API.
type Handler struct {
	client      *http.Client
	base        string
	envKeys     map[string]bool
	labelPrefix string
	filterID    string
	version     string
	slots       chan struct{}
}

// New returns a Handler that forwards to dockerHost (DOCKER_HOST syntax).
// Only container environment variables named in envKeys, and labels that
// start with labelPrefix, are passed on. version is reported in
// VersionHeader.
func New(dockerHost string, envKeys []string, labelPrefix, version string) (*Handler, error) {
	client, base, err := docker.NewHTTP(dockerHost)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]bool, len(envKeys))
	for _, k := range envKeys {
		keys[k] = true
	}
	return &Handler{
		client:      client,
		base:        base,
		envKeys:     keys,
		labelPrefix: labelPrefix,
		filterID:    FilterID(envKeys, labelPrefix),
		version:     version,
		slots:       make(chan struct{}, maxInFlight),
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(FilterHeader, h.filterID)
	w.Header().Set(VersionHeader, h.version)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		deny(w, http.StatusMethodNotAllowed, r)
		return
	}
	// RawPath is set when the path contains escapes such as %2F, which
	// could hide a slash in a container reference.
	if r.URL.RawPath != "" || r.ContentLength > 0 {
		deny(w, http.StatusForbidden, r)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	path := r.URL.Path
	switch {
	case path == "/_ping" && onlyParams(r.URL.Query()):
		h.ping(w, r)
	case path == "/containers/json" && onlyParams(r.URL.Query(), "filters"):
		h.list(w, r)
	case path == "/events" && onlyParams(r.URL.Query(), "filters"):
		h.events(w, r)
	default:
		ref, ok := strings.CutPrefix(path, "/containers/")
		ref, ok2 := strings.CutSuffix(ref, "/json")
		if ok && ok2 && containerRef.MatchString(ref) && onlyParams(r.URL.Query()) {
			h.inspect(w, r, ref)
			return
		}
		deny(w, http.StatusForbidden, r)
	}
}

// onlyParams reports whether q has no parameters other than allowed, each
// given at most once. A "filters" value must be the JSON object Docker
// expects, so it cannot smuggle in anything else.
func onlyParams(q url.Values, allowed ...string) bool {
	for k, v := range q {
		if !slices.Contains(allowed, k) || len(v) != 1 {
			return false
		}
		if k == "filters" {
			var f map[string][]string
			if json.Unmarshal([]byte(v[0]), &f) != nil {
				return false
			}
		}
	}
	return true
}

func deny(w http.ResponseWriter, status int, r *http.Request) {
	slog.Warn("blocked Docker API request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	writeError(w, status, "blocked by nginx-proxy socket-proxy")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

// get sends a fresh GET to Docker: nothing from the client's request is
// forwarded but the parameters checked by onlyParams.
func (h *Handler) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	u := h.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return h.client.Do(req)
}

// forward sends the GET and returns the response if Docker answered 200. In
// every other case it has already answered the client.
func (h *Handler) forward(ctx context.Context, w http.ResponseWriter, path string, q url.Values) *http.Response {
	resp, err := h.get(ctx, path, q)
	if err != nil {
		slog.Error("Docker API request failed", "path", path, "err", err)
		writeError(w, http.StatusBadGateway, "Docker API unreachable")
		return nil
	}
	if resp.StatusCode == http.StatusOK {
		return resp
	}
	defer resp.Body.Close()
	// Pass on the status and Docker's message, but nothing else.
	var body struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
	msg := body.Message
	if len(msg) > 512 {
		msg = msg[:512]
	}
	writeError(w, resp.StatusCode, msg)
	return nil
}

func (h *Handler) ping(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	resp := h.forward(ctx, w, "/_ping", nil)
	if resp == nil {
		return
	}
	resp.Body.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "OK")
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	resp := h.forward(ctx, w, "/containers/json", r.URL.Query())
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	var summaries []struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&summaries); err != nil {
		writeError(w, http.StatusBadGateway, "unexpected response from Docker")
		return
	}
	writeJSON(w, summaries)
}

func (h *Handler) inspect(w http.ResponseWriter, r *http.Request, ref string) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	resp := h.forward(ctx, w, "/containers/"+ref+"/json", nil)
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	// Decoding into docker.Container keeps exactly the fields nginx-proxy
	// reads; everything else in Docker's response is dropped.
	var ctr docker.Container
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&ctr); err != nil {
		writeError(w, http.StatusBadGateway, "unexpected response from Docker")
		return
	}
	ctr.Config.Env = slices.DeleteFunc(ctr.Config.Env, func(kv string) bool {
		k, _, _ := strings.Cut(kv, "=")
		return !h.envKeys[k]
	})
	for k := range ctr.Config.Labels {
		if !strings.HasPrefix(k, h.labelPrefix) {
			delete(ctr.Config.Labels, k)
		}
	}
	writeJSON(w, &ctr)
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	resp := h.forward(r.Context(), w, "/events", r.URL.Query())
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	// Events carry every label of the container in Actor.Attributes; pass
	// on only what nginx-proxy reads.
	dec := json.NewDecoder(bufio.NewReader(resp.Body))
	enc := json.NewEncoder(w)
	for {
		var ev docker.Event
		if err := dec.Decode(&ev); err != nil {
			return
		}
		if err := enc.Encode(&ev); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
