// Package docker is a minimal client for the Docker Engine API.
//
// It implements only the handful of endpoints nginx-proxy needs (list,
// inspect, events), which keeps the dependency tree to the Go standard
// library.
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Client talks to the Docker Engine API over a unix socket or plain TCP.
type Client struct {
	http *http.Client
	base string
}

// New creates a client for host, which uses the DOCKER_HOST syntax
// (unix:///path/to/docker.sock or tcp://host:port).
func New(host string) (*Client, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parse docker host %q: %w", host, err)
	}
	switch u.Scheme {
	case "unix":
		socket := u.Path
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		}
		return &Client{http: &http.Client{Transport: tr}, base: "http://docker"}, nil
	case "tcp", "http":
		return &Client{http: &http.Client{}, base: "http://" + u.Host}, nil
	default:
		return nil, fmt.Errorf("unsupported docker host scheme %q (use unix:// or tcp://)", u.Scheme)
	}
}

// Container is the subset of the container inspect response that nginx-proxy uses.
type Container struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Env          []string            `json:"Env"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]Endpoint `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Endpoint describes a container's attachment to one network.
type Endpoint struct {
	NetworkID         string `json:"NetworkID"`
	IPAddress         string `json:"IPAddress"`
	GlobalIPv6Address string `json:"GlobalIPv6Address"`
	Gateway           string `json:"Gateway"`
}

// Env returns the container's environment as a map. Later entries win.
func (c *Container) Env() map[string]string {
	env := make(map[string]string, len(c.Config.Env))
	for _, kv := range c.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}

// ShortName returns the container name without the leading slash.
func (c *Container) ShortName() string { return strings.TrimPrefix(c.Name, "/") }

// Event is a message from the Docker events stream.
type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID string `json:"ID"`
	} `json:"Actor"`
}

func (c *Client) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	return resp, nil
}

// APIError is a non-200 response from the Engine API.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("docker api: %d %s", e.Status, e.Message) }

// IsNotFound reports whether err is a 404 from the Engine API.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.get(ctx, path, q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// Ping checks that the daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.get(ctx, "/_ping", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// RunningContainers lists running containers matching filters and inspects each one.
func (c *Client) RunningContainers(ctx context.Context, filters map[string][]string) ([]*Container, error) {
	q := url.Values{}
	if len(filters) > 0 {
		f, err := json.Marshal(filters)
		if err != nil {
			return nil, err
		}
		q.Set("filters", string(f))
	}
	var summaries []struct {
		ID string `json:"Id"`
	}
	if err := c.getJSON(ctx, "/containers/json", q, &summaries); err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	out := make([]*Container, 0, len(summaries))
	for _, s := range summaries {
		ctr, err := c.Inspect(ctx, s.ID)
		if IsNotFound(err) {
			continue // removed between list and inspect
		}
		if err != nil {
			return nil, err
		}
		if ctr.State.Running {
			out = append(out, ctr)
		}
	}
	return out, nil
}

// Inspect returns the details of one container.
func (c *Client) Inspect(ctx context.Context, id string) (*Container, error) {
	var ctr Container
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &ctr); err != nil {
		return nil, fmt.Errorf("inspect container %s: %w", id, err)
	}
	return &ctr, nil
}

// Events streams container and network events until ctx is cancelled or the
// connection drops. fn is called for each event.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	filters, _ := json.Marshal(map[string][]string{
		"type":  {"container", "network"},
		"event": {"start", "die", "destroy", "pause", "unpause", "connect", "disconnect"},
	})
	q := url.Values{"filters": {string(filters)}}
	resp, err := c.get(ctx, "/events", q)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(bufio.NewReader(resp.Body))
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("events stream: %w", err)
		}
		fn(ev)
	}
}

// ParseFilters parses DOCKER_CONTAINER_FILTERS ("key=value,key=value").
func ParseFilters(s string) map[string][]string {
	out := map[string][]string{}
	for part := range strings.SplitSeq(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || k == "" {
			continue
		}
		out[k] = append(out[k], v)
	}
	return out
}

var containerIDInMount = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// SelfID returns the ID of the container this process runs in, or "" when it
// cannot be determined (e.g. when running outside Docker).
func SelfID(ctx context.Context, c *Client) string {
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		if m := containerIDInMount.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctr, err := c.Inspect(ctx, host)
	if err != nil {
		return ""
	}
	return ctr.ID
}
