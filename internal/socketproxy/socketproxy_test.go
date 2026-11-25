package socketproxy

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/alexvikman/nginx-proxy/internal/docker"
)

const inspectBody = `{
  "Id": "abc123",
  "Name": "/app",
  "Config": {
    "Env": ["VIRTUAL_HOST=app.test", "DB_PASSWORD=hunter2", "PATH=/usr/bin", "VIRTUAL_PORT=8080"],
    "Labels": {"com.github.nginx-proxy.nginx-proxy.keepalive": "4", "com.example.secret": "s3cr3t"},
    "ExposedPorts": {"8080/tcp": {}}
  },
  "State": {"Running": true},
  "HostConfig": {"NetworkMode": "web", "Binds": ["/:/host"]},
  "Mounts": [{"Source": "/etc/shadow"}],
  "NetworkSettings": {"Networks": {"web": {"NetworkID": "n1", "IPAddress": "172.20.0.3", "Gateway": "172.20.0.1"}}}
}`

// recorder holds the requests that reached the fake Docker daemon.
type recorder struct {
	mu   sync.Mutex
	reqs []string
}

func (r *recorder) add(s string) { r.mu.Lock(); r.reqs = append(r.reqs, s); r.mu.Unlock() }

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reqs...)
}

// fakeDocker records the requests it gets and answers like the Engine API.
func fakeDocker(t *testing.T) (*httptest.Server, *recorder) {
	t.Helper()
	seen := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.add(r.Method + " " + r.URL.RequestURI())
		switch r.URL.Path {
		case "/_ping":
			io.WriteString(w, "OK")
		case "/containers/json":
			// Filters on "route=no" match nothing; any others match app.
			if strings.Contains(r.URL.Query().Get("filters"), "route=no") {
				io.WriteString(w, `[]`)
				return
			}
			io.WriteString(w, `[{"Id":"abc123","Names":["/app"],"Labels":{"com.example.secret":"s3cr3t"}}]`)
		case "/containers/peer/json":
			// A container on the socket proxy's network, like nginx-proxy.
			io.WriteString(w, `{"Id":"peer456","Name":"/peer","State":{"Running":true},"NetworkSettings":{"Networks":{"docker-api":{"NetworkID":"n-api"}}}}`)
		case "/containers/sp/json":
			io.WriteString(w, `{"Id":"sp789","Name":"/socket-proxy","State":{"Running":true},"NetworkSettings":{"Networks":{"docker-api":{"NetworkID":"n-api"}}}}`)
		case "/containers/abc123/json":
			io.WriteString(w, inspectBody)
		case "/containers/gone/json":
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"message":"No such container: gone"}`)
		case "/events":
			w.(http.Flusher).Flush()
			io.WriteString(w, `{"Type":"container","Action":"start","Actor":{"ID":"abc123","Attributes":{"com.example.secret":"s3cr3t","image":"app"}}}`+"\n")
			io.WriteString(w, `{"Type":"network","Action":"connect","Actor":{"ID":"n1","Attributes":{"container":"abc123"}}}`+"\n")
		default:
			t.Errorf("request reached Docker: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// newProxy starts a socket proxy in front of a fake Docker daemon. filters
// is its DOCKER_CONTAINER_FILTERS.
func newProxy(t *testing.T, filters map[string][]string) (*httptest.Server, *recorder) {
	t.Helper()
	return newProxyWith(t, Options{ContainerFilters: filters})
}

func newProxyWith(t *testing.T, o Options) (*httptest.Server, *recorder) {
	t.Helper()
	docker, seen := fakeDocker(t)
	o.EnvKeys = []string{"VIRTUAL_HOST", "VIRTUAL_PORT"}
	o.LabelPrefix = "com.github.nginx-proxy.nginx-proxy."
	o.Version = "1.2.3"
	h, err := New("tcp://"+strings.TrimPrefix(docker.URL, "http://"), o)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestTheClientWorksThroughTheProxy(t *testing.T) {
	srv, _ := newProxy(t, map[string][]string{"label": {"proxy=yes"}})
	cli, err := docker.New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	hdr, err := cli.Ping(ctx)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if hdr.Get(FilterHeader) != FilterID([]string{"VIRTUAL_PORT", "VIRTUAL_HOST"}, "com.github.nginx-proxy.nginx-proxy.") || hdr.Get(VersionHeader) != "1.2.3" {
		t.Fatalf("ping must identify the filter and version, got %v", hdr)
	}
	ctrs, err := cli.RunningContainers(ctx, map[string][]string{"label": {"proxy=yes"}})
	if err != nil || len(ctrs) != 1 {
		t.Fatalf("list: %v %v", ctrs, err)
	}
	c := ctrs[0]
	if c.ID != "abc123" || c.ShortName() != "app" || !c.State.Running || c.HostConfig.NetworkMode != "web" ||
		c.NetworkSettings.Networks["web"].IPAddress != "172.20.0.3" || len(c.Config.ExposedPorts) != 1 {
		t.Fatalf("fields nginx-proxy reads were lost: %+v", c)
	}
	env := c.Env()
	if env["VIRTUAL_HOST"] != "app.test" || env["VIRTUAL_PORT"] != "8080" {
		t.Fatalf("allowed variables were lost: %v", env)
	}
	if _, err := cli.Inspect(ctx, "gone"); !docker.IsNotFound(err) {
		t.Fatalf("a 404 must reach the client as one, got %v", err)
	}
}

func TestSecretsAreStripped(t *testing.T) {
	srv, _ := newProxy(t, nil)
	for _, path := range []string{"/containers/json", "/containers/abc123/json"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		for _, secret := range []string{"hunter2", "DB_PASSWORD", "PATH=", "s3cr3t", "/etc/shadow", "Binds", "Mounts"} {
			if strings.Contains(string(body), secret) {
				t.Errorf("%s passes on %q: %s", path, secret, body)
			}
		}
	}
	if !strings.Contains(fetch(t, srv.URL+"/containers/abc123/json"), "com.github.nginx-proxy.nginx-proxy.keepalive") {
		t.Error("nginx-proxy labels must be passed on")
	}
}

func fetch(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestEventsCarryOnlyWhatIsRead(t *testing.T) {
	srv, seen := newProxy(t, nil)
	// The client's own filters, in another order: accepted.
	resp, err := http.Get(srv.URL + `/events?filters={"event":["start","die","destroy","pause","unpause","connect","disconnect"],"type":["network","container"]}`)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 events, got %q", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "Attributes") || strings.Contains(l, "s3cr3t") {
			t.Errorf("event passes on attributes: %s", l)
		}
	}
	var ev docker.Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil || ev.Type != "container" || ev.Action != "start" || ev.Actor.ID != "abc123" {
		t.Fatalf("event fields were lost: %s", lines[0])
	}
	got := seen.all()
	if len(got) != 1 {
		t.Fatalf("want one events request at Docker, got %v", got)
	}
	u, _ := url.ParseRequestURI(strings.TrimPrefix(got[0], "GET "))
	if f := u.Query().Get("filters"); f != canonicalFilters(docker.EventFilters()) {
		t.Errorf("Docker must get the fixed event filters, got %q", f)
	}
}

func TestOtherRequestsAreBlocked(t *testing.T) {
	srv, seen := newProxy(t, nil)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/containers/create"},
		{"POST", "/containers/abc123/start"},
		{"DELETE", "/containers/abc123"},
		{"POST", "/containers/abc123/exec"},
		{"GET", "/containers/abc123/logs"},
		{"GET", "/containers/abc123/archive?path=/etc"},
		{"GET", "/containers/abc123/export"},
		{"GET", "/info"},
		{"GET", "/version"},
		{"GET", "/secrets"},
		{"GET", "/v1.47/containers/json"},
		{"GET", "/containers/json?all=1"},
		{"GET", "/containers/json?filters=x"},
		{"GET", "/containers/json?filters={}&filters={}"},
		// Filters would reveal stripped labels and images one guess at a time.
		{"GET", `/containers/json?filters={"label":["com.example.secret=s3cr3t"]}`},
		{"GET", `/containers/json?filters={"ancestor":["registry.example/app"]}`},
		{"GET", `/events?filters={"label":["com.example.secret=s3cr3t"]}`},
		{"GET", `/events?filters={"type":["container"]}`},
		{"GET", "/containers/abc123/json?size=1"},
		{"GET", "/containers/../info"},
		{"GET", "/containers/abc%2F..%2F..%2Finfo/json"},
		{"GET", "/containers/.hidden/json"},
		{"GET", "/containers//json"},
		{"GET", "/events?since=0&until=1"},
	} {
		req, err := http.NewRequest(tc.method, srv.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, want it blocked", tc.method, tc.path, resp.StatusCode)
		}
	}
	if got := seen.all(); len(got) != 0 {
		t.Errorf("blocked requests reached Docker: %v", got)
	}
}

func TestTheSocketProxyChoosesTheFilters(t *testing.T) {
	srv, seen := newProxy(t, map[string][]string{"label": {"b=2", "a=1"}})
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", http.StatusOK},
		{`?filters={"label":["a=1","b=2"]}`, http.StatusOK},
		{`?filters={"label":["a=1"]}`, http.StatusForbidden},
		{`?filters={"label":["a=1","b=2"],"name":["x"]}`, http.StatusForbidden},
	} {
		resp, err := http.Get(srv.URL + "/containers/json" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("list%s: got %d, want %d", tc.query, resp.StatusCode, tc.want)
		}
	}
	got := seen.all()
	if len(got) != 2 {
		t.Fatalf("want 2 lists to reach Docker, got %v", got)
	}
	for _, r := range got {
		u, _ := url.ParseRequestURI(strings.TrimPrefix(r, "GET "))
		if f := u.Query().Get("filters"); f != `{"label":["a=1","b=2"]}` {
			t.Errorf("Docker must get the socket proxy's filters, got %q", f)
		}
	}
}

func TestInspectFollowsTheFilters(t *testing.T) {
	excluding := map[string][]string{"label": {"route=no"}}
	status := func(srv *httptest.Server, ref string) int {
		resp, err := http.Get(srv.URL + "/containers/" + ref + "/json")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, tc := range []struct {
		name      string
		o         Options
		app, peer int
	}{
		{"no filters", Options{}, 200, 200},
		{"app matches, peer does not", Options{ContainerFilters: map[string][]string{"label": {"route=yes"}}}, 200, 404},
		{"excluded, own container unknown", Options{ContainerFilters: excluding}, 404, 404},
		// nginx-proxy shares the socket proxy's network, so it can still
		// inspect itself when the filters exclude it.
		{"excluded, peer on the socket proxy's network", Options{ContainerFilters: excluding, SelfID: "sp"}, 404, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newProxyWith(t, tc.o)
			if got := status(srv, "abc123"); got != tc.app {
				t.Errorf("app: got %d, want %d", got, tc.app)
			}
			if got := status(srv, "peer"); got != tc.peer {
				t.Errorf("peer: got %d, want %d", got, tc.peer)
			}
		})
	}

	// The visibility check lists stopped containers too, with the socket
	// proxy's filters.
	srv, seen := newProxyWith(t, Options{ContainerFilters: excluding})
	status(srv, "abc123")
	var list string
	for _, r := range seen.all() {
		if strings.Contains(r, "/containers/json") {
			list = r
		}
	}
	u, _ := url.ParseRequestURI(strings.TrimPrefix(list, "GET "))
	if u == nil || u.Query().Get("all") != "1" || u.Query().Get("filters") != `{"label":["route=no"]}` {
		t.Errorf("unexpected visibility check %q", list)
	}
}
