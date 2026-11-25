package proxy

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// TestContainerEnvIsComplete fails when the model starts reading a container
// variable that ContainerEnv does not list: behind the socket proxy, that
// variable would silently be empty.
func TestContainerEnvIsComplete(t *testing.T) {
	src, err := os.ReadFile("model.go")
	if err != nil {
		t.Fatal(err)
	}
	// env["X"], envOr(e, "X", ...), parseBool(e, "X", ...) and the key
	// lists in validateContainer.
	re := regexp.MustCompile(`(?:env\["|(?:envOr|parseBool)\([a-z.]+, ")([A-Z][A-Z0-9_]+)"|"((?:VIRTUAL|LETSENCRYPT|EXTERNAL)_[A-Z0-9_]+)"`)
	found := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		key := m[1] + m[2]
		found++
		if !slices.Contains(ContainerEnv, key) {
			t.Errorf("model.go reads container variable %s, which ContainerEnv does not list", key)
		}
	}
	if found < len(ContainerEnv) {
		t.Fatalf("found only %d reads of container variables; has the code changed shape?", found)
	}
}
