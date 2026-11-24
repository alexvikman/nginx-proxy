package proxy

import (
	"fmt"
	"log/slog"
	"sync"
)

// dedupe logs a warning when it first occurs and stays quiet for as long as
// it occurs again in every following round. Build runs on every Docker event
// and every resync; without this, a container that stays misconfigured would
// repeat the same warning forever.
type dedupe struct {
	mu        sync.Mutex
	prev, cur map[string]bool
	log       func(msg string, args ...any)
}

func (d *dedupe) warn(msg string, args ...any) {
	key := fmt.Sprintf("%s %v", msg, args)
	d.mu.Lock()
	seen := d.prev[key] || d.cur[key]
	if d.cur == nil {
		d.cur = map[string]bool{}
	}
	d.cur[key] = true
	d.mu.Unlock()
	if !seen {
		d.log(msg, args...)
	}
}

// rotate ends a round. A warning that did not occur in it is logged again
// when it comes back.
func (d *dedupe) rotate() {
	d.mu.Lock()
	d.prev, d.cur = d.cur, nil
	d.mu.Unlock()
}

var warnings = &dedupe{log: slog.Warn}

// warn logs a warning about the configuration being built; see dedupe.
func warn(msg string, args ...any) { warnings.warn(msg, args...) }
