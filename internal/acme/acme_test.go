package acme

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		1: 10 * time.Minute,
		2: 20 * time.Minute,
		8: 1280 * time.Minute,
		9: maxBackoff,
	} {
		if got := backoff(failures); got != want {
			t.Errorf("backoff(%d) = %v, want %v", failures, got, want)
		}
	}
	// A domain can keep failing for months; the wait must never shrink.
	prev := time.Duration(0)
	for failures := 1; failures <= 1000; failures++ {
		got := backoff(failures)
		if got < prev || got < minBackoff || got > maxBackoff {
			t.Fatalf("backoff(%d) = %v after %v", failures, got, prev)
		}
		prev = got
	}
}
