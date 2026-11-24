// Package nginx runs the nginx master process and applies new configurations
// safely: a configuration that fails `nginx -t` is rolled back and never
// reaches the running server.
package nginx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Server manages one nginx master process.
type Server struct {
	Bin      string // nginx binary
	ConfPath string // generated config file, e.g. /etc/nginx/conf.d/default.conf

	cmd         *exec.Cmd
	done        chan error
	fingerprint string
}

// Apply writes conf to ConfPath, checks the full nginx configuration and
// reloads nginx when it is running. Nothing happens when both conf and the
// state of the files it references (fingerprint, see Fingerprint) are
// unchanged. On a failed check the previous file is restored and the error
// is a *CheckError with nginx's output.
func (s *Server) Apply(conf []byte, fingerprint string) (changed bool, err error) {
	old, readErr := os.ReadFile(s.ConfPath)
	confSame := readErr == nil && bytes.Equal(old, conf)
	if confSame && fingerprint == s.fingerprint {
		return false, nil
	}
	if !confSame {
		if err := writeAtomic(s.ConfPath, conf); err != nil {
			return false, err
		}
	}
	if err := s.test(); err != nil {
		if !confSame {
			s.restore(old, readErr)
		}
		return false, err
	}
	s.fingerprint = fingerprint
	if s.cmd != nil {
		if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
			return true, fmt.Errorf("reload nginx: %w", err)
		}
	}
	return true, nil
}

// CheckError is returned when nginx -t rejects a configuration. Output is
// nginx's own message.
type CheckError struct{ Output string }

func (e *CheckError) Error() string {
	return "nginx -t rejected the configuration, keeping the running one: " + e.Output
}

// Check reports whether nginx would accept conf in place of the current
// file, without applying it: the current file is put back either way.
func (s *Server) Check(conf []byte) error {
	old, readErr := os.ReadFile(s.ConfPath)
	if err := writeAtomic(s.ConfPath, conf); err != nil {
		return err
	}
	defer s.restore(old, readErr)
	return s.test()
}

// test runs nginx -t against the files currently on disk.
func (s *Server) test() error {
	if out, err := exec.Command(s.Bin, "-t", "-q").CombinedOutput(); err != nil {
		return &CheckError{Output: strings.TrimSpace(string(out))}
	}
	return nil
}

// restore puts back what ReadFile returned for ConfPath before it was
// overwritten.
func (s *Server) restore(old []byte, readErr error) {
	if readErr == nil {
		_ = writeAtomic(s.ConfPath, old)
	} else {
		_ = os.Remove(s.ConfPath)
	}
}

// Fingerprint summarises the size and modification time of files, so that a
// renewed certificate or an edited include file triggers a reload.
func Fingerprint(files []string) string {
	h := sha256.New()
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			fmt.Fprintf(h, "%s missing\n", f)
			continue
		}
		fmt.Fprintf(h, "%s %d %d\n", f, fi.Size(), fi.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Start launches nginx in the foreground. Done reports when it exits.
func (s *Server) Start() error {
	if s.cmd != nil {
		return errors.New("nginx already started")
	}
	cmd := exec.Command(s.Bin, "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start nginx: %w", err)
	}
	s.cmd = cmd
	s.done = make(chan error, 1)
	go func() { s.done <- cmd.Wait() }()
	return nil
}

// Done is closed with nginx's exit status when the master process exits.
func (s *Server) Done() <-chan error { return s.done }

// Stop asks nginx to shut down gracefully (SIGQUIT) and waits for it.
func (s *Server) Stop() error {
	if s.cmd == nil {
		return nil
	}
	_ = s.cmd.Process.Signal(syscall.SIGQUIT)
	return <-s.done
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".nginx-proxy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
