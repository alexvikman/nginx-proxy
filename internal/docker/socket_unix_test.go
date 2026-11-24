//go:build unix

package docker

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSocketOpenTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	owner, group := st.Uid, st.Gid
	// Ids that are neither the file's owner nor its group.
	worker, otherGroup := owner+1, group+1

	cases := []struct {
		name string
		mode os.FileMode
		uid  uint32
		gids []uint32
		want bool
	}{
		{"root only", 0o600, worker, []uint32{otherGroup}, false},
		{"root and docker group", 0o660, worker, []uint32{otherGroup}, false},
		{"worker is in the socket's group", 0o660, worker, []uint32{otherGroup, group}, true},
		{"group may only read", 0o640, worker, []uint32{group}, false},
		{"world-writable", 0o666, worker, []uint32{otherGroup}, true},
		{"worker owns the socket", 0o600, owner, nil, true},
		// The owner class applies first, even when others could write.
		{"owner without write", 0o466, owner, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			open, known := socketOpenTo(path, tc.uid, tc.gids)
			if !known || open != tc.want {
				t.Fatalf("open = %v (known %v), want %v", open, known, tc.want)
			}
		})
	}

	if _, known := socketOpenTo(filepath.Join(t.TempDir(), "missing"), worker, nil); known {
		t.Error("a missing socket must be reported as unknown")
	}
	if _, known := SocketOpenTo(path, "no-such-user-nginx-proxy-test"); known {
		t.Error("an unknown user must be reported as unknown")
	}
}
