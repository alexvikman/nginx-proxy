//go:build unix

package docker

import (
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"
)

// SocketOpenTo reports whether the named user can connect to the unix socket
// at path, going by the socket's owner, group and mode. known is false when
// that cannot be told, for instance because the user does not exist.
//
// The Docker API amounts to root on the host, so the socket should only be
// open to the proxy itself and not to the user the nginx workers run as.
func SocketOpenTo(path, username string) (open, known bool) {
	u, err := user.Lookup(username)
	if err != nil {
		return false, false
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return false, false
	}
	groups, err := u.GroupIds()
	if err != nil {
		return false, false
	}
	var gids []uint32
	for _, g := range append(groups, u.Gid) {
		if gid, err := strconv.ParseUint(g, 10, 32); err == nil {
			gids = append(gids, uint32(gid))
		}
	}
	return socketOpenTo(path, uint32(uid), gids)
}

func socketOpenTo(path string, uid uint32, gids []uint32) (open, known bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	// Connecting takes write permission, from the first class that applies.
	perm := fi.Mode().Perm()
	switch {
	case st.Uid == uid:
		return perm&0o200 != 0, true
	case slices.Contains(gids, st.Gid):
		return perm&0o020 != 0, true
	default:
		return perm&0o002 != 0, true
	}
}
