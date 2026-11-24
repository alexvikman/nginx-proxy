//go:build !unix

package docker

// SocketOpenTo cannot tell on platforms without unix file permissions.
func SocketOpenTo(path, username string) (open, known bool) { return false, false }
