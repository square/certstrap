//go:build !windows
// +build !windows

package depot

var (
	tag  = &Tag{"host.pem", 0600}
	tag2 = &Tag{"host2.pem", 0600}
)
