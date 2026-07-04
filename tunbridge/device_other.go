//go:build !linux

package tunbridge

import (
	"errors"
	"io"
)

// OpenDevice is Linux-only for now; other platforms run without the TUN
// bridge (modes A/B still apply).
func OpenDevice(name, cidr string, mtu int) (io.ReadWriteCloser, error) {
	return nil, errors.New("the TUN bridge is Linux-only for now")
}
