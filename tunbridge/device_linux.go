//go:build linux

package tunbridge

import (
	"fmt"
	"io"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// OpenDevice creates and configures the kernel TUN device: address assigned,
// MTU set, link up. Assigning the CIDR address also installs the connected
// route for the overlay subnet. Needs CAP_NET_ADMIN (netlink is called
// in-process, so a file capability on the fabric binary is enough — no
// child processes involved).
func OpenDevice(name, cidr string, mtu int) (io.ReadWriteCloser, error) {
	ifce, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name},
	})
	if err != nil {
		return nil, fmt.Errorf("creating TUN device %s (needs CAP_NET_ADMIN or root): %w", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		ifce.Close()
		return nil, fmt.Errorf("looking up %s: %w", name, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		ifce.Close()
		return nil, fmt.Errorf("overlay address %q: %w", cidr, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		ifce.Close()
		return nil, fmt.Errorf("assigning %s to %s: %w", cidr, name, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		ifce.Close()
		return nil, fmt.Errorf("setting MTU on %s: %w", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		ifce.Close()
		return nil, fmt.Errorf("bringing %s up: %w", name, err)
	}
	return ifce, nil
}
