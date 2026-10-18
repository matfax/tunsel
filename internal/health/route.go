package health

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// RouteCheck reports the output interface the kernel would pick for a
// packet to dst carrying mark — the equivalent of `ip route get <dst>
// mark <mark>`.
type RouteCheck func(dst netip.Addr, mark uint32) (iface string, err error)

// ErrNoRoute means the lookup found no route at all.
var ErrNoRoute = errors.New("no route")

// SysRouteCheck resolves the route via rtnetlink.
//
// Probes are bound to the tunnel device and would still get out if the
// tunnel's policy table lost its route (Linux deletes routes of a device
// when it goes down, and they may not come back); forwarded traffic would
// then fall through to other tables. This check makes such a tunnel
// unhealthy instead.
func SysRouteCheck(dst netip.Addr, mark uint32) (string, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return "", err
	}
	defer c.Close()

	family := byte(unix.AF_INET)
	if dst.Is6() {
		family = unix.AF_INET6
	}
	// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags(u32)
	rtm := []byte{family, byte(dst.BitLen()), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, dst.AsSlice())
	ae.Uint32(unix.RTA_MARK, mark)
	attrs, err := ae.Encode()
	if err != nil {
		return "", err
	}
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETROUTE, Flags: netlink.Request},
		Data:   append(rtm, attrs...),
	})
	if err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
			return "", ErrNoRoute
		}
		return "", err
	}
	for _, m := range msgs {
		if len(m.Data) < 12 {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[12:])
		if err != nil {
			return "", err
		}
		for ad.Next() {
			if ad.Type() == unix.RTA_OIF {
				ifi, err := net.InterfaceByIndex(int(ad.Uint32()))
				if err != nil {
					return "", err
				}
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("route lookup returned no output interface")
}
