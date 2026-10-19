package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/matfax/tunsel/internal/config"
)

// Probe describes a single probe of one target through one tunnel.
type Probe struct {
	Iface  string
	Mark   uint32
	Target netip.Addr
	Kind   config.ProbeKind
	Port   uint16
}

type Prober interface {
	// Probe returns the round-trip time, or an error if the target did not
	// answer before ctx expired.
	Probe(ctx context.Context, p Probe) (time.Duration, error)
}

// SocketProber sends probes from sockets bound to the tunnel device
// (SO_BINDTODEVICE) and carrying the tunnel's mark (SO_MARK). The mark
// selects the tunnel's routing table and makes the tool's output chain
// leave the probes alone.
type SocketProber struct{}

func (SocketProber) Probe(ctx context.Context, p Probe) (time.Duration, error) {
	if p.Kind == config.ProbeTCP {
		return probeTCP(ctx, p)
	}
	return probeICMP(ctx, p)
}

func bind(fd int, p Probe) error {
	if err := unix.BindToDevice(fd, p.Iface); err != nil {
		return fmt.Errorf("SO_BINDTODEVICE %s: %w", p.Iface, err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(p.Mark)); err != nil {
		return fmt.Errorf("SO_MARK: %w", err)
	}
	return nil
}

// probeTCP measures the handshake: the time until the connection is
// established or refused.
func probeTCP(ctx context.Context, p Probe) (time.Duration, error) {
	var serr error
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		if err := c.Control(func(fd uintptr) { serr = bind(int(fd), p) }); err != nil {
			return err
		}
		return serr
	}}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(p.Target, p.Port).String())
	rtt := time.Since(start)
	if err == nil {
		conn.Close()
		return rtt, nil
	}
	// A RST proves the path through the tunnel works.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return rtt, nil
	}
	return 0, err
}

func probeICMP(ctx context.Context, p Probe) (time.Duration, error) {
	proto := unix.IPPROTO_ICMP
	var echo, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if p.Target.Is6() {
		proto = unix.IPPROTO_ICMPV6
		echo, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	pc, err := icmpConn(p, proto)
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	if dl, ok := ctx.Deadline(); ok {
		pc.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { pc.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	var token [12]byte
	rand.Read(token[:])
	id, seq := int(binary.BigEndian.Uint16(token[:])), int(binary.BigEndian.Uint16(token[2:]))
	want := icmp.Echo{ID: id, Seq: seq, Data: token[:]}
	msg := icmp.Message{Type: echo, Body: &want}
	// The kernel fills in the ICMPv6 checksum on raw sockets.
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	dst := &net.IPAddr{IP: p.Target.AsSlice()}
	start := time.Now()
	if _, err := pc.WriteTo(b, dst); err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return 0, fmt.Errorf("no reply: %w", ctx.Err())
			}
			return 0, err
		}
		// net.IPConn already strips the IPv4 header of raw sockets.
		if isReply(buf[:n], from, p.Target, proto, reply, want) {
			return time.Since(start), nil
		}
	}
}

// icmpConn opens a raw ICMP socket for proto, bound as p requires.
func icmpConn(p Probe, proto int) (net.PacketConn, error) {
	family := unix.AF_INET
	if p.Target.Is6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	if err := bind(fd, p); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "icmp")
	defer f.Close()
	return net.FilePacketConn(f)
}

// isReply reports whether data, received from from, answers the echo want
// sent to target.
func isReply(data []byte, from net.Addr, target netip.Addr, proto int, reply icmp.Type, want icmp.Echo) bool {
	src, ok := netip.AddrFromSlice(from.(*net.IPAddr).IP)
	if !ok || src.Unmap() != target {
		return false
	}
	m, err := icmp.ParseMessage(proto, data)
	if err != nil || m.Type != reply {
		return false
	}
	e, ok := m.Body.(*icmp.Echo)
	return ok && e.ID == want.ID && e.Seq == want.Seq && bytes.Equal(e.Data, want.Data)
}
