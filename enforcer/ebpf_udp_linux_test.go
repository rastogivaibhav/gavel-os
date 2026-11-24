//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Test only against receiver sockets on the disposable runner's loopback.
// The IPv6 alias is created by ipv6ProofListeners before this helper.
type udpProofPair struct {
	allowed, denied *net.UDPConn
}

func setupUDPProof(t *testing.T) []udpProofPair {
	t.Helper()
	t.Setenv("GAVEL_GUARD_UDP_PROBE", "1")
	var pairs []udpProofPair
	for _, tc := range []struct{ family, allowed, denied string }{
		{"4", "127.0.0.1", "127.0.0.2"},
		{"6", "::1", "fd00:6761:7665:6c::2"},
	} {
		listen := func(ip string) *net.UDPConn {
			s, err := net.ListenUDP("udp"+tc.family, &net.UDPAddr{IP: net.ParseIP(ip)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		}
		a, b := listen(tc.allowed), listen(tc.denied)
		t.Setenv("GAVEL_GUARD_UDP"+tc.family+"_ALLOW", a.LocalAddr().String())
		t.Setenv("GAVEL_GUARD_UDP"+tc.family+"_DENY", b.LocalAddr().String())
		pairs = append(pairs, udpProofPair{a, b})
	}
	return pairs
}

func udpSockaddr(t *testing.T, family, addr string) unix.Sockaddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp"+family, addr)
	if err != nil || a == nil || a.Port == 0 {
		t.Fatalf("invalid UDP proof address %q: %v", addr, err)
	}
	if family == "4" {
		sa := &unix.SockaddrInet4{Port: a.Port}
		copy(sa.Addr[:], a.IP.To4())
		return sa
	}
	sa := &unix.SockaddrInet6{Port: a.Port}
	copy(sa.Addr[:], a.IP.To16())
	return sa
}

// Raw direct syscalls, not an agent SDK or Go's connected UDP abstraction.
// Use separate, unconnected native IPv4/IPv6 sockets and test both send APIs.
func checkUDPProof(t *testing.T) {
	t.Helper()
	if os.Getenv("GAVEL_GUARD_UDP_PROBE") != "1" {
		return
	}
	for _, tc := range []struct{ family string; domain int }{
		{"4", unix.AF_INET}, {"6", unix.AF_INET6},
	} {
		allow := udpSockaddr(t, tc.family, os.Getenv("GAVEL_GUARD_UDP"+tc.family+"_ALLOW"))
		deny := udpSockaddr(t, tc.family, os.Getenv("GAVEL_GUARD_UDP"+tc.family+"_DENY"))
		fd, err := unix.Socket(tc.domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if tc.domain == unix.AF_INET6 {
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
				t.Fatal(err)
			}
		}
		for _, send := range []struct {
			name string
			call func(unix.Sockaddr, []byte) error
		}{
			{"sendto", func(sa unix.Sockaddr, payload []byte) error {
				return unix.Sendto(fd, payload, 0, sa)
			}},
			{"sendmsg", func(sa unix.Sockaddr, payload []byte) error {
				n, err := unix.SendmsgN(fd, payload, nil, sa, 0)
				if err == nil && n != len(payload) {
					t.Fatalf("short UDP sendmsg: %d", n)
				}
				return err
			}},
		} {
			if err := send.call(allow, []byte("allowed-"+send.name)); err != nil {
				t.Fatalf("UDP%s %s permitted syscall failed: %v", tc.family, send.name, err)
			}
			if err := send.call(deny, []byte("FORBIDDEN-"+send.name)); !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
				t.Fatalf("SECURITY FAILURE: UDP%s %s expected kernel EPERM/EACCES, got %v", tc.family, send.name, err)
			}
			t.Logf("KERNEL PROBE: UDP%s %s allowed control and forbidden errno", tc.family, send.name)
		}
	}
}

// Positive proof checks actual packet receipt, not just a successful send.
// Negative proof checks a bound receiver never saw the forbidden payload.
func assertUDPReceivers(t *testing.T, pairs []udpProofPair, probes int) {
	t.Helper()
	for i, pair := range pairs {
		want := map[string]int{"allowed-sendto": probes, "allowed-sendmsg": probes}
		buf := make([]byte, 256)
		if err := pair.allowed.SetReadDeadline(time.Now().Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < probes*2; j++ {
			n, _, err := pair.allowed.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("family %d missing allowed datagram: %v", i, err)
			}
			want[string(buf[:n])]--
		}
		for payload, count := range want {
			if count != 0 {
				t.Fatalf("family %d unexpected received payload count %q=%d", i, payload, count)
			}
		}
		if err := pair.denied.SetReadDeadline(time.Now().Add(200*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, _, err := pair.denied.ReadFromUDP(buf)
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("SECURITY FAILURE: family %d forbidden receiver observed n=%d err=%v", i, n, err)
		}
		t.Logf("KERNEL PROOF: %s received %d allowed datagrams; %s received none", pair.allowed.LocalAddr(), probes*2, pair.denied.LocalAddr())
	}
}
