// Regression tests for the SSU2 NAT bind fallback.
//
// A NAT port mapping improves reachability but is never a precondition for
// listening. Before this fix, createUDPConn propagated the NAT error on both
// the OS-assigned and explicit-port branches, so NewSSU2Transport failed on any
// host without working UPnP/NAT-PMP and the router silently ran without SSU2.
// Both branches now share bindPacketConnWithFallback, mirroring NTCP2.

package ssu2

import (
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/go-i2p/go-i2p/lib/nat"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errNATUnavailable simulates a host with no usable UPnP/NAT-PMP mapping.
var errNATUnavailable = errors.New("no NAT gateway available")

// forceNATFailure makes both NAT seams fail for the duration of the test.
func forceNATFailure(t *testing.T) {
	t.Helper()

	origProbe := probeAndBindNATPacket
	origPort := bindNATWithPortPacket
	t.Cleanup(func() {
		probeAndBindNATPacket = origProbe
		bindNATWithPortPacket = origPort
	})

	probeAndBindNATPacket = func(*nat.BindConfig) (*nat.BindResult, error) {
		return nil, errNATUnavailable
	}
	bindNATWithPortPacket = func(*nat.BindConfig) (*nat.BindResult, error) {
		return nil, errNATUnavailable
	}
}

func newFallbackTestTransport(t *testing.T) *SSU2Transport {
	t.Helper()
	return &SSU2Transport{logger: logger.WithField("test", t.Name())}
}

func TestBindPacketConnWithFallback_OSAssignedPortNATFailure(t *testing.T) {
	forceNATFailure(t)

	transport := newFallbackTestTransport(t)
	config := &Config{ListenerAddress: ":0"}

	// Port 0 is the default configuration and used to be the failing path.
	conn, boundAddr, err := bindPacketConnWithFallback(transport, config, 0)
	require.NoError(t, err, "NAT failure must not prevent binding on an OS-assigned port")
	require.NotNil(t, conn)
	defer func() { _ = conn.Close() }()

	require.NotEmpty(t, boundAddr, "the fallback must report the address it actually bound")

	_, portStr, splitErr := net.SplitHostPort(boundAddr)
	require.NoError(t, splitErr)
	assert.NotEqual(t, "0", portStr, "an OS-assigned port must be resolved to a real port number")

	// The connection must be usable, i.e. a live socket rather than a stub.
	addr, resolveErr := net.ResolveUDPAddr("udp", boundAddr)
	require.NoError(t, resolveErr)
	_, writeErr := conn.WriteTo([]byte("probe"), addr)
	require.NoError(t, writeErr, "the fallback connection must be able to send datagrams")
}

func TestBindPacketConnWithFallback_ExplicitPortNATFailure(t *testing.T) {
	forceNATFailure(t)

	transport := newFallbackTestTransport(t)
	config := &Config{ListenerAddress: ":0"}

	// An explicit port keeps that port when falling back, as NTCP2 does.
	const requested = 42069
	conn, boundAddr, err := bindPacketConnWithFallback(transport, config, requested)
	if errors.Is(err, errNATUnavailable) {
		// The NAT error reached the caller, which means no fallback ran.
		require.NoError(t, err, "NAT failure must not propagate when a plain bind is possible")
	}
	if err != nil {
		// Any other error is the plain bind itself failing (e.g. the port is
		// already taken on a busy host), which is an environment limit rather
		// than a regression in the NAT handling.
		t.Skipf("plain bind on port %d failed, which is unrelated to NAT fallback: %v", requested, err)
	}
	require.NotNil(t, conn)
	defer func() { _ = conn.Close() }()

	_, portStr, splitErr := net.SplitHostPort(boundAddr)
	require.NoError(t, splitErr)
	assert.Equal(t, "42069", portStr, "the fallback must keep the explicitly requested port")
}

func TestBindPacketConnWithFallback_NATSuccessPathUnchanged(t *testing.T) {
	// When NAT succeeds, its connection and bound address are used as-is and
	// the plain fallback is never reached.
	origProbe := probeAndBindNATPacket
	origPort := bindNATWithPortPacket
	t.Cleanup(func() {
		probeAndBindNATPacket = origProbe
		bindNATWithPortPacket = origPort
	})

	fakeConn, err := net.ListenPacket("udp", ":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = fakeConn.Close() })

	fakeResult := &nat.BindResult{PacketConn: fakeConn, BoundAddress: fakeConn.LocalAddr().String()}
	probeAndBindNATPacket = func(*nat.BindConfig) (*nat.BindResult, error) { return fakeResult, nil }
	bindNATWithPortPacket = func(*nat.BindConfig) (*nat.BindResult, error) { return fakeResult, nil }

	transport := newFallbackTestTransport(t)
	config := &Config{ListenerAddress: ":0"}

	conn, boundAddr, err := bindPacketConnWithFallback(transport, config, 0)
	require.NoError(t, err)
	assert.Same(t, fakeConn, conn, "the NAT-provided connection must be returned untouched")
	assert.Equal(t, fakeConn.LocalAddr().String(), boundAddr)

	conn2, boundAddr2, err := bindPacketConnWithFallback(transport, config, 9002)
	require.NoError(t, err)
	assert.Same(t, fakeConn, conn2, "the explicit-port NAT path must also honour a successful bind")
	assert.Equal(t, fakeConn.LocalAddr().String(), boundAddr2)
}

// TestBindPlainUDPConn_PreservesHostAndFamily pins the address reconstruction
// the fallback relies on: wildcard, IPv4 and IPv6 hosts must all bind the
// requested port, with brackets kept for IPv6.
func TestBindPlainUDPConn_PreservesHostAndFamily(t *testing.T) {
	cases := []struct {
		name        string
		address     string
		port        int
		wantHost    string
		wantAnyHost bool
	}{
		// A wildcard UDP bind is normalised by the OS to the unspecified
		// dual-stack address rather than reported as an empty host.
		{name: "wildcard", address: ":0", port: 0, wantAnyHost: true},
		{name: "explicit_port_wildcard", address: ":0", port: 42070, wantAnyHost: true},
		{name: "ipv4_loopback", address: "127.0.0.1:0", port: 42071, wantHost: "127.0.0.1"},
		{name: "ipv6_loopback", address: "[::1]:0", port: 42072, wantHost: "::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, boundAddr, err := bindPlainUDPConn(tc.address, tc.port)
			if err != nil {
				t.Skipf("cannot bind %s on this host: %v", tc.address, err)
			}
			defer func() { _ = conn.Close() }()

			host, portStr, splitErr := net.SplitHostPort(boundAddr)
			require.NoError(t, splitErr)

			if tc.wantAnyHost {
				ip := net.ParseIP(host)
				assert.True(t, host == "" || (ip != nil && ip.IsUnspecified()),
					"a wildcard bind must stay unspecified, got %q", host)
			} else {
				assert.Equal(t, tc.wantHost, host, "the listener host must be preserved")
			}

			if tc.port != 0 {
				assert.Equal(t, strconv.Itoa(tc.port), portStr, "the requested port must be kept")
			} else {
				assert.NotEqual(t, "0", portStr, "an OS-assigned port must be resolved")
			}
		})
	}
}
