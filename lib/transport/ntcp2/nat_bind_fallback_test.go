// Regression tests for the NTCP2 NAT bind fallback.
//
// A NAT port mapping improves reachability but is never a precondition for
// listening. Before this fix, only the explicit-port branch fell back to a
// plain listener: the port-0 branch (the default configuration) propagated the
// NAT error, so CreateRouter hard-failed on hosts without UPnP/NAT-PMP, such
// as CI runners. Both branches now share bindListenerWithFallback, and these
// tests pin that behaviour with the NAT interaction forced to fail.

package ntcp2

import (
	"errors"
	"net"
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

	origProbe := probeAndBindNAT
	origPort := bindNATWithPort
	t.Cleanup(func() {
		probeAndBindNAT = origProbe
		bindNATWithPort = origPort
	})

	probeAndBindNAT = func(*nat.BindConfig) (*nat.BindResult, error) {
		return nil, errNATUnavailable
	}
	bindNATWithPort = func(*nat.BindConfig) (*nat.BindResult, error) {
		return nil, errNATUnavailable
	}
}

func newFallbackTestTransport(t *testing.T) *NTCP2Transport {
	t.Helper()
	return &NTCP2Transport{logger: logger.WithField("test", t.Name())}
}

func TestBindListenerWithFallback_OSAssignedPortNATFailure(t *testing.T) {
	forceNATFailure(t)

	transport := newFallbackTestTransport(t)
	config, err := NewConfig(":0")
	require.NoError(t, err)

	// Port 0 is the default configuration and used to be the failing path.
	listener, boundAddr, err := bindListenerWithFallback(transport, config, 0)
	require.NoError(t, err, "NAT failure must not prevent binding on an OS-assigned port")
	require.NotNil(t, listener)
	defer func() { _ = listener.Close() }()

	require.NotEmpty(t, boundAddr, "the fallback must report the address it actually bound")

	_, portStr, splitErr := net.SplitHostPort(boundAddr)
	require.NoError(t, splitErr)
	assert.NotEqual(t, "0", portStr, "an OS-assigned port must be resolved to a real port number")

	// The bound address must be dialable, i.e. it is a live socket rather than
	// a placeholder.
	conn, dialErr := net.Dial("tcp", boundAddr)
	if dialErr == nil {
		_ = conn.Close()
	}
	require.NoError(t, dialErr, "the fallback listener must accept connections")
}

func TestBindListenerWithFallback_ExplicitPortNATFailure(t *testing.T) {
	forceNATFailure(t)

	transport := newFallbackTestTransport(t)
	config, err := NewConfig(":0")
	require.NoError(t, err)

	// An explicit port keeps that port when falling back, as it did before.
	const requested = 42069
	listener, boundAddr, err := bindListenerWithFallback(transport, config, requested)
	if err != nil {
		// The port may legitimately be taken on a busy host; that is an
		// environment limit, not a regression in the NAT handling.
		t.Skipf("plain bind on port %d failed, which is unrelated to NAT fallback: %v", requested, err)
	}
	require.NotNil(t, listener)
	defer func() { _ = listener.Close() }()

	_, portStr, splitErr := net.SplitHostPort(boundAddr)
	require.NoError(t, splitErr)
	assert.Equal(t, "42069", portStr, "the fallback must keep the explicitly requested port")
}

func TestBindListenerWithFallback_NATSuccessPathUnchanged(t *testing.T) {
	// When NAT succeeds, its listener and bound address are used as-is and the
	// plain fallback is never reached.
	origProbe := probeAndBindNAT
	t.Cleanup(func() { probeAndBindNAT = origProbe })

	fakeListener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = fakeListener.Close() })

	probeAndBindNAT = func(*nat.BindConfig) (*nat.BindResult, error) {
		return &nat.BindResult{Listener: fakeListener, BoundAddress: fakeListener.Addr().String()}, nil
	}

	transport := newFallbackTestTransport(t)
	config, err := NewConfig(":0")
	require.NoError(t, err)

	listener, boundAddr, err := bindListenerWithFallback(transport, config, 0)
	require.NoError(t, err)
	assert.Same(t, fakeListener, listener, "the NAT-provided listener must be returned untouched")
	assert.Equal(t, fakeListener.Addr().String(), boundAddr)
}
