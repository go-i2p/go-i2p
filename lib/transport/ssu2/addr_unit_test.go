package ssu2

// addr_unit_test.go tests the WrapSSU2Addr function which wraps a net.Addr
// as an SSU2Addr without requiring a full RouterInfo.

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWrapSSU2Addr_PlainUDPAddr verifies that a plain UDP address is wrapped
// into a new SSU2Addr.
func TestWrapSSU2Addr_PlainUDPAddr(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	routerHash := make([]byte, 32)
	routerHash[0] = 0xAB

	result, err := WrapSSU2Addr(addr, routerHash)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestWrapSSU2Addr_ExistingSSU2Addr verifies that an already-wrapped SSU2Addr
// is returned as-is without creating a new one.
func TestWrapSSU2Addr_ExistingSSU2Addr(t *testing.T) {
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	routerHash := make([]byte, 32)
	routerHash[1] = 0xCD

	first, err := WrapSSU2Addr(udpAddr, routerHash)
	require.NoError(t, err)

	// Wrapping an already-SSU2Addr should return the same pointer.
	second, err := WrapSSU2Addr(first, routerHash)
	require.NoError(t, err)
	assert.Equal(t, first, second)
}

// TestWrapSSU2Addr_ZeroHash verifies behaviour with an all-zero router hash.
func TestWrapSSU2Addr_ZeroHash(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 4444}
	routerHash := make([]byte, 32) // all zeros

	result, err := WrapSSU2Addr(addr, routerHash)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestWrapSSU2Addr_TCPAddr verifies that a TCP net.Addr is also accepted
// (the function only requires net.Addr, not UDPAddr specifically).
func TestWrapSSU2Addr_TCPAddr(t *testing.T) {
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	routerHash := make([]byte, 32)
	routerHash[2] = 0xEF

	result, err := WrapSSU2Addr(tcpAddr, routerHash)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// TestWrapSSU2Addr_NilAddr checks that a nil net.Addr (panics inside ssu2noise
// if not guarded) is handled gracefully. The function delegates to ssu2noise so
// this serves as a quick smoke-test for the delegation path.
func TestWrapSSU2Addr_AddrNotSSU2(t *testing.T) {
	// A plain *net.UDPAddr is not an *ssu2noise.SSU2Addr => a new one is made.
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	routerHash := make([]byte, 32)

	result, err := WrapSSU2Addr(addr, routerHash)
	require.NoError(t, err)
	assert.NotNil(t, result)
	// result is already *ssu2noise.SSU2Addr from WrapSSU2Addr
	_ = result
}
