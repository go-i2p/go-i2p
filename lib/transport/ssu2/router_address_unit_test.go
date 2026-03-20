package ssu2

// router_address_unit_test.go exercises the unexported and exported helpers
// in router_address.go that were not yet covered: isSSU2Transport,
// encodeBase64, resolveUDPAddress, and ConvertToRouterAddress.

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSSU2RouterAddress creates a RouterAddress with SSU2 transport style and
// the given host/port options for use in unit tests.
func makeSSU2RouterAddress(t testing.TB, host, port string) *router_address.RouterAddress {
	t.Helper()
	ra, err := router_address.NewRouterAddress(0, time.Time{}, "SSU2", map[string]string{
		router_address.HOST_OPTION_KEY: host,
		router_address.PORT_OPTION_KEY: port,
	})
	require.NoError(t, err)
	return ra
}

// TestHasDirectConnectivity_WithHostAndPort verifies that an SSU2 address
// with both host and port is considered directly connectable.
func TestHasDirectConnectivity_WithHostAndPort(t *testing.T) {
	ra := makeSSU2RouterAddress(t, "127.0.0.1", "1234")
	assert.True(t, HasDirectConnectivity(ra))
}

// TestHasDirectConnectivity_WithoutHost verifies that an SSU2 address without
// a host (no IP) is not directly connectable.
func TestHasDirectConnectivity_WithoutHost(t *testing.T) {
	ra, err := router_address.NewRouterAddress(0, time.Time{}, "SSU2", map[string]string{
		router_address.PORT_OPTION_KEY: "1234",
	})
	require.NoError(t, err)
	assert.False(t, HasDirectConnectivity(ra))
}

// TestHasDirectConnectivity_WithoutPort verifies that an SSU2 address without
// a valid port is not directly connectable.
func TestHasDirectConnectivity_WithoutPort(t *testing.T) {
	ra, err := router_address.NewRouterAddress(0, time.Time{}, "SSU2", map[string]string{
		router_address.HOST_OPTION_KEY: "127.0.0.1",
	})
	require.NoError(t, err)
	assert.False(t, HasDirectConnectivity(ra))
}

// TestHasDirectConnectivity_NTCP2Addr verifies that a non-SSU2 address style
// returns false.
func TestHasDirectConnectivity_NTCP2Addr(t *testing.T) {
	ra, err := router_address.NewRouterAddress(0, time.Time{}, "NTCP2", map[string]string{
		router_address.HOST_OPTION_KEY: "127.0.0.1",
		router_address.PORT_OPTION_KEY: "1234",
	})
	require.NoError(t, err)
	assert.False(t, HasDirectConnectivity(ra))
}

func TestIsSSU2Transport_SSU2Style(t *testing.T) {
	ra := makeSSU2RouterAddress(t, "127.0.0.1", "1234")
	assert.True(t, isSSU2Transport(ra))
}

// TestIsSSU2Transport_NTCP2Style verifies that an "NTCP2" style returns false.
func TestIsSSU2Transport_NTCP2Style(t *testing.T) {
	ra, err := router_address.NewRouterAddress(0, time.Time{}, "NTCP2", map[string]string{
		router_address.HOST_OPTION_KEY: "127.0.0.1",
		router_address.PORT_OPTION_KEY: "1234",
	})
	require.NoError(t, err)
	assert.False(t, isSSU2Transport(ra))
}

// TestEncodeBase64_RoundTrip verifies encodeBase64 encodes correctly.
func TestEncodeBase64_RoundTrip(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
	got := encodeBase64(data)
	want := base64.StdEncoding.EncodeToString(data)
	assert.Equal(t, want, got)
}

// TestEncodeBase64_Empty verifies that encoding empty bytes returns empty string.
func TestEncodeBase64_Empty(t *testing.T) {
	assert.Equal(t, "", encodeBase64([]byte{}))
}

// TestResolveUDPAddress_Valid verifies that a RouterAddress with valid host and
// port resolves to a *net.UDPAddr.
func TestResolveUDPAddress_Valid(t *testing.T) {
	ra := makeSSU2RouterAddress(t, "127.0.0.1", "9090")
	udpAddr, err := resolveUDPAddress(ra)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("127.0.0.1").To4(), udpAddr.IP.To4())
	assert.Equal(t, 9090, udpAddr.Port)
}

// TestResolveUDPAddress_IPv6 verifies that IPv6 addresses are resolved
// correctly.
func TestResolveUDPAddress_IPv6(t *testing.T) {
	ra := makeSSU2RouterAddress(t, "::1", "7070")
	udpAddr, err := resolveUDPAddress(ra)
	require.NoError(t, err)
	assert.Equal(t, 7070, udpAddr.Port)
}

// TestConvertToRouterAddress_NilTransport verifies ConvertToRouterAddress
// returns an error for a nil transport.
func TestConvertToRouterAddress_NilTransport(t *testing.T) {
	_, err := ConvertToRouterAddress(nil)
	assert.Error(t, err)
}

// TestConvertToRouterAddress_NoListener verifies ConvertToRouterAddress returns
// an error when the transport has no active listener.
func TestConvertToRouterAddress_NoListener(t *testing.T) {
	tr := makeMinimalTransport()
	_, err := ConvertToRouterAddress(tr)
	assert.Error(t, err, "transport with no listener should fail")
}

// TestConvertToRouterAddress_WithListener verifies ConvertToRouterAddress
// returns a valid SSU2 RouterAddress when the transport has an active listener.
func TestConvertToRouterAddress_WithListener(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	ra, err := ConvertToRouterAddress(tr)
	require.NoError(t, err)
	require.NotNil(t, ra)

	// Transport style must be SSU2.
	style := ra.TransportStyle()
	styleStr, err2 := style.Data()
	require.NoError(t, err2)
	assert.Equal(t, "SSU2", styleStr)

	// Host and port options must be present.
	assert.True(t, ra.CheckOption(router_address.HOST_OPTION_KEY))
	assert.True(t, ra.CheckOption(router_address.PORT_OPTION_KEY))
}

// TestConvertToRouterAddress_WithStaticKey verifies that a 32-byte StaticKey
// on the transport config causes the STATIC_KEY_OPTION_KEY option to be set.
func TestConvertToRouterAddress_WithStaticKey(t *testing.T) {
	tr, cleanup := makeTestTransportWithListener(t)
	defer cleanup()

	// Access the SSU2Config directly (it may be nil on a minimal test
	// transport).  If nil, skip.
	if tr.config.SSU2Config == nil {
		t.Skip("config.SSU2Config is nil, skipping static key test")
	}
	tr.config.SSU2Config.StaticKey = make([]byte, 32)
	for i := range tr.config.SSU2Config.StaticKey {
		tr.config.SSU2Config.StaticKey[i] = byte(i)
	}

	ra, err := ConvertToRouterAddress(tr)
	require.NoError(t, err)
	require.NotNil(t, ra)
	assert.True(t, ra.CheckOption(router_address.STATIC_KEY_OPTION_KEY))
}
