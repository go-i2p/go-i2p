// Tests for peer key and address binding. Validates that the 32-byte
// static key and 16-byte obfuscation IV are bound into the Noise config
// when dialing a peer.

package ntcp2

import (
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/types"
	noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validNTCP2TestKey returns a 32-byte X25519 public key that passes the
// curve-point validation required of a dial target (ntcp2.rst:298).
func validNTCP2TestKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := curve25519.GenerateKeyPair()
	require.NoError(t, err)
	key, ok := pub.(types.ReceivingPublicKey)
	require.True(t, ok)
	return key.Bytes()
}

func makeNTCP2RouterAddress(t *testing.T, host, port string, staticKey, iv []byte) *router_address.RouterAddress {
	t.Helper()
	require.Len(t, staticKey, 32)
	require.Len(t, iv, 16)

	addr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", map[string]string{
		"host": host,
		"port": port,
		"s":    i2pbase64.I2PEncoding.EncodeToString(staticKey),
		"i":    i2pbase64.I2PEncoding.EncodeToString(iv),
		"v":    "2",
	})
	require.NoError(t, err)
	return addr
}

// Validates that dialing a peer binds the exact 32-byte static key and
// 16-byte obfuscation IV from the RouterAddress into the Noise config.
func TestConfigureDialConfigFromAddress_BindsExactAddressMetadata(t *testing.T) {
	var routerHash data.Hash
	cfg, err := noise.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// W6: ConfigureDialConfigFromAddress now verifies all three NTCP2 options
	// (s=, i=, v=) and validates the static key as an X25519 curve point
	// (ntcp2.rst:1861-1862, :298), so the fixture uses real generated keys.
	staticA := validNTCP2TestKey(t)
	ivA := make([]byte, 16)
	for i := range ivA {
		ivA[i] = byte(i + 11)
	}

	addrA := makeNTCP2RouterAddress(t, "198.51.100.10", "12345", staticA, ivA)
	require.NoError(t, ConfigureDialConfigFromAddress(cfg, addrA))
	assert.Equal(t, staticA, cfg.RemoteStaticKey)
	assert.True(t, cfg.EnableAESObfuscation)
	assert.Equal(t, ivA, cfg.ObfuscationIV)

	staticB := validNTCP2TestKey(t)
	ivB := make([]byte, 16)
	for i := range ivB {
		ivB[i] = byte(100 + i)
	}

	addrB := makeNTCP2RouterAddress(t, "203.0.113.20", "22345", staticB, ivB)
	require.NoError(t, ConfigureDialConfigFromAddress(cfg, addrB))
	assert.Equal(t, staticB, cfg.RemoteStaticKey)
	assert.Equal(t, ivB, cfg.ObfuscationIV)
}
