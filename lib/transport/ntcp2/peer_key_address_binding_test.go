package ntcp2

import (
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeNTCP2RouterAddress(t *testing.T, host, port string, staticKey, iv []byte) *router_address.RouterAddress {
	t.Helper()
	require.Len(t, staticKey, 32)
	require.Len(t, iv, 16)

	addr, err := router_address.NewRouterAddress(3, time.Now().Add(24*time.Hour), "NTCP2", map[string]string{
		"host": host,
		"port": port,
		"s":    i2pbase64.I2PEncoding.EncodeToString(staticKey),
		"i":    i2pbase64.I2PEncoding.EncodeToString(iv),
	})
	require.NoError(t, err)
	return addr
}

func TestConfigureDialConfigFromAddress_BindsExactAddressMetadata(t *testing.T) {
	var routerHash data.Hash
	cfg, err := noise.NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	staticA := make([]byte, 32)
	ivA := make([]byte, 16)
	for i := range staticA {
		staticA[i] = byte(i + 1)
	}
	for i := range ivA {
		ivA[i] = byte(i + 11)
	}

	addrA := makeNTCP2RouterAddress(t, "198.51.100.10", "12345", staticA, ivA)
	require.NoError(t, ConfigureDialConfigFromAddress(cfg, addrA))
	assert.Equal(t, staticA, cfg.RemoteStaticKey)
	assert.True(t, cfg.EnableAESObfuscation)
	assert.Equal(t, ivA, cfg.ObfuscationIV)

	staticB := make([]byte, 32)
	ivB := make([]byte, 16)
	for i := range staticB {
		staticB[i] = byte(200 + i)
	}
	for i := range ivB {
		ivB[i] = byte(100 + i)
	}

	addrB := makeNTCP2RouterAddress(t, "203.0.113.20", "22345", staticB, ivB)
	require.NoError(t, ConfigureDialConfigFromAddress(cfg, addrB))
	assert.Equal(t, staticB, cfg.RemoteStaticKey)
	assert.Equal(t, ivB, cfg.ObfuscationIV)
}
