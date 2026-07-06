package ntcp2

import (
	"context"
	"testing"

	"github.com/go-i2p/common/data"
	noise "github.com/go-i2p/go-noise/ntcp2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/require"
)

func TestEnsureLocalStaticKeyConfigured_PopulatesMissingKeyFromKeystore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var routerHash data.Hash
	noiseCfg, err := noise.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	noiseCfg.StaticKey = nil // Simulate missing key under strict verification defaults

	expectedKey := make([]byte, 32)
	for i := range expectedKey {
		expectedKey[i] = byte(i + 1)
	}

	transport := &NTCP2Transport{
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger.WithField("test", "static_key_population"),
		keystore: &testKeystorePB2{keyData: expectedKey},
	}
	transport.config.Store(&Config{Config: noiseCfg})

	key, err := transport.ensureLocalStaticKeyConfigured()
	require.NoError(t, err)
	require.Equal(t, expectedKey, key)

	updated := transport.config.Load()
	require.NotNil(t, updated)
	require.NotNil(t, updated.Config)
	require.Equal(t, expectedKey, updated.Config.StaticKey)
}

func TestEnsureLocalStaticKeyConfigured_ErrorsWithoutKeystoreWhenMissing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var routerHash data.Hash
	noiseCfg, err := noise.NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	noiseCfg.StaticKey = nil

	transport := &NTCP2Transport{
		ctx:    ctx,
		cancel: cancel,
		logger: logger.WithField("test", "static_key_population"),
	}
	transport.config.Store(&Config{Config: noiseCfg})

	_, err = transport.ensureLocalStaticKeyConfigured()
	require.Error(t, err)
	require.Contains(t, err.Error(), "keystore is not configured")
}
