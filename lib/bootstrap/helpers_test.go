package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCompositeBootstrap creates a CompositeBootstrap with common test defaults.
// It constructs a BootstrapConfig using testLowPeerThreshold and the provided fields,
// then creates and validates the CompositeBootstrap instance.
func newTestCompositeBootstrap(t *testing.T, bootstrapType, reseedFilePath string, reseedServers []*config.ReseedConfig) *CompositeBootstrap {
	t.Helper()
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		BootstrapType:    bootstrapType,
		ReseedFilePath:   reseedFilePath,
		ReseedServers:    reseedServers,
	}
	cb := NewCompositeBootstrap(cfg)
	require.NotNil(t, cb)
	return cb
}

// assertBootstrapError asserts that err is non-nil, peers is nil, the error
// message contains contains, and does NOT contain any of notContains.
func assertBootstrapError(t *testing.T, err error, peers interface{}, contains string, notContains ...string) {
	t.Helper()
	require.Error(t, err)
	assert.Nil(t, peers)
	assert.Contains(t, err.Error(), contains)
	for _, nc := range notContains {
		assert.NotContains(t, err.Error(), nc)
	}
}

// assertApplyStrategyNotNil creates a ReseedBootstrap with the given strategy,
// applies it to a single-result set, and asserts the result is not nil.
func assertApplyStrategyNotNil(t *testing.T, strategy, errMsg string) {
	t.Helper()
	cfg := &config.BootstrapConfig{
		ReseedStrategy: strategy,
	}
	rb := &ReseedBootstrap{config: cfg}
	results := []ReseedResult{
		{ServerURL: "https://s1/", RouterInfos: make([]router_info.RouterInfo, 3)},
	}
	combined := rb.applyStrategy(results)
	if combined == nil {
		t.Error(errMsg)
	}
}

// createTempTestFile creates a temporary file with dummy content in the given directory.
func createTempTestFile(tb testing.TB, dir, name string, size int) string {
	tb.Helper()
	tmpFile := filepath.Join(dir, name)
	err := os.WriteFile(tmpFile, createDummyContent(size), 0o644)
	require.NoError(tb, err)
	return tmpFile
}

// createTestRouterAddress creates a test RouterAddress with the given transport style and options.
func createTestRouterAddress(transportStyle string, options map[string]string) *router_address.RouterAddress {
	expiration := time.Now().Add(24 * time.Hour)
	addr, err := router_address.NewRouterAddress(5, expiration, transportStyle, options)
	if err != nil {
		panic("Failed to create test RouterAddress: " + err.Error())
	}
	return addr
}

// createSignedTestRouterInfo creates a properly signed RouterInfo for testing.
// Uses Ed25519 signing keys and ElGamal encryption keys, matching the I2P standard.
func createSignedTestRouterInfo(tb testing.TB, options map[string]string) *router_info.RouterInfo {
	tb.Helper()
	addrCfg := testutil.DefaultRouterAddressConfig()
	addrCfg.Options = map[string]string{
		"host": testHost,
		"port": testPort,
	}
	return testutil.CreateSignedTestRouterInfo(tb, options, &addrCfg)
}
