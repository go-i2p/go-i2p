// Regression test for the SSU2 handshake network ID (netId).
//
// netdb.net_id was plumbed into the published RouterInfo and inbound NetDB
// validation, but NOT into the go-noise SSU2 config, so a router on a
// non-mainline network (netId != 2) still wrote the mainline default of 2 into
// header byte 14 of every SSU2 long-header message. A peer on the test network
// (e.g. i2pd with netid=5) then drops the SessionRequest, so SSU2 sessions never
// establish on a testnet.
//
// These tests build a real bound SSU2 transport the way lib/router does
// (NewSSU2Transport from a signed RouterInfo whose netId option carries the
// configured network) and assert the go-noise config it hands the listener
// carries that netId — the value written into, and required of, the wire
// headers.

package ssu2

import (
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBoundSSU2TransportWithNetID builds a real bound SSU2 transport whose
// identity RouterInfo advertises the given netId.
func newBoundSSU2TransportWithNetID(t *testing.T, netID string) (*SSU2Transport, router_info.RouterInfo) {
	t.Helper()

	identity := testutil.CreateSignedTestRouterInfo(t, map[string]string{"netId": netID}, nil)
	require.NotNil(t, identity)

	config, err := NewConfig("127.0.0.1:0")
	require.NoError(t, err)
	config.WorkingDir = t.TempDir()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 0x10)
	}

	transport, err := NewSSU2Transport(*identity, config, &testKeystore{keyData: key})
	require.NoError(t, err, "constructing a bound SSU2 transport must succeed")
	t.Cleanup(func() { _ = transport.Close() })

	return transport, *identity
}

// TestSSU2ConfigCarriesConfiguredNetID asserts the go-noise SSU2 config built
// from a netId-5 identity carries NetworkID 5, so the handshake headers use the
// configured network rather than the hardcoded default of 2.
func TestSSU2ConfigCarriesConfiguredNetID(t *testing.T) {
	transport, _ := newBoundSSU2TransportWithNetID(t, "5")

	cfg := transport.config.Load()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.SSU2Config)
	assert.EqualValues(t, 5, cfg.SSU2Config.NetworkID,
		"the SSU2 handshake networkID must equal the configured netId")
}

// TestSSU2ConfigDefaultsToMainNetworkWhenNetIDUnset is the negative control: an
// identity advertising the mainline netId (2) yields NetworkID 2, so the fix
// does not perturb production behaviour.
func TestSSU2ConfigDefaultsToMainNetworkWhenNetIDUnset(t *testing.T) {
	transport, _ := newBoundSSU2TransportWithNetID(t, "2")

	cfg := transport.config.Load()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.SSU2Config)
	assert.EqualValues(t, 2, cfg.SSU2Config.NetworkID,
		"a netId-2 identity must keep the mainline networkID")
}
