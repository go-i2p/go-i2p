// C6 compliance tests: the I2P spec's DatabaseStore note - "For security, the
// reply fields are ignored if the message is received down a tunnel." A
// tunnel-delivered (or garlic-clove) store must not have its reply token
// honored: no DeliveryStatus ack and no token-gated flood. A directly-received
// store keeps that behavior, and every store is still stored and correlated.
package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingReplicator records FloodDatabaseStore calls.
type countingReplicator struct {
	floodCalls int
	lastKey    common.Hash
}

func (c *countingReplicator) FloodDatabaseStore(key common.Hash, data []byte, dataType byte) {
	c.floodCalls++
	c.lastKey = key
}

// newStoreWithReplyToken builds a *DatabaseStore carrying a non-zero reply
// token, a reply gateway, and the given reply tunnel ID.
func newStoreWithReplyToken(t *testing.T, replyTunnelID uint32) *DatabaseStore {
	t.Helper()

	var key, gateway common.Hash
	copy(key[:], "c6-dbstore-key-0000000000000000000")
	copy(gateway[:], "c6-reply-gateway-000000000000000000")

	ds := &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
		Key:             key,
		StoreType:       DatabaseStoreTypeRouterInfo,
		ReplyToken:      [4]byte{0, 0, 0, 1}, // non-zero token
		ReplyGateway:    gateway,
		Data:            []byte("router-info-body"),
	}
	ds.ReplyTunnelID[0] = byte(replyTunnelID >> 24)
	ds.ReplyTunnelID[1] = byte(replyTunnelID >> 16)
	ds.ReplyTunnelID[2] = byte(replyTunnelID >> 8)
	ds.ReplyTunnelID[3] = byte(replyTunnelID)
	return ds
}

// setupC6Processor wires a processor with a NetDB store, a floodfill
// replicator, and a clove forwarder.
func setupC6Processor(t *testing.T) (*MessageProcessor, *mockNetDBStore, *countingReplicator, *mockCloveForwarder) {
	t.Helper()
	p := NewMessageProcessor()
	store := newMockNetDBStore()
	p.SetDatabaseManager(NewDatabaseManager(store))
	rep := &countingReplicator{}
	p.SetFloodfillReplicator(rep)
	fwd := &mockCloveForwarder{}
	p.SetCloveForwarder(fwd)
	return p, store, rep, fwd
}

// TestDatabaseStore_DirectReplyTokenIsHonored verifies a directly-received
// store with a reply token still gets its DeliveryStatus ack and flood.
func TestDatabaseStore_DirectReplyTokenIsHonored(t *testing.T) {
	p, store, rep, fwd := setupC6Processor(t)

	ds := newStoreWithReplyToken(t, 0) // reply tunnel 0 => direct ForwardToRouter

	require.NoError(t, p.processDatabaseStoreMessage(ds))

	assert.Equal(t, 1, store.callCount, "direct store is stored")
	assert.Equal(t, 1, rep.floodCalls, "token-gated flood runs for a direct store")
	assert.Equal(t, 1, fwd.routerCalls, "DeliveryStatus ack sent to reply gateway")
}

// TestDatabaseStore_TunnelDeliveredReplyTokenIgnored verifies the C6 fix: a
// store marked as received down a tunnel keeps its reply fields ignored - no
// ack, no flood - while the data is still stored.
func TestDatabaseStore_TunnelDeliveredReplyTokenIgnored(t *testing.T) {
	p, store, rep, fwd := setupC6Processor(t)

	ds := newStoreWithReplyToken(t, 0)
	ds.SetReceivedViaTunnel(true)

	require.NoError(t, p.processDatabaseStoreMessage(ds))

	assert.Equal(t, 1, store.callCount, "tunnel-delivered store data is still stored")
	assert.Equal(t, 0, rep.floodCalls, "flood must not run for a tunnel-delivered store")
	assert.Equal(t, 0, fwd.routerCalls, "no DeliveryStatus ack for a tunnel-delivered store")
	assert.Equal(t, 0, fwd.tunnelCalls, "no tunnel-delivered ack either")
}

// TestDatabaseStore_TunnelDeliveredZeroTokenStored verifies a legitimate
// tunnel-delivered store with no reply token (e.g. a floodfill publish
// confirmation) is stored normally and simply produces no ack.
func TestDatabaseStore_TunnelDeliveredZeroTokenStored(t *testing.T) {
	p, store, rep, fwd := setupC6Processor(t)

	ds := newStoreWithReplyToken(t, 0)
	ds.ReplyToken = [4]byte{0, 0, 0, 0} // no reply token
	ds.SetReceivedViaTunnel(true)

	require.NoError(t, p.processDatabaseStoreMessage(ds))

	assert.Equal(t, 1, store.callCount, "zero-token tunnel store is still stored")
	assert.Equal(t, 0, rep.floodCalls, "no flood without a reply token")
	assert.Equal(t, 0, fwd.routerCalls, "no ack without a reply token")
}

// TestDatabaseStore_TunnelAckViaReplyTunnelIgnored verifies the tunnel-reply
// ack branch (non-zero reply tunnel ID) is also suppressed for a tunnel-
// delivered store.
func TestDatabaseStore_TunnelAckViaReplyTunnelIgnored(t *testing.T) {
	p, store, _, fwd := setupC6Processor(t)

	ds := newStoreWithReplyToken(t, 0x01020304) // non-zero reply tunnel ID
	ds.SetReceivedViaTunnel(true)

	require.NoError(t, p.processDatabaseStoreMessage(ds))

	assert.Equal(t, 1, store.callCount)
	assert.Equal(t, 0, fwd.tunnelCalls, "reply-tunnel ack suppressed for tunnel-delivered store")
}

// TestBaseMessage_TunnelOriginRoundTrip verifies the origin flag survives the
// DataCarrier coercion path used for wire-received messages.
func TestBaseMessage_TunnelOriginRoundTrip(t *testing.T) {
	base := NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore)
	var key common.Hash
	copy(key[:], "c6-coerce-key-0000000000000000000000")
	ds := &DatabaseStore{
		BaseI2NPMessage: base,
		Key:             key,
		StoreType:       DatabaseStoreTypeRouterInfo,
		ReplyToken:      [4]byte{0, 0, 0, 9},
		Data:            []byte("body"),
	}
	body, err := ds.MarshalPayload()
	require.NoError(t, err)

	wire := NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore)
	wire.SetData(body)
	wire.SetReceivedViaTunnel(true)

	coerced, err := coerceDatabaseStoreMessage(wire)
	require.NoError(t, err)

	assert.True(t, coerced.ReceivedViaTunnel(),
		"coercion must preserve the tunnel-origin flag")
	assert.True(t, receivedViaTunnel(wire))
}
