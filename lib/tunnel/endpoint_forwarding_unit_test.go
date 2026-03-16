package tunnel

import (
	"errors"
	"sync"
	"testing"

	"github.com/go-i2p/crypto/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockForwarder records all forwarding calls for verification.
type mockForwarder struct {
	mu          sync.Mutex
	tunnelCalls []forwardTunnelCall
	routerCalls []forwardRouterCall
	tunnelErr   error
	routerErr   error
}

// createTestEndpoint creates an Endpoint with a no-op handler (or a custom one)
// and registers cleanup.  Pass nil for a default no-op handler.
func createTestEndpoint(t *testing.T, handler func([]byte) error) *Endpoint {
	t.Helper()
	if handler == nil {
		handler = func([]byte) error { return nil }
	}
	ep, err := NewEndpoint(TunnelID(1), &tunnel.AESEncryptor{}, handler)
	require.NoError(t, err)
	t.Cleanup(func() { ep.Stop() })
	return ep
}

// createTestEndpointWithForwarder creates an Endpoint with a no-op handler and
// an attached mockForwarder, ready for delivery-instruction tests.
func createTestEndpointWithForwarder(t *testing.T) (*Endpoint, *mockForwarder) {
	t.Helper()
	ep := createTestEndpoint(t, nil)
	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)
	return ep, fwd
}

type forwardTunnelCall struct {
	tunnelID    uint32
	gatewayHash [32]byte
	msgBytes    []byte
}

type forwardRouterCall struct {
	routerHash [32]byte
	msgBytes   []byte
}

func (f *mockForwarder) ForwardToTunnel(tunnelID uint32, gatewayHash [32]byte, msgBytes []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnelCalls = append(f.tunnelCalls, forwardTunnelCall{tunnelID, gatewayHash, msgBytes})
	return f.tunnelErr
}

func (f *mockForwarder) ForwardToRouter(routerHash [32]byte, msgBytes []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routerCalls = append(f.routerCalls, forwardRouterCall{routerHash, msgBytes})
	return f.routerErr
}

// TestSetForwarder tests the SetForwarder method.
func TestSetForwarder(t *testing.T) {
	ep := createTestEndpoint(t, nil)

	// Initially nil
	assert.Nil(t, ep.forwarder)

	fwd := &mockForwarder{}
	ep.SetForwarder(fwd)
	assert.NotNil(t, ep.forwarder)
}

// TestDeliverWithInstructionsLocal tests DTLocal delivery goes to handler.
func TestDeliverWithInstructionsLocal(t *testing.T) {
	var received []byte
	ep := createTestEndpoint(t, func(msgBytes []byte) error {
		received = msgBytes
		return nil
	})

	msg := []byte("hello local delivery")
	di := &DeliveryInstructions{}

	err := ep.deliverWithInstructions(DTLocal, di, msg)
	assert.NoError(t, err)
	assert.Equal(t, msg, received, "DTLocal should deliver to handler")
}

// TestDeliverWithInstructionsTunnel tests DTTunnel delivery forwards via MessageForwarder.
func TestDeliverWithInstructionsTunnel(t *testing.T) {
	ep, fwd := createTestEndpointWithForwarder(t)

	var hash [32]byte
	copy(hash[:], []byte("gateway_hash_for_tunnel_fwd_test"))
	di := &DeliveryInstructions{
		tunnelID: 42,
		hash:     hash,
	}

	msg := []byte("tunnel delivery message")
	err := ep.deliverWithInstructions(DTTunnel, di, msg)
	assert.NoError(t, err)

	assertTunnelForwarded(t, fwd, 42, hash, msg)
}

// TestDeliverWithInstructionsRouter tests DTRouter delivery forwards via MessageForwarder.
func TestDeliverWithInstructionsRouter(t *testing.T) {
	ep, fwd := createTestEndpointWithForwarder(t)

	var hash [32]byte
	copy(hash[:], []byte("router_hash_for_router_fwd_test!"))
	di := &DeliveryInstructions{
		hash: hash,
	}

	msg := []byte("router delivery message")
	err := ep.deliverWithInstructions(DTRouter, di, msg)
	assert.NoError(t, err)

	assertRouterForwarded(t, fwd, hash, msg)
}

// TestDeliverViaForwarderNoForwarder tests graceful handling when no forwarder is set.
func TestDeliverViaForwarderNoForwarder(t *testing.T) {
	ep := createTestEndpoint(t, nil)

	// No forwarder set — should not error, just silently skip
	var hash [32]byte
	err := ep.deliverViaForwarder(DTTunnel, 42, hash, []byte("test"))
	assert.NoError(t, err, "No forwarder should be a no-op, not an error")

	err = ep.deliverViaForwarder(DTRouter, 0, hash, []byte("test"))
	assert.NoError(t, err, "No forwarder should be a no-op for router too")
}

// TestDeliverViaForwarderError tests error propagation from forwarder.
func TestDeliverViaForwarderError(t *testing.T) {
	ep := createTestEndpoint(t, nil)

	fwd := &mockForwarder{
		tunnelErr: errors.New("tunnel forward failed"),
		routerErr: errors.New("router forward failed"),
	}
	ep.SetForwarder(fwd)

	var hash [32]byte
	err := ep.deliverViaForwarder(DTTunnel, 42, hash, []byte("test"))
	assert.Error(t, err, "Should propagate tunnel forwarding error")

	err = ep.deliverViaForwarder(DTRouter, 0, hash, []byte("test"))
	assert.Error(t, err, "Should propagate router forwarding error")
}

// TestDeliverViaForwarderUnknownType tests unknown delivery type handling.
func TestDeliverViaForwarderUnknownType(t *testing.T) {
	ep, fwd := createTestEndpointWithForwarder(t)

	var hash [32]byte
	err := ep.deliverViaForwarder(DTUnused, 0, hash, []byte("test"))
	assert.NoError(t, err, "Unknown delivery type should be silently skipped")

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	assert.Empty(t, fwd.tunnelCalls, "No tunnel calls for unknown type")
	assert.Empty(t, fwd.routerCalls, "No router calls for unknown type")
}

// TestStoreFirstFragmentWithDI tests storing first fragment with routing info.
func TestStoreFirstFragmentWithDI(t *testing.T) {
	ep := createTestEndpoint(t, nil)

	var hash [32]byte
	copy(hash[:], []byte("gateway_hash_for_first_frag_test"))
	di := &DeliveryInstructions{
		tunnelID: 42,
		hash:     hash,
	}

	err := ep.storeFirstFragmentWithDI(1, DTTunnel, di, []byte("fragment data"))
	assert.NoError(t, err)

	// Verify assembler has routing info
	ep.fragmentsMutex.Lock()
	assembler, exists := ep.fragments[1]
	ep.fragmentsMutex.Unlock()

	require.True(t, exists, "Assembler should exist for message ID 1")
	assert.Equal(t, byte(DTTunnel), assembler.deliveryType)
	assert.Equal(t, uint32(42), assembler.tunnelID)
	assert.Equal(t, hash, assembler.hash)
}

// TestStoreFirstFragmentWithDIRouter tests storing first fragment with router routing info.
func TestStoreFirstFragmentWithDIRouter(t *testing.T) {
	ep := createTestEndpoint(t, nil)

	var hash [32]byte
	copy(hash[:], []byte("router_hash_for_first_frag_test!"))
	di := &DeliveryInstructions{
		hash: hash,
	}

	err := ep.storeFirstFragmentWithDI(2, DTRouter, di, []byte("router fragment"))
	assert.NoError(t, err)

	ep.fragmentsMutex.Lock()
	assembler, exists := ep.fragments[2]
	ep.fragmentsMutex.Unlock()

	require.True(t, exists)
	assert.Equal(t, byte(DTRouter), assembler.deliveryType)
	assert.Equal(t, hash, assembler.hash)
}

// TestReassembleAndDeliverTunnel tests reassembly delivers to forwarder for DTTunnel.
func TestReassembleAndDeliverTunnel(t *testing.T) {
	ep, fwd := createTestEndpointWithForwarder(t)

	var hash [32]byte
	copy(hash[:], []byte("gateway_for_reassemble_delivery!"))

	err := reassembleTestFragments(t, ep, 99, DTTunnel, 42, hash, map[int][]byte{
		0: []byte("part1"),
		1: []byte("part2"),
	})
	assert.NoError(t, err)

	assertTunnelForwarded(t, fwd, 42, hash, []byte("part1part2"))
}

// TestReassembleAndDeliverRouter tests reassembly delivers to forwarder for DTRouter.
func TestReassembleAndDeliverRouter(t *testing.T) {
	ep, fwd := createTestEndpointWithForwarder(t)

	var hash [32]byte
	copy(hash[:], []byte("router_for_reassemble_delivery!!"))

	err := reassembleTestFragments(t, ep, 100, DTRouter, 0, hash, map[int][]byte{
		0: []byte("router_part1"),
		1: []byte("router_part2"),
	})
	assert.NoError(t, err)

	assertRouterForwarded(t, fwd, hash, []byte("router_part1router_part2"))
}

// TestReassembleAndDeliverNoForwarder tests reassembly skips gracefully without forwarder.
func TestReassembleAndDeliverNoForwarder(t *testing.T) {
	ep := createTestEndpoint(t, nil)

	// No forwarder set
	err := reassembleTestFragments(t, ep, 101, DTTunnel, 0, [32]byte{}, map[int][]byte{
		0: []byte("data"),
	})
	assert.NoError(t, err, "Should not error without forwarder")
}

// TestReassembleAndDeliverLocal tests reassembly delivers to handler for DTLocal.
func TestReassembleAndDeliverLocal(t *testing.T) {
	var received []byte
	ep := createTestEndpoint(t, func(msgBytes []byte) error {
		received = msgBytes
		return nil
	})

	err := reassembleTestFragments(t, ep, 102, DTLocal, 0, [32]byte{}, map[int][]byte{
		0: []byte("local_"),
		1: []byte("msg"),
	})
	assert.NoError(t, err)
	assert.Equal(t, []byte("local_msg"), received)
}

// TestMessageForwarderInterface tests that mockForwarder correctly implements the interface.
func TestMessageForwarderInterface(t *testing.T) {
	var _ MessageForwarder = (*mockForwarder)(nil)
}

// TestFragmentAssemblerRoutingFields tests the tunnelID and hash fields on fragmentAssembler.
func TestFragmentAssemblerRoutingFields(t *testing.T) {
	var hash [32]byte
	copy(hash[:], []byte("routing_hash_for_assembler_test!"))

	assembler := &fragmentAssembler{
		fragments:    make(map[int][]byte),
		deliveryType: DTTunnel,
		tunnelID:     123,
		hash:         hash,
	}

	assert.Equal(t, byte(DTTunnel), assembler.deliveryType)
	assert.Equal(t, uint32(123), assembler.tunnelID)
	assert.Equal(t, hash, assembler.hash)
}
