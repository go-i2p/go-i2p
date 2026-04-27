package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// makeClove is a test helper that builds a GarlicClove with the given flag bits
// (which encode the delivery type in bits 6–5) and a non-nil wrapped message.
func makeClove(flag byte, hash common.Hash, tunnelID tunnel.TunnelID) GarlicClove {
	inner := NewBaseI2NPMessage(I2NPMessageTypeData)
	inner.data = []byte("payload")
	return GarlicClove{
		DeliveryInstructions: GarlicCloveDeliveryInstructions{
			Flag:     flag,
			Hash:     hash,
			TunnelID: tunnelID,
		},
		I2NPMessage: inner,
		CloveID:     42,
		Expiration:  time.Now().Add(5 * time.Minute),
	}
}

// ── DESTINATION delivery (type 0x01, flag bits 6-5 = 0b01 → 0x20) ───────────

// TestHandleDestinationDelivery_ForwarderCalled verifies that a DESTINATION-type
// clove invokes ForwardToDestination with the correct hash.
func TestHandleDestinationDelivery_ForwarderCalled(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{}
	p.SetCloveForwarder(fwd)

	destHash := common.Hash{1, 2, 3, 4, 5, 6, 7, 8}
	// delivery type 0x01 → flag = 0x01 << 5 = 0x20
	clove := makeClove(0x20, destHash, 0)

	p.handleDestinationDelivery(0, clove)

	if fwd.destCalls != 1 {
		t.Fatalf("expected ForwardToDestination to be called once, got %d", fwd.destCalls)
	}
	if fwd.destHash != destHash {
		t.Errorf("ForwardToDestination called with wrong hash: got %x, want %x", fwd.destHash[:4], destHash[:4])
	}
}

// TestHandleDestinationDelivery_NoForwarder verifies that DESTINATION delivery
// without a forwarder logs a warning and does not panic.
func TestHandleDestinationDelivery_NoForwarder(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()
	// no clove forwarder set

	destHash := common.Hash{10, 20, 30, 40}
	clove := makeClove(0x20, destHash, 0)

	// Should not panic; just logs a warning.
	p.handleDestinationDelivery(0, clove)
}

// TestHandleDestinationDelivery_ForwarderError verifies that a forwarder error
// is logged but does not propagate (handleDestinationDelivery returns nothing).
func TestHandleDestinationDelivery_ForwarderError(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{destErr: &testError{"destination unreachable"}}
	p.SetCloveForwarder(fwd)

	clove := makeClove(0x20, common.Hash{5}, 0)
	p.handleDestinationDelivery(0, clove) // should not panic

	if fwd.destCalls != 1 {
		t.Errorf("expected 1 call, got %d", fwd.destCalls)
	}
}

// ── ROUTER delivery (type 0x02, flag bits 6-5 = 0b10 → 0x40) ─────────────────

// TestHandleRouterDelivery_ForwarderCalled verifies that a ROUTER-type clove
// invokes ForwardToRouter with the correct router hash.
func TestHandleRouterDelivery_ForwarderCalled(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{}
	p.SetCloveForwarder(fwd)

	routerHash := common.Hash{0xAA, 0xBB, 0xCC, 0xDD}
	// delivery type 0x02 → flag = 0x02 << 5 = 0x40
	clove := makeClove(0x40, routerHash, 0)

	p.handleRouterDelivery(0, clove)

	if fwd.routerCalls != 1 {
		t.Fatalf("expected ForwardToRouter to be called once, got %d", fwd.routerCalls)
	}
	if fwd.routerHash != routerHash {
		t.Errorf("ForwardToRouter called with wrong hash: got %x, want %x", fwd.routerHash[:4], routerHash[:4])
	}
}

// TestHandleRouterDelivery_NoForwarder verifies that ROUTER delivery without a
// forwarder logs a warning and does not panic.
func TestHandleRouterDelivery_NoForwarder(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	clove := makeClove(0x40, common.Hash{0xAB}, 0)
	p.handleRouterDelivery(0, clove) // should not panic
}

// TestHandleRouterDelivery_ForwarderError verifies that a forwarder error is
// handled gracefully.
func TestHandleRouterDelivery_ForwarderError(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{routerErr: &testError{"router not found"}}
	p.SetCloveForwarder(fwd)

	clove := makeClove(0x40, common.Hash{7}, 0)
	p.handleRouterDelivery(0, clove)

	if fwd.routerCalls != 1 {
		t.Errorf("expected 1 call, got %d", fwd.routerCalls)
	}
}

// ── TUNNEL delivery (type 0x03, flag bits 6-5 = 0b11 → 0x60) ─────────────────

// TestHandleTunnelDelivery_ForwarderCalled verifies that a TUNNEL-type clove
// invokes ForwardThroughTunnel with the correct gateway hash and tunnel ID.
func TestHandleTunnelDelivery_ForwarderCalled(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{}
	p.SetCloveForwarder(fwd)

	gatewayHash := common.Hash{0x11, 0x22, 0x33, 0x44}
	var tid tunnel.TunnelID = 99999
	// delivery type 0x03 → flag = 0x03 << 5 = 0x60
	clove := makeClove(0x60, gatewayHash, tid)

	p.handleTunnelDelivery(0, clove)

	if fwd.tunnelCalls != 1 {
		t.Fatalf("expected ForwardThroughTunnel to be called once, got %d", fwd.tunnelCalls)
	}
	if fwd.gatewayHash != gatewayHash {
		t.Errorf("ForwardThroughTunnel called with wrong gateway hash: got %x, want %x", fwd.gatewayHash[:4], gatewayHash[:4])
	}
	if fwd.tunnelID != tid {
		t.Errorf("ForwardThroughTunnel called with wrong tunnel ID: got %d, want %d", fwd.tunnelID, tid)
	}
}

// TestHandleTunnelDelivery_NoForwarder verifies that TUNNEL delivery without a
// forwarder logs a warning and does not panic.
func TestHandleTunnelDelivery_NoForwarder(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	clove := makeClove(0x60, common.Hash{0xFF}, 12345)
	p.handleTunnelDelivery(0, clove) // should not panic
}

// TestHandleTunnelDelivery_ForwarderError verifies that a forwarder error is
// handled gracefully.
func TestHandleTunnelDelivery_ForwarderError(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{tunnelErr: &testError{"tunnel gateway unreachable"}}
	p.SetCloveForwarder(fwd)

	clove := makeClove(0x60, common.Hash{0xCA}, 777)
	p.handleTunnelDelivery(0, clove)

	if fwd.tunnelCalls != 1 {
		t.Errorf("expected 1 call, got %d", fwd.tunnelCalls)
	}
}

// ── routeCloveByType dispatch table coverage ──────────────────────────────────

// TestRouteCloveByType_AllDeliveryTypes verifies the full dispatch table in
// routeCloveByType routes each delivery type to the correct forwarder method.
func TestRouteCloveByType_AllDeliveryTypes(t *testing.T) {
	p := NewMessageProcessor()
	p.DisableExpirationCheck()

	fwd := &mockCloveForwarder{}
	p.SetCloveForwarder(fwd)

	// LOCAL (0x00) — handled internally, no forwarder call expected.
	localClove := makeClove(0x00, common.Hash{}, 0)
	p.routeCloveByType(0, 0x00, localClove) // may log "no handler" but must not call fwd

	// DESTINATION (0x01)
	p.routeCloveByType(1, 0x01, makeClove(0x20, common.Hash{1}, 0))

	// ROUTER (0x02)
	p.routeCloveByType(2, 0x02, makeClove(0x40, common.Hash{2}, 0))

	// TUNNEL (0x03)
	p.routeCloveByType(3, 0x03, makeClove(0x60, common.Hash{3}, 1))

	if fwd.destCalls != 1 {
		t.Errorf("DESTINATION: expected 1 ForwardToDestination call, got %d", fwd.destCalls)
	}
	if fwd.routerCalls != 1 {
		t.Errorf("ROUTER: expected 1 ForwardToRouter call, got %d", fwd.routerCalls)
	}
	if fwd.tunnelCalls != 1 {
		t.Errorf("TUNNEL: expected 1 ForwardThroughTunnel call, got %d", fwd.tunnelCalls)
	}
}
