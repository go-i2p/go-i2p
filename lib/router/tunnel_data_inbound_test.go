// Regression test for inbound TunnelData (type 18) handling in the router.
//
// Live symptom: go-i2p rejected inbound TunnelData from i2pd peers with
// "message does not implement TunnelCarrier interface", so tunnel data never
// flowed and i2pd stopped selecting go-i2p as a tunnel hop.
//
// The router's extractTunnelPayload asserts the i2np.TunnelCarrier interface.
// Before the fix the inbound parse produced a bare *BaseI2NPMessage that did
// not satisfy it, so every transit/endpoint TunnelData was dropped here.
package router

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/stretchr/testify/require"
)

// TestExtractTunnelPayloadFromSerializedTunnelData parses a serialized
// TunnelData (type 18) the way the NTCP2/SSU2 inbound path does and asserts
// extractTunnelPayload returns the correct 1024-byte payload and TunnelID
// without the "does not implement TunnelCarrier" error.
func TestExtractTunnelPayloadFromSerializedTunnelData(t *testing.T) {
	var payload [i2np.TunnelDataPayloadSize]byte
	for i := range payload {
		payload[i] = byte(i ^ 0x5A)
	}
	const wantID buildrecord.TunnelID = 0xCAFEBABE

	// Serialize as the live outbound path does (9-byte short header), then
	// parse with the inbound factory the transports now use.
	m := i2np.NewTunnelDataMessage(wantID, payload)
	m.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))
	wire, err := i2np.MarshalMessageShort(m)
	require.NoError(t, err)

	msg, err := i2np.ParseInboundShortI2NP(wire)
	require.NoError(t, err)
	require.Equal(t, i2np.I2NPMessageTypeTunnelData, msg.Type())

	// The parsed message must satisfy TunnelCarrier so the router can extract it.
	_, ok := msg.(i2np.TunnelCarrier)
	require.True(t, ok, "inbound TunnelData must implement TunnelCarrier")

	// extractTunnelPayload must return the 1024-byte payload and the tunnel ID.
	data, gotID, err := extractTunnelPayload(msg)
	require.NoError(t, err, "extractTunnelPayload must not reject a parsed inbound TunnelData")
	require.Equal(t, wantID, gotID, "extracted TunnelID must match the wire value")
	require.Len(t, data, tunnelDataPayloadSize, "extracted payload must be 1024 bytes")
	require.Equal(t, payload[:], data, "extracted payload must round-trip unchanged")
}

// TestHandleTunnelDataUnregisteredFromSerializedMessage drives the full
// HandleTunnelData entry point with a parsed inbound TunnelData. The tunnel is
// not registered, so the expected outcome is the "not registered" error — which
// proves the message cleared the TunnelCarrier extraction and reached the
// routing logic, rather than being rejected at the carrier assertion.
func TestHandleTunnelDataUnregisteredFromSerializedMessage(t *testing.T) {
	var payload [i2np.TunnelDataPayloadSize]byte
	m := i2np.NewTunnelDataMessage(0x01020304, payload)
	m.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))
	wire, err := i2np.MarshalMessageShort(m)
	require.NoError(t, err)

	msg, err := i2np.ParseInboundShortI2NP(wire)
	require.NoError(t, err)

	handler := NewInboundMessageHandler(nil)
	err = handler.HandleTunnelData(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not registered",
		"must reach the routing stage (unregistered), not fail the TunnelCarrier assertion")
	require.NotContains(t, err.Error(), "TunnelCarrier",
		"must not reject a parsed inbound TunnelData on the carrier assertion")
}
