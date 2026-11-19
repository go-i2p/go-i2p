// Regression tests for inbound TunnelData (type 18) TunnelCarrier handling.
//
// Live symptom: a go-i2p router acting as a tunnel endpoint/hop rejected every
// inbound TunnelData from an i2pd peer with "message does not implement
// TunnelCarrier interface" (582 occurrences in the router log), so no tunnel
// data flowed and i2pd stopped selecting go-i2p as a hop ("Can't select next
// hop for i-U6...").
//
// Root cause: the NTCP2/SSU2 inbound parse produced a bare *BaseI2NPMessage,
// which satisfies DataCarrier (GetData) but not TunnelCarrier (GetTunnelData /
// GetTunnelID), so processTunnelDataMessage's typed assertion failed and the
// message was dropped before its payload was ever examined.
package i2np

import (
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/stretchr/testify/require"
)

// newSerializedTunnelData builds a wire-format TunnelData (type 18) carrying
// the given tunnel ID and 1024-byte payload, using the live short-header
// serializer (the format NTCP2/SSU2 actually deliver).
func newSerializedTunnelData(t *testing.T, tunnelID buildrecord.TunnelID, payload [TunnelDataPayloadSize]byte) []byte {
	t.Helper()
	msg := NewTunnelDataMessage(tunnelID, payload)
	msg.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))
	wire, err := MarshalMessageShort(msg)
	require.NoError(t, err)
	return wire
}

// TestInboundTunnelDataSatisfiesTunnelCarrier parses a serialized TunnelData
// (type 18) exactly the way the NTCP2/SSU2 inbound path now does and asserts
// the parsed message satisfies TunnelCarrier, with the correct 1024-byte
// payload and TunnelID.
func TestInboundTunnelDataSatisfiesTunnelCarrier(t *testing.T) {
	var payload [TunnelDataPayloadSize]byte
	for i := range payload {
		payload[i] = byte(i)
	}
	const wantID buildrecord.TunnelID = 0xDEADBEEF

	wire := newSerializedTunnelData(t, wantID, payload)

	// Inbound NTCP2/SSU2 parse target.
	msg, err := ParseInboundShortI2NP(wire)
	require.NoError(t, err)
	require.Equal(t, I2NPMessageTypeTunnelData, msg.Type())

	// The parsed message must satisfy TunnelCarrier (it did not before the fix).
	carrier, ok := msg.(TunnelCarrier)
	require.True(t, ok, "parsed TunnelData must implement TunnelCarrier")

	require.Equal(t, wantID, carrier.GetTunnelID(), "GetTunnelID must return the wire tunnel ID")
	require.Len(t, carrier.GetTunnelData(), TunnelDataPayloadSize,
		"GetTunnelData must return the 1024-byte payload (IV + encrypted data), not the 1028-byte body")
	require.Equal(t, payload[:], carrier.GetTunnelData(), "payload must round-trip unchanged")

	// The base behavior must be preserved through the embedded base.
	require.NotEmpty(t, msg.MessageID())
	require.False(t, msg.Expiration().IsZero())
}

// TestInboundTunnelDataProcessedByProcessor feeds a serialized TunnelData
// through the processor and asserts it is delegated to the handler rather than
// rejected on the TunnelCarrier assertion.
func TestInboundTunnelDataProcessedByProcessor(t *testing.T) {
	var payload [TunnelDataPayloadSize]byte
	payload[0] = 0x42

	wire, err := func() ([]byte, error) {
		m := NewTunnelDataMessage(0x1234, payload)
		m.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))
		return MarshalMessageShort(m)
	}()
	require.NoError(t, err)

	msg, err := ParseInboundShortI2NP(wire)
	require.NoError(t, err)

	proc := NewMessageProcessor()
	proc.DisableExpirationCheck()
	handler := &mockTunnelDataHandler{}
	proc.SetTunnelDataHandler(handler)

	require.NoError(t, proc.ProcessMessage(msg), "processor must accept a parsed inbound TunnelData")
	require.True(t, handler.called, "TunnelData must be delegated to the handler")
}

// TestInboundTunnelDataStandardHeader covers the standard-header inbound path
// (tunnel-delivered / garlic-clove inner messages) so the promotion is proven
// consistent across both header formats.
func TestInboundTunnelDataStandardHeader(t *testing.T) {
	var payload [TunnelDataPayloadSize]byte
	payload[1023] = 0xFF
	const wantID buildrecord.TunnelID = 0x01020304

	m := NewTunnelDataMessage(wantID, payload)
	m.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))
	wire, err := m.MarshalBinary()
	require.NoError(t, err)

	msg, err := ParseInboundStandardI2NP(wire)
	require.NoError(t, err)

	carrier, ok := msg.(TunnelCarrier)
	require.True(t, ok, "standard-header TunnelData must implement TunnelCarrier")
	require.Equal(t, wantID, carrier.GetTunnelID())
	require.Equal(t, payload[:], carrier.GetTunnelData())
}

// TestInboundDataSatisfiesPayloadCarrier closes the same class of bug for Data
// (type 20), whose handler asserts PayloadCarrier. A bare base would fail it.
func TestInboundDataSatisfiesPayloadCarrier(t *testing.T) {
	payload := []byte("hello i2p application payload")

	m := NewDataMessage(payload)
	m.BaseI2NPMessage.SetExpiration(time.Now().Add(5 * time.Minute))
	wire, err := MarshalMessageShort(m)
	require.NoError(t, err)

	msg, err := ParseInboundShortI2NP(wire)
	require.NoError(t, err)
	require.Equal(t, I2NPMessageTypeData, msg.Type())

	carrier, ok := msg.(PayloadCarrier)
	require.True(t, ok, "parsed Data message must implement PayloadCarrier")
	require.Equal(t, payload, carrier.GetPayload(), "GetPayload must return the length-prefixed payload")
}

// TestInboundParseMalformedTunnelDataFallsBackToBase proves a malformed
// TunnelData body does not become a hard transport error: the bare base is
// returned, so the downstream handler rejects it on the carrier/size check
// exactly as before.
func TestInboundParseMalformedTunnelDataFallsBackToBase(t *testing.T) {
	// Short header declaring type 18 but a body that is not 1028 bytes.
	base := NewBaseI2NPMessage(I2NPMessageTypeTunnelData)
	base.SetMessageID(0x99)
	base.SetExpiration(time.Now().Add(5 * time.Minute))
	base.SetData([]byte{0x01, 0x02, 0x03}) // too short for a real TunnelData body
	wire, err := base.MarshalShortI2NP()
	require.NoError(t, err)

	msg, err := ParseInboundShortI2NP(wire)
	require.NoError(t, err, "malformed body must not error at the transport boundary")
	_, ok := msg.(TunnelCarrier)
	require.False(t, ok, "a malformed TunnelData body must fall back to the bare base (no TunnelCarrier)")
}
