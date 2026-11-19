// Regression tests for inbound ShortTunnelBuild (type 25) DataCarrier handling.
//
// Live symptom: a go-i2p router acting as a tunnel hop rejected every inbound
// ShortTunnelBuild from an i2pd peer with "tunnel build message does not
// implement DataCarrier", so i2pd reported "Test of tunnel failed" and go-i2p
// never reported tunnels_participating > 0.
package i2np

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// newSerializedShortTunnelBuild builds a wire-format ShortTunnelBuild (type 25)
// carrying `count` 218-byte records, using the live outbound serializer.
func newSerializedShortTunnelBuild(t *testing.T, count int) []byte {
	t.Helper()
	factory := NewBuildMessageFactory()
	records := make([][]byte, count)
	for i := range records {
		rec := make([]byte, ShortBuildRecordSize)
		rec[0] = byte(0xA0 + i)
		records[i] = rec
	}
	serialized, err := factory.CreateShortTunnelBuildMessage(records, 0x11223344)
	require.NoError(t, err)
	return serialized
}

// TestInboundShortTunnelBuildSatisfiesDataCarrier parses a serialized
// ShortTunnelBuild (type 25) the way the NTCP2/SSU2 inbound path does and
// asserts the parsed message satisfies DataCarrier and that
// extractBuildMessageData returns the non-empty record body.
func TestInboundShortTunnelBuildSatisfiesDataCarrier(t *testing.T) {
	serialized := newSerializedShortTunnelBuild(t, 4)

	// Inbound NTCP2/SSU2 parse target: BaseI2NPMessage.UnmarshalBinary.
	msg := &BaseI2NPMessage{}
	require.NoError(t, msg.UnmarshalBinary(serialized))
	require.Equal(t, I2NPMessageTypeShortTunnelBuild, msg.Type())

	// The parsed message must satisfy DataCarrier.
	var asMessage Message = msg
	carrier, ok := asMessage.(DataCarrier)
	require.True(t, ok, "parsed ShortTunnelBuild must implement DataCarrier")
	require.NotEmpty(t, carrier.GetData())

	// And the processor's extraction path must return the record body.
	processor := NewMessageProcessor()
	data, err := processor.extractBuildMessageData(msg)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	require.Equal(t, 1+4*ShortBuildRecordSize, len(data))
	require.Equal(t, byte(4), data[0], "count byte must be 4")
}

// TestInboundVariableTunnelBuildSatisfiesDataCarrier covers the same extraction
// contract for VariableTunnelBuild (type 23), which shares the build-request
// extraction path. The message body is a count-prefixed record list, identical
// in shape to type 25.
func TestInboundVariableTunnelBuildSatisfiesDataCarrier(t *testing.T) {
	body := make([]byte, 1+3*ShortBuildRecordSize)
	body[0] = 3

	msg := NewBaseI2NPMessage(I2NPMessageTypeVariableTunnelBuild)
	msg.SetMessageID(0x55667788)
	msg.SetData(body)

	var asMessage Message = msg
	_, ok := asMessage.(DataCarrier)
	require.True(t, ok, "parsed VariableTunnelBuild must implement DataCarrier")

	processor := NewMessageProcessor()
	data, err := processor.extractBuildMessageData(msg)
	require.NoError(t, err)
	require.NotEmpty(t, data)
}
