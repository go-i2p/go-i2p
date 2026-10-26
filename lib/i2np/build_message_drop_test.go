// Regression tests for the dispatch of the four 528-byte-record tunnel build
// message types (21/22/23/24), which this router recognises and drops rather
// than implements. See the "Tunnel build message coverage (known gap)" section
// of doc.go for why the gap exists and why it is NOT a deprecation allowance.

package i2np

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessMessageDispatch_LongRecordBuildTypesAreDroppedNotUnknown pins the
// A1/A2 handling: types 21, 22, 23 and 24 must be dropped without an error, and
// must never be reported as "unknown message type". Before this change 21/22
// fell through to the default branch, which logged at Error level and returned
// oops.Errorf("unknown message type: %d") — mislabelling a message type the
// specification defines (i2np.rst:691-694) and producing an observable,
// fingerprintable deviation from a conforming router.
func TestProcessMessageDispatch_LongRecordBuildTypesAreDroppedNotUnknown(t *testing.T) {
	processor := NewMessageProcessor()

	for _, msgType := range []int{
		I2NPMessageTypeTunnelBuild,
		I2NPMessageTypeTunnelBuildReply,
		I2NPMessageTypeVariableTunnelBuild,
		I2NPMessageTypeVariableTunnelBuildReply,
	} {
		t.Run(specNameForBuildType(msgType), func(t *testing.T) {
			msg := NewBaseI2NPMessage(msgType)
			msg.SetMessageID(4242)

			err := processor.processMessageDispatch(msg, 0)
			require.NoError(t, err,
				"long-record build type %d must be dropped silently, not error", msgType)
		})
	}
}

// TestI2NPBuildTypeConstantsMatchSpecRegistry pins the type bytes against
// i2np.rst:683-696 so a future edit cannot renumber them. The registry's fourth
// column is "Since", not deprecation: 21/22 read "deprecated" while 23/24 read
// "0.7.12", and the normative Notes for 21/22 (:1581-1583, :1607-1609) say they
// "has not been deprecated. Routers must implement."
func TestI2NPBuildTypeConstantsMatchSpecRegistry(t *testing.T) {
	assert.Equal(t, 21, I2NPMessageTypeTunnelBuild)
	assert.Equal(t, 22, I2NPMessageTypeTunnelBuildReply)
	assert.Equal(t, 23, I2NPMessageTypeVariableTunnelBuild)
	assert.Equal(t, 24, I2NPMessageTypeVariableTunnelBuildReply)
	assert.Equal(t, 25, I2NPMessageTypeShortTunnelBuild)
	assert.Equal(t, 26, I2NPMessageTypeOutboundTunnelBuildReply)
}

// TestProcessMessageDispatch_UnknownTypeStillErrors guards the boundary of the
// drop behaviour: an unregistered type is still an error, so the new silent drop
// is scoped to the four defined long-record build messages and not widened to
// arbitrary input.
func TestProcessMessageDispatch_UnknownTypeStillErrors(t *testing.T) {
	processor := NewMessageProcessor()

	// 27 is absent from the spec's message registry (i2np.rst:683-696 jumps from
	// OutboundTunnelBuildReply 26 to the reserved ranges), so it is genuinely
	// unknown rather than a defined-but-unimplemented type.
	msg := NewBaseI2NPMessage(27)
	err := processor.processMessageDispatch(msg, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

func specNameForBuildType(t int) string {
	switch t {
	case I2NPMessageTypeTunnelBuild:
		return "TunnelBuild"
	case I2NPMessageTypeTunnelBuildReply:
		return "TunnelBuildReply"
	case I2NPMessageTypeVariableTunnelBuild:
		return "VariableTunnelBuild"
	default:
		return "VariableTunnelBuildReply"
	}
}
