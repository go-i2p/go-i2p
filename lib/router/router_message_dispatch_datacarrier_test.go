// Regression test for the sourcedMessage wrapper's DataCarrier forwarding.
//
// The router wraps every inbound tunnel-build message (types 23/25/26) in
// sourcedMessage to thread the delivering peer (the previous hop). Because
// sourcedMessage embeds the i2np.Message *interface* — which does not declare
// GetData() — the concrete *BaseI2NPMessage's GetData() was not promoted, so
// the processor's DataCarrier assertion in extractBuildMessageData failed and
// inbound ShortTunnelBuild (type 25) requests were rejected before their build
// records were parsed.
package router

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/require"
)

// TestSourcedMessageForwardsDataCarrier verifies that wrapping a build message
// in sourcedMessage preserves DataCarrier, so the processor can extract the
// build record body.
func TestSourcedMessageForwardsDataCarrier(t *testing.T) {
	body := make([]byte, 1+4*i2np.ShortBuildRecordSize)
	body[0] = 4

	base := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeShortTunnelBuild)
	base.SetMessageID(0x11223344)
	base.SetData(body)

	// Sanity: the unwrapped message already satisfies DataCarrier.
	_, ok := i2np.Message(base).(i2np.DataCarrier)
	require.True(t, ok)

	var source common.Hash
	source[0] = 0xAB
	wrapped := &sourcedMessage{Message: base, source: source}

	// The wrapper must satisfy DataCarrier (it did not before the fix).
	carrier, ok := i2np.Message(wrapped).(i2np.DataCarrier)
	require.True(t, ok, "sourcedMessage must implement DataCarrier")
	require.Equal(t, body, carrier.GetData(), "GetData must forward the underlying record body")

	// Source attribution must still work.
	sp, ok := i2np.Message(wrapped).(i2np.SourceHashProvider)
	require.True(t, ok)
	require.Equal(t, source, sp.SourceHash())
}
