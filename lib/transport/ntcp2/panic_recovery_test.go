package ntcp2

import (
	"context"
	"net"
	"testing"

	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// panickingConn is a net.Conn whose Read panics, standing in for a block
// unframer that trips over malformed remote input. It gives a deterministic,
// remote-input-shaped panic at the point the I2P-004 receive-worker seam must
// contain.
type panickingConn struct {
	mockConn
}

func (c *panickingConn) Read(_ []byte) (int, error) {
	panic("simulated unframer panic on remote input")
}

// TestReceiveNextMessageWithRecovery proves the I2P-004 ntcp2 seam: a panic
// raised while reading/framing one inbound message must be recovered, the
// message dropped, and the receive worker told to keep going (returns true),
// rather than propagating and killing the worker goroutine and the process.
func TestReceiveNextMessageWithRecovery(t *testing.T) {
	conn := &panickingConn{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	session := NewNTCP2Session(conn, ctx, logger.WithField("test", t.Name()))

	unframer := session.createBlockUnframer()

	// The inner call must panic — this is the panic the seam exists to catch.
	require.Panics(t, func() {
		_ = session.processNextInboundMessageFromBlocks(unframer)
	})

	// The recovery wrapper must swallow it and signal the worker to continue.
	var keepGoing bool
	assert.NotPanics(t, func() {
		keepGoing = session.receiveNextMessageWithRecovery(unframer)
	}, "receiveNextMessageWithRecovery must recover panics from the read path")
	assert.True(t, keepGoing, "a recovered panic must drop the message and keep the worker alive")
}

// compile-time guard: panickingConn satisfies net.Conn.
var _ net.Conn = (*panickingConn)(nil)
