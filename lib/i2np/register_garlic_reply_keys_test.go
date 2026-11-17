package i2np

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// countingRegistrar is a minimal GarlicKeyRegistrar that records how many
// one-time garlic keys were registered.
type countingRegistrar struct {
	count int
}

func (c *countingRegistrar) RegisterOneTimeGarlicKey(tag [8]byte, key [32]byte) {
	c.count++
}

// TestRegisterGarlicReplyKeys_GatedOnOBEPFlag is the I2P-B-2 guard: the creator
// must register a one-time garlic reply key only when the build's last hop is
// actually an OBEP (outbound build). For an inbound build the last hop is a
// plain participant that never sends a garlic-wrapped reply, so registering a
// key there would leave a dead entry that is never consumed.
func TestRegisterGarlicReplyKeys_GatedOnOBEPFlag(t *testing.T) {
	tm := &TunnelManager{}

	// A non-empty preReplyCKs slice is required to reach the registration path.
	preReplyCKs := make([][x25519KeySize]byte, 3)

	// Outbound build: last hop is OBEP -> exactly one key registered.
	reg := &countingRegistrar{}
	tm.SetGarlicKeyRegistrar(reg)
	err := tm.registerGarlicReplyKeys(preReplyCKs, true, 42, 1)
	assert.NoError(t, err, "registerGarlicReplyKeys(outbound) error")
	assert.Equal(t, 1, reg.count, "outbound build must register one garlic reply key")

	// Inbound build: last hop is not OBEP -> no key registered (no dead entry).
	reg2 := &countingRegistrar{}
	tm.SetGarlicKeyRegistrar(reg2)
	err = tm.registerGarlicReplyKeys(preReplyCKs, false, 43, 2)
	assert.NoError(t, err, "registerGarlicReplyKeys(inbound) error")
	assert.Equal(t, 0, reg2.count, "inbound build must not register a garlic reply key (I2P-B-2)")

	// Nil registrar is a no-op regardless of the flag.
	tm.SetGarlicKeyRegistrar(nil)
	err = tm.registerGarlicReplyKeys(preReplyCKs, true, 44, 3)
	assert.NoError(t, err, "registerGarlicReplyKeys(nil registrar) error")
}
