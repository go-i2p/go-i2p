package tunnel

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestManager_RefuseAllTransit_DefaultIsFalse verifies that a freshly
// constructed Manager does not refuse transit by default.
func TestManager_RefuseAllTransit_DefaultIsFalse(t *testing.T) {
	m := NewManagerWithConfig(testTunnelConfig())
	t.Cleanup(m.Stop)
	assert.False(t, m.RefuseAllTransit(), "default RefuseAllTransit must be false")
}

// TestManager_SetRefuseAllTransit_RejectsAllRequests verifies that enabling
// the refuse-all-transit policy causes ProcessBuildRequest to reject every
// request with BuildReplyCodeBandwidth and the well-known reason string.
func TestManager_SetRefuseAllTransit_RejectsAllRequests(t *testing.T) {
	m := NewManagerWithConfig(testTunnelConfig())
	t.Cleanup(m.Stop)

	m.SetRefuseAllTransit(true)
	assert.True(t, m.RefuseAllTransit(), "RefuseAllTransit must report true after enabling")

	var src common.Hash
	src[0] = 0xAB

	accepted, code, reason := m.ProcessBuildRequest(src)
	assert.False(t, accepted, "build request must be rejected when refuse-all-transit is set")
	assert.Equal(t, byte(BuildReplyCodeBandwidth), code,
		"reject code must be BANDWIDTH (30) per I2P spec")
	assert.Equal(t, "transit_refused", reason)
}

// TestManager_SetRefuseAllTransit_TogglesBack verifies that disabling the
// refuse policy restores normal acceptance behaviour.
func TestManager_SetRefuseAllTransit_TogglesBack(t *testing.T) {
	m := NewManagerWithConfig(testTunnelConfig())
	t.Cleanup(m.Stop)

	m.SetRefuseAllTransit(true)
	m.SetRefuseAllTransit(false)
	assert.False(t, m.RefuseAllTransit(), "RefuseAllTransit must report false after disabling")

	var src common.Hash
	accepted, _, _ := m.ProcessBuildRequest(src)
	assert.True(t, accepted, "build request must be accepted again after refuse policy is cleared")
}
