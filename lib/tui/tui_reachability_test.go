package tui

// tui_reachability_test.go covers the reachability status line features.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_DefaultReachabilityUnknown verifies that a freshly created model
// starts in the Unknown reachability state.
func TestNew_DefaultReachabilityUnknown(t *testing.T) {
	m := New("pass", "127.0.0.1:7650")
	assert.Equal(t, ReachabilityUnknown, m.reachabilityStatus)
}

// TestUpdate_ReachabilityStatusMsg verifies that sending a ReachabilityStatusMsg
// updates the model's reachability state.
func TestUpdate_ReachabilityStatusMsg(t *testing.T) {
	m := New("pass", "127.0.0.1:7650")
	updated, _ := m.Update(ReachabilityStatusMsg{State: ReachabilityHidden})
	wm, ok := updated.(WrapperModel)
	require.True(t, ok)
	assert.Equal(t, ReachabilityHidden, wm.reachabilityStatus)
}

// TestUpdate_AllReachabilityStates verifies each defined state is accepted.
func TestUpdate_AllReachabilityStates(t *testing.T) {
	states := []ReachabilityState{
		ReachabilityUnknown,
		ReachabilityHidden,
		ReachabilityFirewalled,
		ReachabilityIPv4,
		ReachabilityIPv6,
	}
	for _, state := range states {
		m := New("pass", "127.0.0.1:7650")
		updated, _ := m.Update(ReachabilityStatusMsg{State: state})
		wm, ok := updated.(WrapperModel)
		require.True(t, ok, "state: %s", state)
		assert.Equal(t, state, wm.reachabilityStatus, "state: %s", state)
	}
}

// TestRenderReachabilityStatus_ContainsState verifies the status line includes
// the state label.
func TestRenderReachabilityStatus_ContainsState(t *testing.T) {
	m := New("pass", "127.0.0.1:7650")
	m.reachabilityStatus = ReachabilityIPv4

	line := m.renderReachabilityStatus()
	assert.True(t, strings.Contains(line, "Reachable IPv4"), "status line should contain state: %q", line)
	assert.True(t, strings.Contains(line, "Network:"), "status line should contain 'Network:' prefix: %q", line)
}

// TestView_ContainsStatusLine verifies that View() appends the reachability
// status line to the output.
func TestView_ContainsStatusLine(t *testing.T) {
	m := New("pass", "127.0.0.1:7650")
	m.reachabilityStatus = ReachabilityFirewalled

	view := m.View()
	assert.True(t, strings.Contains(view, "Network:"), "view should contain 'Network:' status line")
}
