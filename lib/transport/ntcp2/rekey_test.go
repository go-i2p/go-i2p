// Tests for NTCP2 message-count tracking and threshold-based session
// replacement. NTCP2 has no in-band mid-session rekey, so the compliant
// behaviour is to retire a session once it crosses RekeyThreshold and let the
// transport re-handshake.

package ntcp2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- rekeyState unit tests ---

func TestRekeyState_RecordSent(t *testing.T) {
	rs := newRekeyState()
	total := rs.recordSent()
	assert.Equal(t, uint64(1), total)
	assert.Equal(t, uint64(1), rs.totalMessages())
}

func TestRekeyState_RecordReceived(t *testing.T) {
	rs := newRekeyState()
	total := rs.recordReceived()
	assert.Equal(t, uint64(1), total)
	assert.Equal(t, uint64(1), rs.totalMessages())
}

func TestRekeyState_MixedCounting(t *testing.T) {
	rs := newRekeyState()
	rs.recordSent()
	rs.recordSent()
	rs.recordReceived()
	assert.Equal(t, uint64(3), rs.totalMessages())
}

func TestRekeyState_NeedsReplacement_BelowThreshold(t *testing.T) {
	rs := newRekeyState()
	for i := 0; i < 100; i++ {
		rs.recordSent()
	}
	assert.False(t, rs.needsReplacement())
}

func TestRekeyState_NeedsReplacement_AtThreshold(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold)
	assert.True(t, rs.needsReplacement())
}

func TestRekeyState_NeedsReplacement_AboveThreshold(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold+100)
	assert.True(t, rs.needsReplacement())
}

func TestRekeyState_ConcurrentAccess(t *testing.T) {
	rs := newRekeyState()
	var wg sync.WaitGroup
	const goroutines = 10
	const messagesPerGoroutine = 1000

	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				rs.recordSent()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				rs.recordReceived()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, uint64(goroutines*messagesPerGoroutine*2), rs.totalMessages())
}

// --- tryTriggerReplacement is one-shot ---

func TestRekeyState_TryTriggerReplacement_FirstWins(t *testing.T) {
	rs := newRekeyState()

	require.True(t, rs.tryTriggerReplacement(), "first caller must win the trigger")
	assert.Equal(t, uint64(1), rs.getReplacementCount())

	// Subsequent calls must not re-trigger: a session is replaced at most once.
	for i := 0; i < 5; i++ {
		assert.False(t, rs.tryTriggerReplacement(), "trigger must be one-shot")
	}
	assert.Equal(t, uint64(1), rs.getReplacementCount(), "replacement count stays at 1")
}

// Validates that concurrent workers crossing the threshold together schedule
// exactly one replacement.
func TestRekeyState_TryTriggerReplacement_ConcurrentSingleWinner(t *testing.T) {
	rs := newRekeyState()

	const workers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	winners := make([]bool, workers)

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			winners[idx] = rs.tryTriggerReplacement()
		}(i)
	}
	close(start)
	wg.Wait()

	var won int
	for _, w := range winners {
		if w {
			won++
		}
	}
	assert.Equal(t, 1, won, "exactly one worker may claim the replacement")
	assert.Equal(t, uint64(1), rs.getReplacementCount())
}

// --- RekeyThreshold value ---

// Validates that the replacement threshold is 65535, just under 2^16, so a
// session is retired well before the Noise nonce counters approach their
// limit.
func TestRekeyThreshold_Value(t *testing.T) {
	assert.Equal(t, uint64(65535), RekeyThreshold)
}

// --- session-level replacement behaviour ---

// Validates that crossing the threshold closes the session (drop-and-restart)
// rather than rekeying it in place, and that the close is scheduled off the
// calling worker so a worker never joins itself.
func TestSession_CheckRekey_ReplacesSessionAtThreshold(t *testing.T) {
	s := newTestSession(t)

	// Drive the counters past the threshold without sending real traffic.
	atomic.StoreUint64(&s.rekeyState.messagesSent, RekeyThreshold)

	s.checkRekey(s.rekeyState.totalMessages())

	select {
	case <-s.GetContext().Done():
		// Session cancelled: the transport will re-handshake on next use.
	case <-time.After(5 * time.Second):
		t.Fatal("session context was not cancelled after crossing the rekey threshold")
	}

	total, replacements := s.GetTrafficStats()
	assert.Equal(t, uint64(1), replacements, "exactly one replacement must be recorded")
	assert.GreaterOrEqual(t, total, RekeyThreshold)
}

// Below the threshold the session must stay up.
func TestSession_CheckRekey_BelowThresholdKeepsSession(t *testing.T) {
	s := newTestSession(t)

	atomic.StoreUint64(&s.rekeyState.messagesSent, RekeyThreshold-1)
	total := s.rekeyState.totalMessages()
	s.checkRekey(total)

	select {
	case <-s.GetContext().Done():
		t.Fatal("session must not be replaced below the rekey threshold")
	default:
	}

	reportedTotal, replacements := s.GetTrafficStats()
	assert.Equal(t, uint64(0), replacements)
	assert.Equal(t, uint64(RekeyThreshold-1), reportedTotal)
}

// Concurrent threshold hits (send worker + receive worker) must produce a
// single replacement.
func TestSession_CheckRekey_ConcurrentTriggersSingleReplacement(t *testing.T) {
	s := newTestSession(t)

	atomic.StoreUint64(&s.rekeyState.messagesSent, RekeyThreshold)

	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			s.checkRekey(s.rekeyState.totalMessages())
		}()
	}
	wg.Wait()

	_, replacements := s.GetTrafficStats()
	assert.Equal(t, uint64(1), replacements, "only one replacement may be scheduled")

	select {
	case <-s.GetContext().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session context was not cancelled")
	}
}
