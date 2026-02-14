package ntcp2

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

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

func TestRekeyState_ResetCounters(t *testing.T) {
	rs := newRekeyState()
	for i := 0; i < 100; i++ {
		rs.recordSent()
	}
	assert.Equal(t, uint64(100), rs.totalMessages())
	assert.Equal(t, uint64(0), rs.getRekeyCount())

	rs.resetCounters()
	assert.Equal(t, uint64(0), rs.totalMessages())
	assert.Equal(t, uint64(1), rs.getRekeyCount())
}

func TestRekeyState_NeedsRekey_BelowThreshold(t *testing.T) {
	rs := newRekeyState()
	for i := 0; i < 100; i++ {
		rs.recordSent()
	}
	assert.False(t, rs.needsRekey())
}

func TestRekeyState_NeedsRekey_AtThreshold(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold)
	assert.True(t, rs.needsRekey())
}

func TestRekeyState_NeedsRekey_AboveThreshold(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold+100)
	assert.True(t, rs.needsRekey())
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

// --- mockRekeyConn for testing attemptRekey ---

type mockRekeyConn struct {
	rekeys   int
	failNext bool
}

func (m *mockRekeyConn) Rekey() error {
	if m.failNext {
		return errors.New("rekey failed")
	}
	m.rekeys++
	return nil
}

// nonRekeyConn does NOT implement Rekeyer
type nonRekeyConn struct{}

// --- attemptRekey tests ---

func TestAttemptRekey_ConnDoesNotImplementRekeyer(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold)
	require.True(t, rs.needsRekey())

	conn := &nonRekeyConn{}
	result := attemptRekey(conn, rs)

	assert.False(t, result, "should return false when conn does not implement Rekeyer")
	assert.Equal(t, uint64(0), rs.totalMessages(), "counters should be reset even when rekeying unavailable")
	assert.Equal(t, uint64(1), rs.getRekeyCount(), "rekey count should still increment")
}

func TestAttemptRekey_ConnImplementsRekeyer_Success(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold)

	conn := &mockRekeyConn{}
	result := attemptRekey(conn, rs)

	assert.True(t, result, "should return true when rekey succeeds")
	assert.Equal(t, 1, conn.rekeys, "should have called Rekey() once")
	assert.Equal(t, uint64(0), rs.totalMessages(), "counters should be reset")
	assert.Equal(t, uint64(1), rs.getRekeyCount())
}

func TestAttemptRekey_ConnImplementsRekeyer_Failure(t *testing.T) {
	rs := newRekeyState()
	atomic.StoreUint64(&rs.messagesSent, RekeyThreshold)

	conn := &mockRekeyConn{failNext: true}
	result := attemptRekey(conn, rs)

	assert.False(t, result, "should return false when rekey fails")
	assert.Equal(t, 0, conn.rekeys, "should not have incremented rekey count on conn")
	// Counters must NOT be reset on failure so the next message triggers another attempt
	assert.Equal(t, RekeyThreshold, rs.totalMessages(), "counters should remain above threshold after failure")
	assert.Equal(t, uint64(0), rs.getRekeyCount(), "state rekey count should not increment on failure")
}

func TestAttemptRekey_MultipleRekeys(t *testing.T) {
	rs := newRekeyState()
	conn := &mockRekeyConn{}

	for i := 0; i < 5; i++ {
		atomic.StoreUint64(&rs.messagesSent, RekeyThreshold)
		result := attemptRekey(conn, rs)
		assert.True(t, result)
		assert.Equal(t, uint64(0), rs.totalMessages())
	}

	assert.Equal(t, 5, conn.rekeys)
	assert.Equal(t, uint64(5), rs.getRekeyCount())
}

// --- Rekeyer interface compile-time check ---

var _ Rekeyer = (*mockRekeyConn)(nil)

// --- RekeyThreshold value test ---

func TestRekeyThreshold_Value(t *testing.T) {
	// Verify threshold is just under 2^16 as documented
	assert.Equal(t, uint64(65535), RekeyThreshold)
}
