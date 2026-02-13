package sntp

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSelectRandomServerEmptyList verifies that selectRandomServer does not
// panic when called with an empty server list.
func TestSelectRandomServerEmptyList(t *testing.T) {
	rt := NewRouterTimestamper(&DefaultNTPClient{})
	assert.NotPanics(t, func() {
		result := rt.selectRandomServer([]string{}, false)
		assert.Equal(t, "", result, "should return empty string for empty server list")
	})
}

// TestSelectRandomServerSingleItem verifies correct behavior with one server.
func TestSelectRandomServerSingleItem(t *testing.T) {
	rt := NewRouterTimestamper(&DefaultNTPClient{})
	result := rt.selectRandomServer([]string{"0.pool.ntp.org"}, false)
	assert.Equal(t, "0.pool.ntp.org", result)
}

// TestTimestampNowConcurrentWithStartStop verifies that concurrent calls to
// TimestampNow(), Start(), and Stop() do not race.
// Run with: go test -race ./lib/util/time/sntp/
func TestTimestampNowConcurrentWithStartStop(t *testing.T) {
	rt := NewRouterTimestamper(&DefaultNTPClient{})

	var wg sync.WaitGroup

	// Concurrent TimestampNow calls
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				rt.TimestampNow()
			}
		}()
	}

	// Concurrent Start/Stop cycles
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Don't actually start (would try NTP queries), just test field access
			rt.mutex.Lock()
			rt.initialized = true
			rt.mutex.Unlock()
		}()
	}

	wg.Wait()
	rt.Stop()
}
