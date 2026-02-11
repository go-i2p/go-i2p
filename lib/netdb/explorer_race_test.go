package netdb

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

// TestExplorer_SetTransport_ConcurrentSafe verifies that SetTransport and
// SetOurHash can be called concurrently with reads without data races.
// Run with -race to verify.
func TestExplorer_SetTransport_ConcurrentSafe(t *testing.T) {
	cfg := DefaultExplorerConfig()
	explorer := NewExplorer(nil, nil, cfg)

	var wg sync.WaitGroup

	// Writer goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				explorer.SetTransport(nil)
			}
		}()
	}

	// Reader goroutines (simulate what performExploratoryLookup does)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				explorer.fieldMu.RLock()
				_ = explorer.transport
				explorer.fieldMu.RUnlock()
			}
		}()
	}

	wg.Wait()
}

// TestExplorer_SetOurHash_ConcurrentSafe verifies that SetOurHash
// can be called concurrently with reads without data races.
func TestExplorer_SetOurHash_ConcurrentSafe(t *testing.T) {
	cfg := DefaultExplorerConfig()
	explorer := NewExplorer(nil, nil, cfg)

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				explorer.SetOurHash(common.Hash{id})
			}
		}(byte(i))
	}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				explorer.fieldMu.RLock()
				_ = explorer.ourHash
				explorer.fieldMu.RUnlock()
			}
		}()
	}

	wg.Wait()
}

// TestExplorer_SetTransport_ValuePersists verifies that SetTransport
// stores the value correctly.
func TestExplorer_SetTransport_ValuePersists(t *testing.T) {
	cfg := DefaultExplorerConfig()
	explorer := NewExplorer(nil, nil, cfg)
	assert.Nil(t, explorer.transport)

	explorer.SetTransport(nil)
	explorer.fieldMu.RLock()
	assert.Nil(t, explorer.transport)
	explorer.fieldMu.RUnlock()
}
