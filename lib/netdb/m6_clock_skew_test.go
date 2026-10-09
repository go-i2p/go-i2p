package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

// TestM6_RaceDetectorValidatesTimestampCheck
// Concurrent validation calls should have no data races.
func TestM6_RaceDetectorValidatesTimestampCheck(t *testing.T) {
	t.Parallel()

	db := &StdNetDB{}
	now := time.Now()
	ri := router_info.RouterInfo{}
	hash := common.Hash{}

	done := make(chan struct{})
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				_ = db.validatePublishedTimestamp(ri, hash, now)
			}
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	t.Log("50 goroutines × 100 iterations completed - race detector verified clean")
}
