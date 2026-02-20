package i2np

import (
	"sync"
	"testing"
	"time"
)

// TestProcessMessage_NoDeadlockOnGarlicLocalDelivery verifies that processing
// a garlic message with a LOCAL delivery clove does not deadlock when a
// concurrent goroutine calls a Set* method (which acquires a write lock).
//
// Before the fix, ProcessMessage held RLock for the entire dispatch.
// Garlic LOCAL delivery recursively called ProcessMessage, which tried to
// re-acquire RLock. If a writer was waiting between the two RLock calls,
// Go's RWMutex would deadlock: the writer blocks on the outer RLock,
// and the inner RLock blocks on the waiting writer.
func TestProcessMessage_NoDeadlockOnGarlicLocalDelivery(t *testing.T) {
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()

	// Create a simple Data message to be wrapped as a LOCAL delivery clove.
	innerMsg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	innerMsg.data = []byte("test-payload")

	// Build a clove with LOCAL delivery type (0x00 in bits 6-5 of Flag).
	clove := GarlicClove{
		DeliveryInstructions: GarlicCloveDeliveryInstructions{
			Flag: 0x00, // LOCAL delivery: (Flag >> 5) & 0x03 == 0x00
		},
		I2NPMessage: innerMsg,
		CloveID:     1,
		Expiration:  time.Now().Add(5 * time.Minute),
	}

	done := make(chan struct{})
	var writerStarted sync.WaitGroup
	writerStarted.Add(1)

	// Start a goroutine that repeatedly calls a Set* method (acquires write lock).
	// This is the scenario that triggers the deadlock with the old code.
	go func() {
		writerStarted.Done()
		for {
			select {
			case <-done:
				return
			default:
				// SetDatabaseManager acquires p.mu.Lock() (write lock).
				// With the old code, this would block if ProcessMessage
				// held RLock, and then the recursive ProcessMessage call
				// would deadlock trying to re-acquire RLock.
				processor.SetDatabaseManager(nil)
			}
		}
	}()

	writerStarted.Wait()

	// Give the writer goroutine a moment to start competing for the lock.
	time.Sleep(time.Millisecond)

	// Process the clove, which will call handleLocalDelivery → ProcessMessage.
	// With the fix, ProcessMessage releases RLock before dispatch, so this
	// re-entrant call acquires its own independent RLock and completes.
	//
	// We run this in a goroutine with a timeout to detect deadlocks.
	result := make(chan error, 1)
	go func() {
		processor.processGarlicCloves([]GarlicClove{clove})
		result <- nil
	}()

	select {
	case <-result:
		// Success: no deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: processGarlicCloves did not complete within 5 seconds; " +
			"garlic LOCAL delivery re-entrancy likely caused a deadlock")
	}

	close(done)
}

// TestProcessMessage_ConcurrentSetAndProcess verifies that ProcessMessage and
// Set* methods can be called concurrently without data races or deadlocks.
func TestProcessMessage_ConcurrentSetAndProcess(t *testing.T) {
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup

	// Start multiple goroutines calling ProcessMessage concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
			msg.data = []byte("concurrent-test")
			for j := 0; j < iterations; j++ {
				_ = processor.ProcessMessage(msg)
			}
		}()
	}

	// Concurrently call Set* methods to exercise the write lock path.
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				processor.SetDatabaseManager(nil)
				processor.SetSearchReplyHandler(nil)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed without deadlock.
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK: concurrent ProcessMessage + Set* did not complete within 10 seconds")
	}
}

// TestProcessMessage_ReentrantLocalDelivery verifies that a garlic clove
// with LOCAL delivery correctly processes the inner message.
func TestProcessMessage_ReentrantLocalDelivery(t *testing.T) {
	processor := NewMessageProcessor()
	processor.DisableExpirationCheck()

	// Create an inner Data message.
	innerMsg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	innerMsg.data = []byte("inner-payload")

	clove := GarlicClove{
		DeliveryInstructions: GarlicCloveDeliveryInstructions{
			Flag: 0x00, // LOCAL delivery
		},
		I2NPMessage: innerMsg,
		CloveID:     42,
		Expiration:  time.Now().Add(5 * time.Minute),
	}

	// processGarlicCloves → processSingleClove → routeCloveByType →
	// handleLocalDelivery → ProcessMessage → processDataMessage
	//
	// This exercises the full re-entrant path. If it completes without
	// panic or deadlock, the fix is working.
	result := make(chan struct{}, 1)
	go func() {
		processor.processGarlicCloves([]GarlicClove{clove})
		result <- struct{}{}
	}()

	select {
	case <-result:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("Re-entrant LOCAL delivery did not complete within 5 seconds")
	}
}
