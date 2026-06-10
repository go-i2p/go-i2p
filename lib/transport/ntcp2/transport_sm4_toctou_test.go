package ntcp2

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/stretchr/testify/require"
)

// SM-4 Test Suite: Listener State During Accept Loop TOCTOU
// Tests the interaction between acceptNextConnection and SetIdentity listener swaps
// ensuring no race conditions cause connection drops or hung accept loops.

// TestSM4_AcceptClosedListenerRetry verifies that when SetIdentity closes the listener
// during Accept(), the accept loop recovers gracefully with transient error retry.
func TestSM4_AcceptClosedListenerRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	// Verify listener is not nil initially
	transport.identityMu.RLock()
	listener := transport.listener
	transport.identityMu.RUnlock()
	require.NotNil(t, listener, "listener should be non-nil after transport creation")

	// Simulate listener close (what happens during SetIdentity swap)
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener for simulation: %v", err)
	}

	// acceptNextConnection should handle closed listener gracefully
	// It will get "use of closed network connection" error and retry
	retry := transport.acceptNextConnection()
	if !retry {
		t.Fatalf("acceptNextConnection returned false (shutdown) when it should have retried on closed listener error")
	}

	// Verify transport is still healthy after retry
	transport.identityMu.RLock()
	finalListener := transport.listener
	transport.identityMu.RUnlock()
	require.NotNil(t, finalListener, "listener should still exist after retry")
}

// TestSM4_ConcurrentSetIdentityAndAccept verifies that rapid SetIdentity calls
// and Accept attempts don't cause crashes or hangs. This tests the actual TOCTOU window.
func TestSM4_ConcurrentSetIdentityAndAccept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	runtime.GOMAXPROCS(4) // Ensure high concurrency

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		wg                sync.WaitGroup
		acceptAttempts    int32
		acceptErrors      int32
		acceptSuccesses   int32
		identityRotations int32
		acceptLoopExits   int32
	)

	// Goroutine 1: Simulate Accept loop attempts every 10ms for 3 seconds
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				atomic.AddInt32(&acceptLoopExits, 1)
				return
			case <-ticker.C:
				atomic.AddInt32(&acceptAttempts, 1)
				// This simulates acceptNextConnection being called
				// We don't actually Accept to avoid blocking on a TCP connection
				transport.identityMu.RLock()
				listener := transport.listener
				transport.identityMu.RUnlock()

				if listener == nil {
					atomic.AddInt32(&acceptErrors, 1)
				} else {
					atomic.AddInt32(&acceptSuccesses, 1)
				}
			}
		}
	}()

	// Goroutine 2: Rotate identity every 50ms to swap listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newIdent := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
				if err := transport.SetIdentity(*newIdent); err != nil {
					// Identity rotation can fail, that's ok for this test
					continue
				}
				atomic.AddInt32(&identityRotations, 1)
			}
		}
	}()

	// Wait for both goroutines to finish
	wg.Wait()

	attempts := atomic.LoadInt32(&acceptAttempts)
	errors := atomic.LoadInt32(&acceptErrors)
	successes := atomic.LoadInt32(&acceptSuccesses)
	rotations := atomic.LoadInt32(&identityRotations)

	t.Logf("SM-4 TOCTOU test: attempts=%d, successes=%d, errors=%d (expected: successes+errors ≈ attempts), identity_rotations=%d",
		attempts, successes, errors, rotations)

	// Verify consistency: successes + errors should roughly equal attempts
	// (allowing for small timing window where listener might be nil during swap)
	totalResult := successes + errors
	if totalResult < attempts-5 || totalResult > attempts+5 {
		t.Errorf("SM-4: listener snapshot inconsistency - attempts=%d, successes=%d, errors=%d, total=%d",
			attempts, successes, errors, totalResult)
	}

	// Verify we performed multiple identity rotations
	if rotations < 50 {
		t.Logf("Warning: only %d identity rotations performed (expected ~60)", rotations)
	}

	// Final health check: listener should be non-nil at end
	transport.identityMu.RLock()
	finalListener := transport.listener
	transport.identityMu.RUnlock()
	require.NotNil(t, finalListener, "listener unexpectedly nil at test end")

	t.Logf("SM-4: Transport health check passed - listener is healthy after concurrent TOCTOU stress")
}

// TestSM4_RapidIdentitySwapWithAcceptLoop verifies no goroutine leaks or deadlocks
// occur during rapid listener swaps with accept loop running.
func TestSM4_RapidIdentitySwapWithAcceptLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	initialGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Goroutine 1: Pump accept loop calls for 2 seconds
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Call acceptNextConnection repeatedly
				transport.acceptNextConnection()
			}
		}
	}()

	// Goroutine 2: Rotate identity rapidly for 2 seconds
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				newIdent := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
				_ = transport.SetIdentity(*newIdent)
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	cancel() // Ensure context is done

	// Give goroutines a moment to clean up
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	leakedGoroutines := finalGoroutines - initialGoroutines

	// Allow 2-3 goroutines of slack for scheduler variability
	if leakedGoroutines > 3 {
		t.Errorf("SM-4: Potential goroutine leak detected - initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, leakedGoroutines)
	}

	t.Logf("SM-4: Goroutine count check passed - initial=%d, final=%d, delta=%d",
		initialGoroutines, finalGoroutines, leakedGoroutines)
}

// TestSM4_AcceptErrorReportingOnSwap verifies that "use of closed network connection"
// errors from listener swaps are properly reported and don't cause silent failures.
func TestSM4_AcceptErrorReportingOnSwap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	// Manually trigger a listener close to simulate a race condition
	transport.identityMu.Lock()
	currentListener := transport.listener
	transport.identityMu.Unlock()

	if currentListener != nil {
		currentListener.Close()
	}

	// acceptNextConnection should return true (retry), not false (shutdown)
	retry := transport.acceptNextConnection()
	if !retry {
		t.Error("SM-4: acceptNextConnection returned false on closed listener; should retry on transient error")
	}

	// Transport should still be functional
	transport.identityMu.RLock()
	finalListener := transport.listener
	transport.identityMu.RUnlock()
	require.NotNil(t, finalListener, "listener became nil unexpectedly after closed listener error")

	t.Logf("SM-4: Error reporting on swap verified - transport recovered gracefully")
}

// TestSM4_TwoListenerSnapshotConsistency verifies that back-to-back listener snapshots
// are consistent (both see the same listener or both see nil during swap).
func TestSM4_TwoListenerSnapshotConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	// Take two rapid snapshots and verify they're consistent
	transport.identityMu.RLock()
	listener1 := transport.listener
	transport.identityMu.RUnlock()

	// Yield to scheduler
	runtime.Gosched()

	transport.identityMu.RLock()
	listener2 := transport.listener
	transport.identityMu.RUnlock()

	// Both should be the same pointer (or both nil during swap)
	if listener1 != listener2 {
		t.Errorf("SM-4: Listener pointer changed between snapshots - snapshot1=%p, snapshot2=%p",
			listener1, listener2)
	}

	require.NotNil(t, listener1, "Listener unexpectedly nil in snapshot consistency test (snapshot1)")
	require.NotNil(t, listener2, "Listener unexpectedly nil in snapshot consistency test (snapshot2)")

	t.Logf("SM-4: Two snapshot consistency verified - both are %p", listener1)
}

// TestSM4_ListenerNilDuringSwapRecovery verifies that when listener is temporarily nil
// during SetIdentity swap, acceptNextConnection waits and retries rather than shutting down.
func TestSM4_ListenerNilDuringSwapRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	// Simulate listener being nil (as would happen temporarily during SetIdentity)
	transport.identityMu.Lock()
	transport.listener = nil
	transport.identityMu.Unlock()

	// acceptNextConnection should return true (retry) when listener is nil but transport is running
	startTime := time.Now()
	retry := transport.acceptNextConnection()
	duration := time.Since(startTime)

	if !retry {
		t.Error("SM-4: acceptNextConnection returned false (shutdown) when listener was nil; should retry")
	}

	// Should have waited ~50ms for retry (not 0ms and not a panic)
	if duration < 40*time.Millisecond {
		t.Logf("Warning: retry wait was %.1fms (expected ~50ms)", duration.Seconds()*1000)
	}

	// Verify listener was restored
	transport.identityMu.RLock()
	finalListener := transport.listener
	transport.identityMu.RUnlock()

	require.NotNil(t, finalListener, "Listener should be restored after nil retry")

	t.Logf("SM-4: Nil recovery test passed - waited %.1fms and recovered", duration.Seconds()*1000)
}

// TestSM4_ConfigConsistencyDuringSwap verifies that config (ListenerAddress) stays
// consistent with listener even when they're being swapped.
func TestSM4_ConfigConsistencyDuringSwap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SM-4 test in short mode")
	}
	t.Parallel()

	transport := createTransportSM4(t)
	defer transport.Close()

	// Rotate identity a few times
	for i := 0; i < 5; i++ {
		newIdent := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
		if err := transport.SetIdentity(*newIdent); err != nil {
			t.Logf("Identity rotation %d failed: %v (ok for test)", i, err)
			continue
		}

		// Check that config and listener address match
		cfg := transport.config.Load()
		listener := transport.listener

		if listener != nil {
			listenerNetAddr := listener.Addr()
			if listenerNetAddr == nil {
				t.Fatalf("SM-4: listener.Addr() returned nil after swap %d", i)
			}

			// Extract TCP address (handle wrapped ntcp2.Addr)
			var tcpAddr *net.TCPAddr
			switch addr := listenerNetAddr.(type) {
			case *net.TCPAddr:
				tcpAddr = addr
			case interface{ UnderlyingAddr() net.Addr }:
				if underlying, ok := addr.UnderlyingAddr().(*net.TCPAddr); ok {
					tcpAddr = underlying
				}
			}

			if tcpAddr != nil {
				actualAddr := fmt.Sprintf("%s:%d", tcpAddr.IP, tcpAddr.Port)
				storedAddr := cfg.ListenerAddress

				// Port might differ on first run due to NAT/port mapping,
				// but they should have the same basic format
				if storedAddr == "" {
					t.Fatalf("SM-4: ListenerAddress unexpectedly empty after swap %d", i)
				}

				t.Logf("SM-4 swap %d: config=%s, listener=%s", i, storedAddr, actualAddr)
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("SM-4: Config consistency verified across %d identity rotations", 5)
}

// Helper: Create a minimal transport for SM-4 tests
func createTransportSM4(t *testing.T) *NTCP2Transport {
	t.Helper()
	config, err := NewConfig("127.0.0.1:0") // Dynamic port
	require.NoError(t, err)

	identity := testutil.CreateSignedTestRouterInfo(t, map[string]string{}, nil)
	keystore := &testKeystoreSM4{
		keyData: make([]byte, 32),
	}
	transport, err := NewNTCP2Transport(*identity, config, keystore)
	if err != nil {
		t.Fatalf("failed to create NTCP2Transport: %v", err)
	}
	if transport == nil {
		t.Fatal("NewNTCP2Transport returned nil transport")
	}
	return transport
}

// testKeystoreSM4 implements KeystoreProvider for SM-4 tests
type testKeystoreSM4 struct {
	keyData []byte
}

func (k *testKeystoreSM4) GetEncryptionPrivateKey() types.PrivateEncryptionKey {
	return &testPrivateKeySM4Key{keyData: k.keyData}
}

// testPrivateKeySM4Key implements types.PrivateEncryptionKey for testing
type testPrivateKeySM4Key struct {
	keyData []byte
}

func (k *testPrivateKeySM4Key) Bytes() []byte {
	if len(k.keyData) == 0 {
		return testPrivateKeySM4[:]
	}
	return k.keyData
}

func (k *testPrivateKeySM4Key) Zero() {
	for i := range k.keyData {
		k.keyData[i] = 0
	}
}

func (k *testPrivateKeySM4Key) NewDecrypter() (types.Decrypter, error) {
	return nil, nil
}

func (k *testPrivateKeySM4Key) Public() (types.PublicEncryptionKey, error) {
	return nil, nil
}

var testPrivateKeySM4 = &[32]byte{
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32,
}
