package netdb

import (
	"context"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
)

// mockI2NPSender records queued messages for assertions.
type mockI2NPSender struct {
	mu       sync.Mutex
	messages []i2np.Message
	err      error
}

func (m *mockI2NPSender) QueueSendI2NP(msg i2np.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockI2NPSender) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

// mockSessionProvider returns a single shared sender for every peer.
type mockSessionProvider struct {
	sender *mockI2NPSender
	err    error
}

func (m *mockSessionProvider) GetSession(_ router_info.RouterInfo) (I2NPSender, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.sender, nil
}

func keyFromByte(b byte) common.Hash {
	var h common.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func TestDatabaseLookupClient_SynchronousReply(t *testing.T) {
	sender := &mockI2NPSender{}
	client := NewDatabaseLookupClient(&mockSessionProvider{sender: sender})

	target := keyFromByte(0x11)
	from := keyFromByte(0x22)
	lookup := i2np.NewDatabaseLookup(target, from, i2np.DatabaseLookupFlagTypeRI, nil)

	type result struct {
		data    []byte
		msgType int
		err     error
	}
	resCh := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		data, msgType, err := client.SendDatabaseLookup(ctx, router_info.RouterInfo{}, lookup)
		resCh <- result{data, msgType, err}
	}()

	// Wait for the message to actually be queued before delivering the reply,
	// proving the waiter was registered before send.
	waitFor(t, func() bool { return sender.count() == 1 })

	payload := []byte("router-info-body")
	if !client.DeliverLookupReply(target, i2np.I2NPMessageTypeDatabaseStore, payload) {
		t.Fatal("DeliverLookupReply returned false, expected a waiting lookup")
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("unexpected error: %v", res.err)
		}
		if res.msgType != i2np.I2NPMessageTypeDatabaseStore {
			t.Fatalf("msgType = %d, want %d", res.msgType, i2np.I2NPMessageTypeDatabaseStore)
		}
		if string(res.data) != string(payload) {
			t.Fatalf("data = %q, want %q", res.data, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendDatabaseLookup did not return after reply delivery")
	}
}

func TestDatabaseLookupClient_Timeout(t *testing.T) {
	sender := &mockI2NPSender{}
	client := NewDatabaseLookupClient(&mockSessionProvider{sender: sender})

	lookup := i2np.NewDatabaseLookup(keyFromByte(0x33), keyFromByte(0x44), i2np.DatabaseLookupFlagTypeRI, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := client.SendDatabaseLookup(ctx, router_info.RouterInfo{}, lookup)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Registry must be drained after the timed-out lookup unregisters.
	if n := registryCount(client); n != 0 {
		t.Fatalf("registry not drained after timeout: %d pending", n)
	}
}

func TestDatabaseLookupClient_MismatchedKeyDoesNotDeliver(t *testing.T) {
	sender := &mockI2NPSender{}
	client := NewDatabaseLookupClient(&mockSessionProvider{sender: sender})

	target := keyFromByte(0x55)
	lookup := i2np.NewDatabaseLookup(target, keyFromByte(0x66), i2np.DatabaseLookupFlagTypeRI, nil)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, _, err := client.SendDatabaseLookup(ctx, router_info.RouterInfo{}, lookup)
		done <- err
	}()
	waitFor(t, func() bool { return sender.count() == 1 })

	// Delivery for a DIFFERENT key must not satisfy the waiter.
	if client.DeliverLookupReply(keyFromByte(0x99), i2np.I2NPMessageTypeDatabaseStore, []byte("x")) {
		t.Fatal("delivery for wrong key incorrectly matched a waiter")
	}

	if err := <-done; err == nil {
		t.Fatal("expected timeout error for unmatched lookup, got nil")
	}
}

func TestDatabaseLookupClient_ParallelWaitersFIFO(t *testing.T) {
	sender := &mockI2NPSender{}
	client := NewDatabaseLookupClient(&mockSessionProvider{sender: sender})

	target := keyFromByte(0x77)

	const n = 3
	results := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			// Each query builds its own lookup message, matching production
			// (queryPeer creates a fresh DatabaseLookup per peer).
			lookup := i2np.NewDatabaseLookup(target, keyFromByte(0x88), i2np.DatabaseLookupFlagTypeRI, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, msgType, err := client.SendDatabaseLookup(ctx, router_info.RouterInfo{}, lookup)
			if err != nil {
				results <- -1
				return
			}
			results <- msgType
		}()
	}

	// All three concurrent lookups for the same target must register before we
	// deliver replies.
	waitFor(t, func() bool { return registryCount(client) == n })

	for i := 0; i < n; i++ {
		if !client.DeliverLookupReply(target, i2np.I2NPMessageTypeDatabaseSearchReply, []byte("s")) {
			t.Fatalf("delivery %d returned false, expected a waiter", i)
		}
	}

	for i := 0; i < n; i++ {
		select {
		case mt := <-results:
			if mt != i2np.I2NPMessageTypeDatabaseSearchReply {
				t.Fatalf("waiter got msgType %d, want %d", mt, i2np.I2NPMessageTypeDatabaseSearchReply)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("not all parallel waiters were satisfied")
		}
	}
}

func TestDatabaseLookupClient_DeliverNoWaiterReturnsFalse(t *testing.T) {
	client := NewDatabaseLookupClient(&mockSessionProvider{sender: &mockI2NPSender{}})
	if client.DeliverLookupReply(keyFromByte(0x01), i2np.I2NPMessageTypeDatabaseStore, []byte("x")) {
		t.Fatal("DeliverLookupReply returned true with no registered waiter")
	}
}

func TestLookupReplyRegistry_Bound(t *testing.T) {
	r := newLookupReplyRegistry()
	chans := make([]chan lookupResponse, 0, maxPendingLookups)
	for i := 0; i < maxPendingLookups; i++ {
		ch := r.register(keyFromByte(byte(i % 256)))
		if ch == nil {
			t.Fatalf("registration %d unexpectedly refused before cap", i)
		}
		chans = append(chans, ch)
	}
	// One past the cap must be refused.
	if r.register(keyFromByte(0xAB)) != nil {
		t.Fatal("registry exceeded maxPendingLookups bound")
	}
	// After unregistering one, a new registration must succeed again.
	r.unregister(keyFromByte(0), chans[0])
	if r.register(keyFromByte(0xCD)) == nil {
		t.Fatal("registry did not free a slot after unregister")
	}
}

func TestDatabaseLookupClient_SendError(t *testing.T) {
	provider := &mockSessionProvider{err: errSendFailure}
	client := NewDatabaseLookupClient(provider)
	lookup := i2np.NewDatabaseLookup(keyFromByte(0x10), keyFromByte(0x20), i2np.DatabaseLookupFlagTypeRI, nil)

	ctx := context.Background()
	_, _, err := client.SendDatabaseLookup(ctx, router_info.RouterInfo{}, lookup)
	if err == nil {
		t.Fatal("expected error when session provider fails")
	}
	// A failed send must not leak a registry entry.
	if n := registryCount(client); n != 0 {
		t.Fatalf("registry leaked after send failure: %d pending", n)
	}
}

// --- test helpers ---

var errSendFailure = &testError{"session unavailable"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func registryCount(c *DatabaseLookupClient) int {
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	return c.registry.count
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
