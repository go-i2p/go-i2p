package sntp

import (
	"testing"
	"time"
)

// setupTimestamperWithMock creates a RouterTimestamper backed by a MockNTPClient
// with the given clock offset and a MockListener already registered.
func setupTimestamperWithMock(t *testing.T, offset time.Duration) (*RouterTimestamper, *MockListener) {
	t.Helper()
	listener := &MockListener{}
	mockClient := &MockNTPClient{ClockOffset: offset}
	timestamper := NewRouterTimestamper(mockClient)
	timestamper.AddListener(listener)
	return timestamper, listener
}

// queryTimeAndAssertSuccess runs queryTime on the timestamper with a default
// server list and asserts that the query succeeded.
func queryTimeAndAssertSuccess(t *testing.T, timestamper *RouterTimestamper) {
	t.Helper()
	servers := []string{"pool.ntp.org"}
	success := timestamper.queryTime(servers, 5*time.Second, false)
	if !success {
		t.Fatal("Expected queryTime to succeed")
	}
}

// assertListenerGotUpdates asserts that the listener received at least one
// time update.
func assertListenerGotUpdates(t *testing.T, listener *MockListener) {
	t.Helper()
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.updates) == 0 {
		t.Fatal("Expected listener to receive time update")
	}
}
