package sntp

import (
	"github.com/beevik/ntp"
	"sync"
	"testing"
	"time"
)

type MockNTPClient struct {
	ClockOffset time.Duration
	Error       error
}

func (c *MockNTPClient) QueryWithOptions(host string, options ntp.QueryOptions) (*ntp.Response, error) {
	if c.Error != nil {
		return nil, c.Error
	}
	return &ntp.Response{
		ClockOffset: c.ClockOffset,
	}, nil
}

type MockListener struct {
	mu       sync.Mutex
	updates  []time.Time
	stratums []uint8
}

func (ml *MockListener) SetNow(now time.Time, stratum uint8) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.updates = append(ml.updates, now)
	ml.stratums = append(ml.stratums, stratum)
}

func TestRouterTimestamperInitialization(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)
	if timestamper == nil {
		t.Fatal("Expected RouterTimestamper instance, got nil")
	}
}

func TestAddAndRemoveListener(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)
	listener := &MockListener{}

	timestamper.AddListener(listener)
	if len(timestamper.listeners) != 1 {
		t.Errorf("Expected 1 listener, got %d", len(timestamper.listeners))
	}

	timestamper.RemoveListener(listener)
	if len(timestamper.listeners) != 0 {
		t.Errorf("Expected 0 listeners, got %d", len(timestamper.listeners))
	}
}

func TestTimestampNow(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)
	listener := &MockListener{}
	timestamper.AddListener(listener)

	// Mock Injection
	mockNTPClient := &MockNTPClient{
		ClockOffset: 1 * time.Second,
	}
	timestamper.ntpClient = mockNTPClient

	timestamper.Start()
	defer timestamper.Stop()

	timestamper.WaitForInitialization()

	// Trigger update
	timestamper.TimestampNow()

	time.Sleep(100 * time.Millisecond)

	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.updates) == 0 {
		t.Error("Expected at least one time update, got none")
	}
}
func TestTimestampNowWithRealNTP(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)
	listener := &MockListener{}
	timestamper.AddListener(listener)

	timestamper.Start()
	defer timestamper.Stop()

	t.Log("Waiting for initialization...")
	timestamper.WaitForInitialization()
	t.Log("Initialization complete")

	// Trigger an immediate time update
	t.Log("Triggering time update...")
	timestamper.TimestampNow()

	timeout := time.After(30 * time.Second)
	updateReceived := make(chan struct{})

	go func() {
		for {
			listener.mu.Lock()
			if len(listener.updates) > 0 {
				listener.mu.Unlock()
				updateReceived <- struct{}{}
				return
			}
			listener.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-updateReceived:
		t.Log("Update received successfully")
	case <-timeout:
		t.Error("Timed out waiting for NTP update")
	}

	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.updates) == 0 {
		t.Error("Expected at least one time update, got none")
	} else {
		t.Logf("Received %d updates", len(listener.updates))
		for i, update := range listener.updates {
			t.Logf("Update %d: %v", i, update)
		}
	}

	t.Logf("NTP Servers: %v", timestamper.servers)
	t.Logf("Priority Servers: %v", timestamper.priorityServers)
}
func TestWaitForInitialization(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)
	start := time.Now()
	go func() {
		time.Sleep(1 * time.Second)
		timestamper.mutex.Lock()
		timestamper.initialized = true
		timestamper.mutex.Unlock()
	}()
	timestamper.WaitForInitialization()
	elapsed := time.Since(start)
	if elapsed < 1*time.Second {
		t.Errorf("Expected to wait at least 1 second, waited %v", elapsed)
	}
}

func TestQueryTime(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)
	listener := &MockListener{}
	timestamper.AddListener(listener)

	// Mock injection
	mockNTPClient := &MockNTPClient{
		ClockOffset: 1 * time.Second,
	}
	timestamper.ntpClient = mockNTPClient

	servers := []string{"pool.ntp.org"}
	success := timestamper.queryTime(servers, 5*time.Second, false)
	if !success {
		t.Error("Expected queryTime to succeed")
	}

	// Ensure that the listener received an update
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if len(listener.updates) == 0 {
		t.Error("Expected listener to receive time update")
	}
}

func TestUpdateConfig(t *testing.T) {
	defaultClient := &DefaultNTPClient{}
	timestamper := NewRouterTimestamper(defaultClient)

	// Modify the default configuration
	timestamper.queryFrequency = 1 * time.Minute
	timestamper.concurringServers = 5

	timestamper.updateConfig()

	if timestamper.queryFrequency < minQueryFrequency {
		t.Errorf("Expected queryFrequency >= %v, got %v", minQueryFrequency, timestamper.queryFrequency)
	}
	if timestamper.concurringServers > 4 {
		t.Errorf("Expected concurringServers <= 4, got %d", timestamper.concurringServers)
	}
}
