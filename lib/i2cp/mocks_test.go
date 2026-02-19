package i2cp

// mocks_test.go — Shared mock types and test helper functions used across
// multiple test files in the i2cp package.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// MOCK TYPES
// =============================================================================

// mockPeerSelector implements tunnel.PeerSelector for testing.
type mockPeerSelector struct{}

func (m *mockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	return []router_info.RouterInfo{}, nil
}

// mockLeaseSetPublisher implements LeaseSetPublisher for testing.
type mockLeaseSetPublisher struct {
	mu            sync.Mutex
	published     map[common.Hash][]byte
	publishErr    error
	publishCalled int
}

func newMockLeaseSetPublisher() *mockLeaseSetPublisher {
	return &mockLeaseSetPublisher{
		published: make(map[common.Hash][]byte),
	}
}

func (m *mockLeaseSetPublisher) PublishLeaseSet(key common.Hash, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.publishCalled++
	if m.publishErr != nil {
		return m.publishErr
	}
	m.published[key] = data
	return nil
}

// GetPublishCount returns the number of times PublishLeaseSet was called.
func (m *mockLeaseSetPublisher) GetPublishCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.publishCalled
}

// mockTunnelBuilder implements tunnel.BuilderInterface for testing.
type mockTunnelBuilder struct {
	nextID tunnel.TunnelID
}

func (m *mockTunnelBuilder) BuildTunnel(req tunnel.BuildTunnelRequest) (*tunnel.BuildTunnelResult, error) {
	m.nextID++
	return &tunnel.BuildTunnelResult{
		TunnelID:   m.nextID,
		PeerHashes: nil,
	}, nil
}

// mockNetDBStore implements NetDBStore for testing.
type mockNetDBStore struct {
	stored    map[common.Hash][]byte
	dataTypes map[common.Hash]byte
	err       error
}

func newMockNetDBStore() *mockNetDBStore {
	return &mockNetDBStore{
		stored:    make(map[common.Hash][]byte),
		dataTypes: make(map[common.Hash]byte),
	}
}

func (m *mockNetDBStore) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	if m.err != nil {
		return m.err
	}
	m.stored[key] = data
	m.dataTypes[key] = dataType
	return nil
}

// mockDestinationResolver is a test double for the destination resolver interface.
type mockDestinationResolver struct {
	key [32]byte
	err error
}

func (m *mockDestinationResolver) ResolveDestination(destHash common.Hash) ([32]byte, error) {
	return m.key, m.err
}

// mockHostnameResolver implements the hostname resolver interface for testing.
type mockHostnameResolver struct {
	destinations map[string][]byte
	err          error
}

func (m *mockHostnameResolver) ResolveHostname(hostname string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	dest, ok := m.destinations[hostname]
	if !ok {
		return nil, errors.New("hostname not found")
	}
	return dest, nil
}

// mockTransportSender is a mock transport sender for testing.
type mockTransportSender struct {
	mu       sync.Mutex
	messages []mockSentMessage
}

type mockSentMessage struct {
	peerHash common.Hash
	msg      interface{}
}

// =============================================================================
// TEST-ONLY EXPORTED SESSION ACCESSORS
// =============================================================================

// IncomingMessages returns the incoming message channel for testing.
func (s *Session) IncomingMessages() <-chan *IncomingMessage {
	return s.incomingMessages
}

// ClientNetDB returns the session's client NetDB for testing isolation.
func (s *Session) ClientNetDB() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientNetDB
}

// =============================================================================
// SHARED HELPER FUNCTIONS
// =============================================================================

// setupTestEnvironment creates a complete test environment with server, session, and tunnel pools.
func setupTestEnvironment(t *testing.T) (*Server, *Session, *tunnel.Pool, *tunnel.Pool, func()) {
	t.Helper()

	config := &ServerConfig{
		ListenAddr:  "localhost:0",
		Network:     "tcp",
		MaxSessions: 100,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	sessionConfig := DefaultSessionConfig()
	sessionConfig.TunnelLifetime = 1 * time.Minute
	sessionConfig.Nickname = "test-session"

	session, err := server.manager.CreateSession(nil, sessionConfig)
	require.NoError(t, err)
	require.NotNil(t, session)

	selector := &mockPeerSelector{}
	inboundConfig := tunnel.DefaultPoolConfig()
	inboundConfig.IsInbound = true
	inboundConfig.MinTunnels = 2
	inboundConfig.MaxTunnels = 3
	inboundConfig.TunnelLifetime = 1 * time.Minute

	outboundConfig := tunnel.DefaultPoolConfig()
	outboundConfig.IsInbound = false
	outboundConfig.MinTunnels = 2
	outboundConfig.MaxTunnels = 3
	outboundConfig.TunnelLifetime = 1 * time.Minute

	inboundPool := tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)
	outboundPool := tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)

	builder := &mockTunnelBuilder{}
	inboundPool.SetTunnelBuilder(builder)
	outboundPool.SetTunnelBuilder(builder)

	session.SetInboundPool(inboundPool)
	session.SetOutboundPool(outboundPool)

	for i := 0; i < 2; i++ {
		tunnelID := tunnel.TunnelID(1000 + i)
		var gateway common.Hash
		copy(gateway[:], []byte("mock-gateway-router-hash-12345678901234567890"))

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []common.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		inboundPool.AddTunnel(tunnelState)
	}

	cleanup := func() {
		session.Stop()
		inboundPool.Stop()
		outboundPool.Stop()
		if err := server.Stop(); err != nil {
			t.Logf("Error stopping server: %v", err)
		}
	}

	return server, session, inboundPool, outboundPool, cleanup
}

// dialI2CPClient connects to an I2CP server and sends the required protocol byte (0x2a).
func dialI2CPClient(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{0x2a}); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// receiveMessageWithContext receives a message with context timeout.
func receiveMessageWithContext(ctx context.Context, session *Session) (*IncomingMessage, error) {
	msgChan := make(chan *IncomingMessage, 1)
	errChan := make(chan error, 1)

	go func() {
		msg, err := session.ReceiveMessage()
		if err != nil {
			errChan <- err
			return
		}
		msgChan <- msg
	}()

	select {
	case msg := <-msgChan:
		return msg, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// createTestDestination creates a valid test destination using the keys package.
func createTestDestination() (*destination.Destination, error) {
	keyStore, err := keys.NewDestinationKeyStore()
	if err != nil {
		return nil, err
	}
	return keyStore.Destination(), nil
}

// prependSessionID builds a wire-format payload by prepending a 2-byte
// big-endian session ID to the given data.
func prependSessionID(sessionID uint16, payload []byte) []byte {
	result := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(result[0:2], sessionID)
	copy(result[2:], payload)
	return result
}

// createTestSessionWithLeaseSet creates a session with a valid LeaseSet2 for testing.
func createTestSessionWithLeaseSet(t *testing.T) (*Session, []byte) {
	t.Helper()

	session, err := NewSession(1, nil, nil)
	require.NoError(t, err)

	selector := &mockPeerSelector{}
	inboundPool := tunnel.NewTunnelPool(selector)

	for i := 0; i < 2; i++ {
		tunnelID := tunnel.TunnelID(5000 + i)
		var gateway common.Hash
		copy(gateway[:], []byte("gateway-router-hash-1234567890ab"))
		gateway[31] = byte(i)

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []common.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		inboundPool.AddTunnel(tunnelState)
	}
	session.SetInboundPool(inboundPool)

	leaseSetBytes, err := session.CreateLeaseSet()
	require.NoError(t, err)
	require.NotEmpty(t, leaseSetBytes)

	return session, leaseSetBytes
}

// createTestHash creates a deterministic test hash.
func createTestHash() common.Hash {
	var hash common.Hash
	for i := range hash {
		hash[i] = byte(i)
	}
	return hash
}

// createTestSessionWithoutPools creates a minimal session without pools.
func createTestSessionWithoutPools(t *testing.T) *Session {
	t.Helper()
	config := DefaultSessionConfig()
	session := &Session{
		id:        1,
		config:    config,
		active:    true,
		createdAt: time.Now(),
	}
	return session
}

// createTestSessionWithEmptyPools creates minimal session with empty pools.
func createTestSessionWithEmptyPools(t *testing.T) *Session {
	t.Helper()
	config := DefaultSessionConfig()
	session := &Session{
		id:        1,
		config:    config,
		active:    true,
		createdAt: time.Now(),
	}

	selector := &mockPeerSelector{}
	session.outboundPool = tunnel.NewTunnelPool(selector)
	session.inboundPool = tunnel.NewTunnelPool(selector)

	return session
}

// createTestSessionWithZeroHopTunnels creates a session with a zero-hop tunnel for testing.
func createTestSessionWithZeroHopTunnels(t *testing.T) *Session {
	t.Helper()
	config := DefaultSessionConfig()
	session := &Session{
		id:        1,
		config:    config,
		active:    true,
		createdAt: time.Now(),
	}

	selector := &mockPeerSelector{}
	session.outboundPool = tunnel.NewTunnelPool(selector)
	session.inboundPool = tunnel.NewTunnelPool(selector)

	zeroHopTunnel := &tunnel.TunnelState{
		ID:        tunnel.TunnelID(9999),
		Hops:      []common.Hash{},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
	}
	session.outboundPool.AddTunnel(zeroHopTunnel)

	return session
}

// setupMessageRouterTest sets up a message router test environment.
func setupMessageRouterTest(t *testing.T) (*Session, *i2np.GarlicSessionManager, TransportSendFunc, map[string]i2np.I2NPMessage) {
	t.Helper()

	server, session, _, outboundPool, cleanup := setupTestEnvironment(t)
	t.Cleanup(cleanup)
	_ = server

	for i := 0; i < 2; i++ {
		tunnelID := tunnel.TunnelID(2000 + i)
		var gateway common.Hash
		copy(gateway[:], []byte("mock-outbound-gateway-hash-12345678901234567890"))
		gateway[31] = byte(i)

		tunnelState := &tunnel.TunnelState{
			ID:        tunnelID,
			Hops:      []common.Hash{gateway},
			State:     tunnel.TunnelReady,
			CreatedAt: time.Now(),
		}
		outboundPool.AddTunnel(tunnelState)
	}

	var privKey [32]byte
	copy(privKey[:], "test-private-key-32-bytes-pad")
	garlicMgr, err := i2np.NewGarlicSessionManager(privKey)
	require.NoError(t, err)

	sentMessages := make(map[string]i2np.I2NPMessage)
	transportSend := func(peerHash common.Hash, msg i2np.I2NPMessage) error {
		key := string(peerHash[:])
		sentMessages[key] = msg
		return nil
	}

	return session, garlicMgr, transportSend, sentMessages
}

// createMockTunnels creates mock tunnel data for testing.
func createMockTunnels(count int) []*tunnel.TunnelState {
	tunnels := make([]*tunnel.TunnelState, count)
	for i := 0; i < count; i++ {
		var gateway [32]byte
		for j := 0; j < 32; j++ {
			gateway[j] = byte((i*32 + j) % 256)
		}

		tunnels[i] = &tunnel.TunnelState{
			ID:        tunnel.TunnelID(1000 + i),
			State:     tunnel.TunnelReady,
			Hops:      []common.Hash{gateway},
			CreatedAt: time.Now(),
		}
	}
	return tunnels
}
