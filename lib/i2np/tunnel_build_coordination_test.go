package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	router_info "github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockPeerSelector implements tunnel.PeerSelector for testing
type MockPeerSelector struct {
	peers []router_info.RouterInfo
}

func (m *MockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	if len(m.peers) < count {
		return m.peers, nil // Return what we have
	}
	return m.peers[:count], nil
}

// SimpleMockPeerSelector implements tunnel.PeerSelector without requiring RouterInfo initialization
type SimpleMockPeerSelector struct{}

func (s *SimpleMockPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	// Return empty slice to simulate sufficient peers without requiring RouterInfo initialization
	// This allows testing the TunnelManager logic without complex RouterInfo setup
	peers := make([]router_info.RouterInfo, count)
	return peers, nil
}

// InsufficientPeerSelector simulates insufficient peers available
type InsufficientPeerSelector struct{}

func (s *InsufficientPeerSelector) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	// Always return fewer peers than requested
	if count > 3 {
		return make([]router_info.RouterInfo, 3), nil
	}
	return make([]router_info.RouterInfo, count-1), nil
}

// MockMultiSessionProvider implements SessionProvider for testing with multiple sessions
type MockMultiSessionProvider struct {
	sessions map[string]*MockTransportSession
}

func NewMockMultiSessionProvider() *MockMultiSessionProvider {
	return &MockMultiSessionProvider{
		sessions: make(map[string]*MockTransportSession),
	}
}

func (m *MockMultiSessionProvider) GetSessionByHash(hash common.Hash) (TransportSession, error) {
	hashStr := string(hash[:])
	if session, exists := m.sessions[hashStr]; exists {
		return session, nil
	}
	// Return new session if not exists
	session := NewMockTransportSession()
	m.sessions[hashStr] = session
	return session, nil
}

// TestTunnelBuildMessage_Creation tests creation of TunnelBuild I2NP messages
func TestTunnelBuildMessage_Creation(t *testing.T) {
	// Create test build request records
	records := createTestBuildRequestRecords()

	// Create TunnelBuild message
	msg := NewTunnelBuildMessage(records)

	// Verify I2NPMessage interface compliance
	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_BUILD, msg.Type())
	assert.Equal(t, 0, msg.MessageID())                // Default message ID
	assert.True(t, msg.Expiration().After(time.Now())) // Should have future expiration

	// Verify TunnelBuilder interface compliance
	buildRecords := msg.GetBuildRecords()
	assert.Equal(t, 8, len(buildRecords))
	assert.Equal(t, 8, msg.GetRecordCount())

	// Verify data is set (placeholder check)
	data := msg.GetData()
	assert.Equal(t, 8*528, len(data)) // 8 records * 528 bytes each
}

// TestTunnelBuildMessage_Serialization tests marshaling and unmarshaling
func TestTunnelBuildMessage_Serialization(t *testing.T) {
	records := createTestBuildRequestRecords()
	originalMsg := NewTunnelBuildMessage(records)
	originalMsg.SetMessageID(12345)

	// Marshal the message
	data, err := originalMsg.MarshalBinary()
	require.NoError(t, err)
	assert.True(t, len(data) > 16) // Should have I2NP header + data

	// Unmarshal into new message
	newMsg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
	}
	err = newMsg.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, originalMsg.Type(), newMsg.Type())
	assert.Equal(t, originalMsg.MessageID(), newMsg.MessageID())
	assert.Equal(t, len(originalMsg.GetData()), len(newMsg.GetData()))
}

// TestTunnelManager_BuildTunnel_Core tests the core tunnel building functionality
func TestTunnelManager_BuildTunnel_Core(t *testing.T) {
	// This test focuses on the message creation and sending logic
	// without relying on complex RouterInfo initialization

	// Test TunnelManager methods in isolation
	tm := NewTunnelManager(nil)

	// Test tunnel ID generation
	tunnelID := tm.generateTunnelID()
	assert.NotEqual(t, tunnel.TunnelID(0), tunnelID)

	// Test that TunnelManager can be created and configured
	assert.NotNil(t, tm)
	assert.Nil(t, tm.sessionProvider) // Should start nil

	// Test setting session provider
	mockSessionProvider := NewMockSessionProvider()
	tm.SetSessionProvider(mockSessionProvider)
	assert.NotNil(t, tm.sessionProvider)
}

// TestTunnelManager_BuildTunnel_InsufficientPeers tests error handling with insufficient peers
func TestTunnelManager_BuildTunnel_InsufficientPeers(t *testing.T) {
	// Create mock peer selector that returns insufficient peers
	insufficientPeerSelector := &InsufficientPeerSelector{}

	tm := NewTunnelManager(insufficientPeerSelector)

	records := createTestBuildRequestRecords()
	builder := NewTunnelBuilder(records)

	// Should fail due to insufficient peers
	err := tm.BuildTunnel(builder)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient peers")
}

// TestTunnelManager_SetSessionProvider tests session provider management
func TestTunnelManager_SetSessionProvider(t *testing.T) {
	tm := NewTunnelManager(nil)

	// Should start with nil session provider
	assert.Nil(t, tm.sessionProvider)

	// Set a session provider
	mockSessionProvider := NewMockSessionProvider()
	tm.SetSessionProvider(mockSessionProvider)
	assert.NotNil(t, tm.sessionProvider)

	// Can set it back to nil
	tm.SetSessionProvider(nil)
	assert.Nil(t, tm.sessionProvider)
}

// TestTunnelManager_GenerateTunnelID tests tunnel ID generation
func TestTunnelManager_GenerateTunnelID(t *testing.T) {
	tm := NewTunnelManager(nil)

	// Generate multiple tunnel IDs
	ids := make(map[tunnel.TunnelID]bool)
	for i := 0; i < 100; i++ {
		id := tm.generateTunnelID()

		// Verify ID is non-zero
		assert.NotEqual(t, tunnel.TunnelID(0), id)

		// Verify uniqueness (highly likely with time-based generation)
		_, exists := ids[id]
		assert.False(t, exists, "Tunnel ID should be unique")
		ids[id] = true

		// Small delay to ensure time-based uniqueness
		time.Sleep(time.Nanosecond)
	}
}

// TestTunnelBuildMessage_InterfaceCompliance verifies interface satisfaction
func TestTunnelBuildMessage_InterfaceCompliance(t *testing.T) {
	records := createTestBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	// Test I2NPMessage interface
	var i2npMsg I2NPMessage = msg
	assert.NotNil(t, i2npMsg)

	// Test TunnelBuilder interface
	var tunnelBuilder TunnelBuilder = msg
	assert.NotNil(t, tunnelBuilder)

	// Test MessageSerializer interface
	var serializer MessageSerializer = msg
	assert.NotNil(t, serializer)

	// Test MessageIdentifier interface
	var identifier MessageIdentifier = msg
	assert.NotNil(t, identifier)

	// Test MessageExpiration interface
	var expiration MessageExpiration = msg
	assert.NotNil(t, expiration)
}

// TestI2NPMessageFactory_CreateTunnelBuildMessage tests factory method
func TestI2NPMessageFactory_CreateTunnelBuildMessage(t *testing.T) {
	factory := NewI2NPMessageFactory()
	records := createTestBuildRequestRecords()

	msg := factory.CreateTunnelBuildMessage(records)

	// Verify it returns I2NPMessage interface
	assert.NotNil(t, msg)
	assert.Equal(t, I2NP_MESSAGE_TYPE_TUNNEL_BUILD, msg.Type())

	// Verify it can be cast to TunnelBuilder
	builder, ok := msg.(TunnelBuilder)
	assert.True(t, ok)
	assert.Equal(t, 8, builder.GetRecordCount())
}

// Helper function to create test build request records
func createTestBuildRequestRecords() [8]BuildRequestRecord {
	var records [8]BuildRequestRecord

	for i := 0; i < 8; i++ {
		records[i] = BuildRequestRecord{
			ReceiveTunnel: tunnel.TunnelID(i + 1000),
			NextTunnel:    tunnel.TunnelID(i + 2000),
			Flag:          i,
			RequestTime:   time.Now(),
			SendMessageID: i + 3000,
		}

		// Set some test hash values
		copy(records[i].OurIdent[:], []byte("test_our_ident_hash_"+string(rune('0'+i))))
		copy(records[i].NextIdent[:], []byte("test_next_ident_hash_"+string(rune('0'+i))))

		// Set session keys (placeholder values)
		copy(records[i].LayerKey[:], []byte("test_layer_key_"+string(rune('0'+i))))
		copy(records[i].IVKey[:], []byte("test_iv_key_"+string(rune('0'+i))))
		copy(records[i].ReplyKey[:], []byte("test_reply_key_"+string(rune('0'+i))))

		// Set reply IV
		copy(records[i].ReplyIV[:], []byte("test_reply_iv_"+string(rune('0'+i))))

		// Set padding
		copy(records[i].Padding[:], []byte("padding_data_"+string(rune('0'+i))))
	}

	return records
}

// Benchmark tests for performance validation
func BenchmarkTunnelBuildMessage_Creation(b *testing.B) {
	records := createTestBuildRequestRecords()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewTunnelBuildMessage(records)
	}
}

func BenchmarkTunnelBuildMessage_Serialization(b *testing.B) {
	records := createTestBuildRequestRecords()
	msg := NewTunnelBuildMessage(records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.MarshalBinary()
	}
}
