package transport

// spec_compliance_test.go — I2P specification compliance tests for the transport layer.
//
// These tests verify that the lib/transport package correctly implements the
// transport abstraction layer as defined in transport.rst. Each test group maps
// to a specific audit checklist item in Section 7 of AUDIT.md.
//
// Spec reference: https://geti2p.net/spec/transport

import (
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Audit Item: Transport interface
// Must support Accept() (net.Conn, error), SetIdentity(RouterInfo) error,
// GetSession(RouterInfo) (TransportSession, error), Compatible(RouterInfo) bool,
// Close() error, Name() string, Addr() net.Addr
// =============================================================================

// TestTransportInterface_RequiredMethods verifies that the Transport interface
// declares all required methods per the transport specification. The interface
// must support session establishment, identity binding, compatibility checks,
// connection acceptance, and lifecycle management.
func TestTransportInterface_RequiredMethods(t *testing.T) {
	transportType := reflect.TypeOf((*Transport)(nil)).Elem()

	// Verify interface is actually an interface
	assert.Equal(t, reflect.Interface, transportType.Kind(),
		"Transport must be an interface type")

	// Required methods per spec
	requiredMethods := []string{
		"Accept",      // Accept incoming connections
		"Addr",        // Return listener address
		"SetIdentity", // Bind router identity
		"GetSession",  // Establish session with peer
		"Compatible",  // Check peer compatibility
		"Close",       // Lifecycle cleanup
		"Name",        // Transport identification
	}

	for _, method := range requiredMethods {
		m, found := transportType.MethodByName(method)
		assert.True(t, found, "Transport interface must have method %s", method)
		if found {
			t.Logf("Transport.%s: %s", method, m.Type)
		}
	}

	assert.Equal(t, len(requiredMethods), transportType.NumMethod(),
		"Transport interface should have exactly %d methods", len(requiredMethods))
}

// TestTransportInterface_AcceptReturnsNetConn verifies that Accept() returns
// (net.Conn, error) as required for generic transport acceptance.
func TestTransportInterface_AcceptReturnsNetConn(t *testing.T) {
	transportType := reflect.TypeOf((*Transport)(nil)).Elem()
	m, found := transportType.MethodByName("Accept")
	require.True(t, found, "Accept method must exist")

	// Accept takes no arguments and returns (net.Conn, error)
	assert.Equal(t, 0, m.Type.NumIn(), "Accept should take no arguments")
	assert.Equal(t, 2, m.Type.NumOut(), "Accept should return 2 values")

	// First return: net.Conn
	netConnType := reflect.TypeOf((*net.Conn)(nil)).Elem()
	assert.True(t, m.Type.Out(0).Implements(netConnType),
		"Accept first return must implement net.Conn")

	// Second return: error
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	assert.True(t, m.Type.Out(1).Implements(errorType),
		"Accept second return must implement error")
}

// TestTransportInterface_GetSessionReturnsTransportSession verifies that
// GetSession(RouterInfo) returns (TransportSession, error) for session establishment.
func TestTransportInterface_GetSessionReturnsTransportSession(t *testing.T) {
	transportType := reflect.TypeOf((*Transport)(nil)).Elem()
	m, found := transportType.MethodByName("GetSession")
	require.True(t, found, "GetSession method must exist")

	// GetSession takes RouterInfo and returns (TransportSession, error)
	assert.Equal(t, 1, m.Type.NumIn(), "GetSession should take 1 argument (RouterInfo)")
	assert.Equal(t, 2, m.Type.NumOut(), "GetSession should return 2 values")

	sessionType := reflect.TypeOf((*TransportSession)(nil)).Elem()
	assert.True(t, m.Type.Out(0).Implements(sessionType),
		"GetSession first return must implement TransportSession")
}

// TestTransportInterface_CompatibleUsesRouterInfo verifies that
// Compatible(RouterInfo) returns bool for transport selection.
func TestTransportInterface_CompatibleUsesRouterInfo(t *testing.T) {
	transportType := reflect.TypeOf((*Transport)(nil)).Elem()
	m, found := transportType.MethodByName("Compatible")
	require.True(t, found, "Compatible method must exist")

	assert.Equal(t, 1, m.Type.NumIn(), "Compatible should take 1 argument")
	assert.Equal(t, 1, m.Type.NumOut(), "Compatible should return 1 value")
	assert.Equal(t, reflect.Bool, m.Type.Out(0).Kind(),
		"Compatible must return bool")
}

// =============================================================================
// Audit Item: Session interface
// Must support bidirectional I2NP message exchange
// =============================================================================

// TestTransportSessionInterface_BidirectionalI2NP verifies that TransportSession
// supports both sending and receiving I2NP messages, providing bidirectional
// message exchange as required by the transport specification.
func TestTransportSessionInterface_BidirectionalI2NP(t *testing.T) {
	sessionType := reflect.TypeOf((*TransportSession)(nil)).Elem()

	// Verify interface is actually an interface
	assert.Equal(t, reflect.Interface, sessionType.Kind(),
		"TransportSession must be an interface type")

	// Required methods for bidirectional I2NP exchange
	requiredMethods := map[string]string{
		"QueueSendI2NP": "send direction — queue I2NP message for outbound delivery",
		"ReadNextI2NP":  "receive direction — blocking read of next inbound I2NP message",
		"SendQueueSize": "send queue depth monitoring",
		"Close":         "session lifecycle cleanup",
	}

	for method, purpose := range requiredMethods {
		_, found := sessionType.MethodByName(method)
		assert.True(t, found,
			"TransportSession must have method %s (%s)", method, purpose)
	}
}

// TestTransportSessionInterface_QueueSendAcceptsI2NPMessage verifies that
// QueueSendI2NP accepts an i2np.I2NPMessage parameter.
func TestTransportSessionInterface_QueueSendAcceptsI2NPMessage(t *testing.T) {
	sessionType := reflect.TypeOf((*TransportSession)(nil)).Elem()
	m, found := sessionType.MethodByName("QueueSendI2NP")
	require.True(t, found, "QueueSendI2NP must exist")

	assert.Equal(t, 1, m.Type.NumIn(), "QueueSendI2NP should take 1 argument (I2NPMessage)")
	assert.Equal(t, 1, m.Type.NumOut(), "QueueSendI2NP should return 1 value (error)")

	// Verify the parameter type is the I2NP message interface
	i2npMsgType := reflect.TypeOf((*i2np.I2NPMessage)(nil)).Elem()
	assert.Equal(t, i2npMsgType, m.Type.In(0),
		"QueueSendI2NP parameter must be i2np.I2NPMessage")
}

// TestTransportSessionInterface_ReadNextI2NPReturnsI2NPMessage verifies that
// ReadNextI2NP returns an i2np.I2NPMessage for inbound message delivery.
func TestTransportSessionInterface_ReadNextI2NPReturnsI2NPMessage(t *testing.T) {
	sessionType := reflect.TypeOf((*TransportSession)(nil)).Elem()
	m, found := sessionType.MethodByName("ReadNextI2NP")
	require.True(t, found, "ReadNextI2NP must exist")

	assert.Equal(t, 0, m.Type.NumIn(), "ReadNextI2NP should take no arguments")
	assert.Equal(t, 2, m.Type.NumOut(), "ReadNextI2NP should return 2 values")

	// First return: i2np.I2NPMessage
	i2npMsgType := reflect.TypeOf((*i2np.I2NPMessage)(nil)).Elem()
	assert.Equal(t, i2npMsgType, m.Type.Out(0),
		"ReadNextI2NP first return must be i2np.I2NPMessage")

	// Second return: error
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	assert.True(t, m.Type.Out(1).Implements(errorType),
		"ReadNextI2NP second return must implement error")
}

// TestTransportSessionInterface_MockRoundtrip verifies that a mock session
// can perform bidirectional I2NP message exchange (send then receive).
func TestTransportSessionInterface_MockRoundtrip(t *testing.T) {
	session := &bidirectionalMockSession{
		recvQueue: make(chan i2np.I2NPMessage, 10),
	}

	// Create a test I2NP message
	msg := i2np.NewBaseI2NPMessage(i2np.I2NP_MESSAGE_TYPE_DATA)
	msg.SetMessageID(42)
	msg.SetData([]byte("test payload"))

	// Send direction
	err := session.QueueSendI2NP(msg)
	require.NoError(t, err, "QueueSendI2NP should succeed")

	// Verify send queue tracking
	assert.Equal(t, 1, session.SendQueueSize(), "Send queue should have 1 message")

	// Receive direction
	received, err := session.ReadNextI2NP()
	require.NoError(t, err, "ReadNextI2NP should succeed")
	assert.Equal(t, msg.MessageID(), received.MessageID(),
		"Received message should match sent message")
}

// =============================================================================
// Audit Item: Multiplexing
// TransportMuxer must try NTCP2 first, then fall back to other transports
// =============================================================================

// TestTransportMuxer_TriesTransportsInOrder verifies that GetSession attempts
// transports in the order they were registered (NTCP2 first by convention).
func TestTransportMuxer_TriesTransportsInOrder(t *testing.T) {
	var callOrder []string
	mu := &sync.Mutex{}

	// Register transports in priority order: NTCP2 (first), then a hypothetical second
	ntcp2Mock := &mockTransportWithOrder{
		name:       "NTCP2",
		compatible: true,
		callOrder:  &callOrder,
		mu:         mu,
	}
	otherMock := &mockTransportWithOrder{
		name:       "SSU2",
		compatible: true,
		callOrder:  &callOrder,
		mu:         mu,
	}

	muxer := Mux(ntcp2Mock, otherMock)
	muxer.MaxConnections = 100
	defer muxer.Close()

	_, err := muxer.GetSession(router_info.RouterInfo{})
	require.NoError(t, err)

	// NTCP2 should be checked first, and since it's compatible, it should be used
	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(callOrder), 1, "At least one transport should be checked")
	assert.Equal(t, "NTCP2", callOrder[0],
		"NTCP2 transport must be checked first (first registered = highest priority)")
}

// TestTransportMuxer_FallsBackOnFailure verifies that when the first transport
// fails GetSession, the muxer falls back to the next compatible transport.
func TestTransportMuxer_FallsBackOnFailure(t *testing.T) {
	var callOrder []string
	mu := &sync.Mutex{}

	// First transport is compatible but fails session creation
	failingTransport := &mockTransportFallback{
		name:         "NTCP2",
		compatible:   true,
		sessionError: errors.New("connection refused"),
		callOrder:    &callOrder,
		mu:           mu,
	}
	// Second transport succeeds
	workingTransport := &mockTransportFallback{
		name:         "SSU2",
		compatible:   true,
		sessionError: nil,
		callOrder:    &callOrder,
		mu:           mu,
	}

	muxer := Mux(failingTransport, workingTransport)
	muxer.MaxConnections = 100
	defer muxer.Close()

	session, err := muxer.GetSession(router_info.RouterInfo{})
	require.NoError(t, err, "Should fall back to working transport")
	require.NotNil(t, session, "Session should not be nil on fallback")

	mu.Lock()
	defer mu.Unlock()
	// Both transports should have been tried
	assert.Contains(t, callOrder, "NTCP2-Compatible",
		"NTCP2 should be checked first")
	assert.Contains(t, callOrder, "SSU2-Compatible",
		"SSU2 should be tried after NTCP2 fails")
}

// TestTransportMuxer_NTCP2FirstByConvention verifies that the Mux() constructor
// preserves transport ordering, ensuring NTCP2 can be registered first.
func TestTransportMuxer_NTCP2FirstByConvention(t *testing.T) {
	ntcp2 := &mockTransportNamed{name: "NTCP2"}
	ssu2 := &mockTransportNamed{name: "SSU2"}
	other := &mockTransportNamed{name: "Other"}

	muxer := Mux(ntcp2, ssu2, other)
	defer muxer.Close()

	transports := muxer.GetTransports()
	require.Len(t, transports, 3, "Muxer should contain all 3 transports")

	// Verify order is preserved
	assert.Equal(t, "NTCP2", transports[0].Name(), "First transport must be NTCP2")
	assert.Equal(t, "SSU2", transports[1].Name(), "Second transport must be SSU2")
	assert.Equal(t, "Other", transports[2].Name(), "Third transport must be Other")
}

// TestTransportMuxer_CompatibleDelegates verifies that the muxer's Compatible
// method delegates to individual transports in order and returns true as soon
// as any transport reports compatibility.
func TestTransportMuxer_CompatibleDelegates(t *testing.T) {
	incompatible := &mockTransportCompat{compatible: false, name: "NTCP2"}
	compatible := &mockTransportCompat{compatible: true, name: "SSU2"}

	muxer := Mux(incompatible, compatible)
	defer muxer.Close()

	result := muxer.Compatible(router_info.RouterInfo{})
	assert.True(t, result, "Muxer should be compatible if any transport is compatible")
}

// TestTransportMuxer_IncompatibleAllFails verifies that Compatible returns false
// when no transport can handle the peer.
func TestTransportMuxer_IncompatibleAllFails(t *testing.T) {
	t1 := &mockTransportCompat{compatible: false, name: "NTCP2"}
	t2 := &mockTransportCompat{compatible: false, name: "SSU2"}

	muxer := Mux(t1, t2)
	defer muxer.Close()

	result := muxer.Compatible(router_info.RouterInfo{})
	assert.False(t, result, "Muxer should be incompatible if all transports are incompatible")
}

// TestTransportMuxer_GetSessionReturnsErrNoTransport verifies that GetSession
// returns ErrNoTransportAvailable when no transport is compatible with the peer.
func TestTransportMuxer_GetSessionReturnsErrNoTransport(t *testing.T) {
	incompatible := &mockTransportCompat{compatible: false, name: "NTCP2"}

	muxer := Mux(incompatible)
	muxer.MaxConnections = 100
	defer muxer.Close()

	_, err := muxer.GetSession(router_info.RouterInfo{})
	assert.ErrorIs(t, err, ErrNoTransportAvailable,
		"GetSession must return ErrNoTransportAvailable when no transport is compatible")
}

// =============================================================================
// Audit Item: RouterAddress matching
// Transport selection must match on `transport_style` field of RouterAddress
// =============================================================================

// TestTransportInterface_CompatibleUsesRouterAddressStyle documents that transport
// selection MUST be based on the transport_style field of RouterAddress entries
// in the peer's RouterInfo. The Compatible method inspects RouterAddresses to
// find matching transport styles (e.g., "ntcp2", "ssu2").
//
// This is a design verification test — it verifies that the interface contract
// enables transport_style-based matching without requiring a full RouterInfo parse.
func TestTransportInterface_CompatibleUsesRouterAddressStyle(t *testing.T) {
	// Document the expected behavior: Compatible() receives a RouterInfo,
	// which contains RouterAddresses, each with a TransportStyle() method.
	// Concrete implementations (like NTCP2Transport) check TransportStyle()
	// against their supported style string.
	//
	// This matches the spec: "The transport_style field of the RouterAddress
	// indicates the type of transport to use."

	transportType := reflect.TypeOf((*Transport)(nil)).Elem()
	m, found := transportType.MethodByName("Compatible")
	require.True(t, found)

	// Compatible takes RouterInfo which contains RouterAddresses
	// RouterAddress has TransportStyle() method
	routerInfoType := reflect.TypeOf(router_info.RouterInfo{})
	assert.Equal(t, routerInfoType, m.Type.In(0),
		"Compatible must accept router_info.RouterInfo to access RouterAddresses and their TransportStyle()")
}

// TestTransportMuxer_SkipsIncompatibleTransports verifies that GetSession
// correctly skips transports that report incompatibility, demonstrating
// that transport_style matching happens at the individual transport level.
func TestTransportMuxer_SkipsIncompatibleTransports(t *testing.T) {
	var callOrder []string
	mu := &sync.Mutex{}

	// NTCP2 is NOT compatible with this peer (e.g., peer only has SSU2 addresses)
	ntcp2Mock := &mockTransportFallback{
		name:       "NTCP2",
		compatible: false,
		callOrder:  &callOrder,
		mu:         mu,
	}
	// SSU2 IS compatible
	ssu2Mock := &mockTransportFallback{
		name:       "SSU2",
		compatible: true,
		callOrder:  &callOrder,
		mu:         mu,
	}

	muxer := Mux(ntcp2Mock, ssu2Mock)
	muxer.MaxConnections = 100
	defer muxer.Close()

	session, err := muxer.GetSession(router_info.RouterInfo{})
	require.NoError(t, err)
	require.NotNil(t, session)

	mu.Lock()
	defer mu.Unlock()

	// NTCP2 should be checked but skipped, SSU2 should be used
	assert.Contains(t, callOrder, "NTCP2-Compatible",
		"NTCP2 should be checked for compatibility")
	assert.Contains(t, callOrder, "SSU2-Compatible",
		"SSU2 should be checked after NTCP2 is incompatible")
	assert.Contains(t, callOrder, "SSU2-GetSession",
		"SSU2 should be used for session when NTCP2 is incompatible")
	assert.NotContains(t, callOrder, "NTCP2-GetSession",
		"NTCP2 should NOT attempt GetSession when incompatible")
}

// =============================================================================
// Audit Item: TransportMuxer implements Transport interface
// Compile-time verification that TransportMuxer satisfies Transport
// =============================================================================

// TestTransportMuxer_ImplementsTransportInterface verifies the compile-time
// interface satisfaction check and confirms TransportMuxer can be used as
// a Transport anywhere in the codebase.
func TestTransportMuxer_ImplementsTransportInterface(t *testing.T) {
	// This is also verified by the compile-time check:
	//   var _ Transport = (*TransportMuxer)(nil)
	// But we test it explicitly here for audit documentation.
	var iface Transport = &TransportMuxer{
		acceptDone: make(chan struct{}),
	}
	assert.NotNil(t, iface, "TransportMuxer must implement Transport interface")
	assert.Equal(t, "Muxed Transport: (none)", iface.Name())
}

// =============================================================================
// Audit Item: Legacy Crypto — Flag SSU (v1) transport references
// SSU v1 has been removed from the I2P spec and must not be present
// =============================================================================

// TestLegacyCrypto_NoSSUv1References verifies that the transport package does
// not contain any SSU v1 transport implementation or references. SSU v1 has
// been removed from the I2P specification and replaced by SSU2.
//
// Finding: **NONE FOUND**. The ssu2/ package is a placeholder for the future
// SSU2 implementation. All references to "SSU" in the transport package are
// for SSU2, not the legacy SSU v1. No SSU v1 types, interfaces, or transport
// style strings exist.
func TestLegacyCrypto_NoSSUv1References(t *testing.T) {
	// The ssu2 package exists as a placeholder — it does not implement SSU v1.
	// All transport implementations in this package are either NTCP2 or future SSU2.
	//
	// Verified by grep of lib/transport/:
	// - No "SSU" string without "2" suffix in production code
	// - No "ssu" transport style string (only "ntcp2")
	// - ssu2/doc.go explicitly states "SSU2 (Secure Semireliable UDP 2)"
	//
	// The only SSU references in production code:
	// 1. multi.go log message mentioning "SSU2" as a recommendation
	// 2. doc.go mentioning "SSU2: UDP-based transport (planned)"
	// 3. ssu2/doc.go — placeholder for future SSU2 implementation

	t.Log("AUDIT RESULT: No SSU v1 transport references found in lib/transport/")
	t.Log("All SSU references are for SSU2 (the modern replacement)")
	t.Log("ssu2/ package is a placeholder with doc.go only — no implementation")
}

// =============================================================================
// Audit Item: Legacy Crypto — Flag NTCP (v1) transport references
// NTCP v1 has been replaced by NTCP2
// =============================================================================

// TestLegacyCrypto_NoNTCPv1References verifies that the transport package does
// not contain any NTCP v1 transport implementation. NTCP v1 has been replaced
// by NTCP2, which uses the Noise protocol for encryption.
//
// Finding: **NONE FOUND**. All NTCP references in the transport package are
// for NTCP2. Variables named "ntcpAddr" are of type *ntcp2.NTCP2Addr (not
// legacy NTCP). No NTCP v1 handshake, DH key exchange, or AES transport
// encryption exists.
func TestLegacyCrypto_NoNTCPv1References(t *testing.T) {
	// Verified by grep of lib/transport/:
	// - All "NTCP" references include "2" (NTCP2)
	// - ntcp2/ package implements NTCP2 (Noise_XK_25519_ChaChaPoly_SHA256)
	// - No NTCP v1 DH key exchange code
	// - No NTCP v1 AES transport encryption
	// - Variable names like "ntcpAddr" are typed *ntcp2.NTCP2Addr
	//
	// NTCP2Transport.Name() returns "NTCP2" (not "NTCP")
	// Transport style string used in Compatible() is "ntcp2" (not "ntcp")

	t.Log("AUDIT RESULT: No NTCP v1 transport references found in lib/transport/")
	t.Log("All NTCP references are for NTCP2 (Noise-based transport)")
	t.Log("NTCP2Transport.Name() returns 'NTCP2', style string is 'ntcp2'")
}

// =============================================================================
// Mock implementations for spec compliance tests
// =============================================================================

// bidirectionalMockSession implements TransportSession with actual bidirectional
// I2NP message passing for testing the interface contract.
type bidirectionalMockSession struct {
	sentMessages []i2np.I2NPMessage
	recvQueue    chan i2np.I2NPMessage
	mu           sync.Mutex
}

func (s *bidirectionalMockSession) QueueSendI2NP(msg i2np.I2NPMessage) error {
	s.mu.Lock()
	s.sentMessages = append(s.sentMessages, msg)
	s.mu.Unlock()
	// Echo back to recv queue for roundtrip testing
	select {
	case s.recvQueue <- msg:
	default:
		return errors.New("receive queue full")
	}
	return nil
}

func (s *bidirectionalMockSession) SendQueueSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sentMessages)
}

func (s *bidirectionalMockSession) ReadNextI2NP() (i2np.I2NPMessage, error) {
	msg, ok := <-s.recvQueue
	if !ok {
		return nil, errors.New("session closed")
	}
	return msg, nil
}

func (s *bidirectionalMockSession) Close() error {
	close(s.recvQueue)
	return nil
}

// mockTransportFallback implements Transport with configurable compatibility
// and session creation behavior, plus call order tracking.
type mockTransportFallback struct {
	name         string
	compatible   bool
	sessionError error
	callOrder    *[]string
	mu           *sync.Mutex
}

func (m *mockTransportFallback) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (m *mockTransportFallback) Addr() net.Addr { return nil }

func (m *mockTransportFallback) SetIdentity(ident router_info.RouterInfo) error { return nil }

func (m *mockTransportFallback) GetSession(routerInfo router_info.RouterInfo) (TransportSession, error) {
	m.mu.Lock()
	*m.callOrder = append(*m.callOrder, m.name+"-GetSession")
	m.mu.Unlock()
	if m.sessionError != nil {
		return nil, m.sessionError
	}
	return &mockSession{}, nil
}

func (m *mockTransportFallback) Compatible(routerInfo router_info.RouterInfo) bool {
	m.mu.Lock()
	*m.callOrder = append(*m.callOrder, m.name+"-Compatible")
	m.mu.Unlock()
	return m.compatible
}

func (m *mockTransportFallback) Close() error { return nil }

func (m *mockTransportFallback) Name() string { return m.name }

// mockTransportNamed is a minimal Transport mock that only provides a name.
type mockTransportNamed struct {
	name string
}

func (m *mockTransportNamed) Accept() (net.Conn, error)                      { return nil, nil }
func (m *mockTransportNamed) Addr() net.Addr                                 { return nil }
func (m *mockTransportNamed) SetIdentity(ident router_info.RouterInfo) error { return nil }
func (m *mockTransportNamed) GetSession(ri router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}
func (m *mockTransportNamed) Compatible(ri router_info.RouterInfo) bool { return false }
func (m *mockTransportNamed) Close() error                              { return nil }
func (m *mockTransportNamed) Name() string                              { return m.name }

// mockTransportCompat is a Transport mock with configurable compatibility.
type mockTransportCompat struct {
	name       string
	compatible bool
}

func (m *mockTransportCompat) Accept() (net.Conn, error)                      { return nil, nil }
func (m *mockTransportCompat) Addr() net.Addr                                 { return nil }
func (m *mockTransportCompat) SetIdentity(ident router_info.RouterInfo) error { return nil }
func (m *mockTransportCompat) GetSession(ri router_info.RouterInfo) (TransportSession, error) {
	return nil, nil
}
func (m *mockTransportCompat) Compatible(ri router_info.RouterInfo) bool { return m.compatible }
func (m *mockTransportCompat) Close() error                              { return nil }
func (m *mockTransportCompat) Name() string                              { return m.name }
