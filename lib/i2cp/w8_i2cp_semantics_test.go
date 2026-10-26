// W8 spec-compliance regression tests: I2CP semantics.
//
// Each test pins a specific normative statement of the I2CP spec
// (.spec_audit/i2cp.rst) that the router previously violated. They are written
// to fail against the pre-fix implementation; see the audit report for the
// verified revert/prove cycle.
package i2cp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/red25519"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Finding 1: nonce=0 must mean "send no status" (i2cp.rst:1426-1429)
// ---------------------------------------------------------------------------

// TestW8_SendMessage_NonceZeroSendsNoStatus verifies that a SendMessage with a
// zero nonce gets NO MessageStatus reply at all, while the message is still
// routed. i2cp.rst:1426-1429: "a nonce value of 0 is allowed, and tells to the
// router that it should not send either MessageStatusMessage_".
func TestW8_SendMessage_NonceZeroSendsNoStatus(t *testing.T) {
	server, session, msg := buildSendMessageRequestWithNonce(t, "dest-hash-value-for-nonce-zero!", "payload", 0)
	session.SetOutboundPool(&tunnel.Pool{})

	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)

	require.NoError(t, err, "a nonce of 0 suppresses the status, it does not reject the message")
	assert.Nil(t, response,
		"SendMessage with nonce 0 must not produce a MessageStatus (i2cp.rst:1426-1429)")
}

// TestW8_SendMessage_NonzeroNonceEchoedInStatus verifies the companion rule: a
// non-zero nonce is answered with MessageStatus(Accepted) carrying that same
// nonce. i2cp.rst:1405-1408: "That message will contain the same nonce sent
// here."
func TestW8_SendMessage_NonzeroNonceEchoedInStatus(t *testing.T) {
	const nonce uint32 = 0xDEADBEEF

	server, session, msg := buildSendMessageRequestWithNonce(t, "dest-hash-value-for-nonce-echo!", "payload", nonce)
	session.SetOutboundPool(&tunnel.Pool{})

	sessionPtr := session
	response, err := server.handleSendMessage(msg, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, response, "non-zero nonce must be answered with a MessageStatus")

	require.Len(t, response.Payload, 15)
	assert.Equal(t, MessageStatusAccepted, response.Payload[6], "status must be Accepted")
	got := binary.BigEndian.Uint32(response.Payload[11:15])
	assert.Equal(t, nonce, got, "the accepted status must echo the request nonce")
}

// TestW8_SendMessageExpires_NonceZeroSendsNoStatus verifies the same rule for
// SendMessageExpires. i2cp.rst:1474-1477.
func TestW8_SendMessageExpires_NonceZeroSendsNoStatus(t *testing.T) {
	server, session, msg := buildSendMessageExpiresRequest(t, 0)
	session.SetOutboundPool(&tunnel.Pool{})

	sessionPtr := session
	response, err := server.handleSendMessageExpires(msg, &sessionPtr)
	require.NoError(t, err)
	assert.Nil(t, response,
		"SendMessageExpires with nonce 0 must not produce a MessageStatus (i2cp.rst:1474-1477)")
}

// TestW8_StatusCallback_SuppressesNonceZero verifies the suppression applies to
// the asynchronous status path too — "not send either MessageStatusMessage_".
func TestW8_StatusCallback_SuppressesNonceZero(t *testing.T) {
	server, session, buf := newStatusTestServer(t)

	callback := server.buildStatusCallback(session)
	callback(1001, MessageStatusSuccess, 32, 0)

	assert.Zero(t, buf.Len(),
		"an async status for a nonce-0 message must not be written (i2cp.rst:1426-1429)")

	callback(1002, MessageStatusSuccess, 32, 7)
	frames := decodeStatusFrames(buf.Bytes())
	require.Len(t, frames, 1, "a non-zero nonce must still be reported")
	assert.Equal(t, uint32(7), frames[0].Nonce,
		"the async status must carry the nonce it was invoked with (i2cp.rst:1405-1408)")
}

// TestW8_StatusCallback_MessageReliabilityNoneSuppressesAcceptedOnly verifies
// the 0.9.14 rule: in a messageReliability=none session the router never sends
// the "accepted" status, but a non-zero nonce still requests the later
// success/failure status. i2cp.rst:1421-1423, :1431-1437.
func TestW8_StatusCallback_MessageReliabilityNoneSuppressesAcceptedOnly(t *testing.T) {
	_, session, _ := newStatusTestServer(t)

	session.mu.Lock()
	session.config.MessageReliability = MessageReliabilityNone
	session.mu.Unlock()

	// "accepted" is suppressed for the whole session.
	assert.False(t, sendStatusRequested(7, session.MessageReliability(), true),
		"messageReliability=none must suppress the accepted status (i2cp.rst:1421-1423)")
	// ...but the delivery status is requested by a non-zero nonce.
	assert.True(t, sendStatusRequested(7, session.MessageReliability(), false),
		"a non-zero nonce opts back into the delivery status (i2cp.rst:1431-1437)")
	// ...and nonce 0 still wins over everything.
	assert.False(t, sendStatusRequested(0, MessageReliabilityBestEffort, false),
		"nonce 0 means no status at all (i2cp.rst:1426-1429)")

	// End-to-end: the handler must not emit the accepted status.
	server2, session2, msg := buildSendMessageRequestWithNonce(t, "dest-hash-reliability-none-test!!!", "payload", 99)
	session2.SetOutboundPool(&tunnel.Pool{})
	session2.mu.Lock()
	session2.config.MessageReliability = MessageReliabilityNone
	session2.mu.Unlock()

	sessionPtr := session2
	response, err := server2.handleSendMessage(msg, &sessionPtr)
	require.NoError(t, err)
	assert.Nil(t, response,
		"a messageReliability=none session gets no accepted status (i2cp.rst:1421-1423)")
}

// TestW8_MessageReliabilityNoneIsHonored verifies the option is no longer
// silently downgraded to BestEffort.
func TestW8_MessageReliabilityNoneIsHonored(t *testing.T) {
	config := DefaultSessionConfig()
	applyMessageOptions(config, map[string]string{"i2cp.messageReliability": "None"})

	assert.Equal(t, MessageReliabilityNone, config.MessageReliability,
		"i2cp.messageReliability=none must be honored (i2cp.rst:1421-1423)")
	assert.NotContains(t, config.UnsupportedOptions, "i2cp.messageReliability",
		"None is implemented for status reporting, so it is not an unsupported option")

	// Guaranteed remains unimplemented and is still downgraded.
	config = DefaultSessionConfig()
	applyMessageOptions(config, map[string]string{"i2cp.messageReliability": "Guaranteed"})
	assert.Equal(t, MessageReliabilityBestEffort, config.MessageReliability)
	assert.Contains(t, config.UnsupportedOptions, "i2cp.messageReliability")
}

// ---------------------------------------------------------------------------
// Finding 2: async MessageStatus must carry the message's nonce
//             (i2cp.rst:1405-1408)
// ---------------------------------------------------------------------------

// TestW8_AsyncMessageStatus_CarriesRealNonce drives the full asynchronous path
// (handler -> routeMessageWithStatus -> MessageRouter -> status callback -> wire)
// and asserts the status the client receives carries the nonce of the message it
// refers to, not a hardcoded 0.
func TestW8_AsyncMessageStatus_CarriesRealNonce(t *testing.T) {
	const nonce uint32 = 0x01020304

	server, session, _, outboundPool, cleanup := setupTestEnvironment(t)
	t.Cleanup(cleanup)

	addTestTunnelsToPool(outboundPool, 4000, "mock-outbound-gateway-hash-12345678901234567890", 2)

	// Observe the asynchronous status on a connection registered for the session.
	conn := &syncBufConn{Buffer: &bytes.Buffer{}}
	server.mu.Lock()
	server.sessionConns[session.ID()] = conn
	server.connWriteMu[session.ID()] = &sync.Mutex{}
	server.mu.Unlock()

	garlicMock := newMockGarlicEncryptor()
	transportSend := func(_ common.Hash, _ i2np.Message) error { return nil }
	server.SetMessageRouter(NewMessageRouter(garlicMock, transportSend))

	dest := session.Destination()
	destHash, err := dest.Hash()
	require.NoError(t, err)
	server.SetDestinationResolver(stubResolver{key: destHash})

	sendMsg := &SendMessagePayload{
		Destination: *dest,
		Payload:     []byte("async nonce propagation"),
		Nonce:       nonce,
	}

	sessionPtr := session
	_, err = server.handleSendMessage(buildSendMessageMessage(t, session, sendMsg), &sessionPtr)
	require.NoError(t, err)

	statuses := waitForStatusFrames(t, conn, 2*time.Second)
	require.NotEmpty(t, statuses, "expected an asynchronous MessageStatus on the wire")
	for _, st := range statuses {
		assert.Equal(t, nonce, st.Nonce,
			"asynchronous MessageStatus must echo the nonce of the message it refers to (i2cp.rst:1405-1408)")
	}
}

// TestW8_NotifyStatusCallback_PropagatesNonce verifies the router->client nonce
// plumbing directly: RouteRequest.Nonce must reach every callback invocation.
func TestW8_NotifyStatusCallback_PropagatesNonce(t *testing.T) {
	const nonce uint32 = 0x11223344

	session, _ := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	session.SetOutboundPool(&tunnel.Pool{}) // no tunnels -> NoTunnels status

	var got []uint32
	mr := NewMessageRouter(&mockGarlicEncryptor{}, func(_ common.Hash, _ i2np.Message) error { return nil })
	err := mr.RouteOutboundMessage(RouteRequest{
		Session:         session,
		MessageID:       1,
		DestinationHash: common.HashData([]byte("dest")),
		Payload:         []byte("x"),
		Nonce:           nonce,
		StatusCallback: func(_ uint32, _ uint8, _, n uint32) {
			got = append(got, n)
		},
	})
	require.Error(t, err, "pool with no tunnels must fail routing")
	require.NotEmpty(t, got, "the status callback must be invoked")
	for _, n := range got {
		assert.Equal(t, nonce, n,
			"every asynchronous status must carry the message nonce (i2cp.rst:1405-1408)")
	}
}

// ---------------------------------------------------------------------------
// Finding 3: SessionStatus(Destroyed) must not be sent (i2cp.rst:785-806)
// ---------------------------------------------------------------------------

// TestW8_DestroySession_RepliesDisconnectNotSessionStatus is covered by
// TestHandleDestroySessionSendsDisconnectNotSessionStatus in
// server_unit_test.go; this variant pins the wire-level behaviour through the
// connection loop: the client receives a DisconnectMessage (type 30) and the
// socket is closed, never a SessionStatus (type 2) with status byte 0.
func TestW8_DestroySession_RepliesDisconnectNotSessionStatus(t *testing.T) {
	server := newTestI2CPServer(t, "")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)

	sessionPtr := session
	destroy := &Message{Type: MessageTypeDestroySession, SessionID: session.ID()}

	response, err := server.handleDestroySession(destroy, &sessionPtr)
	require.Error(t, err, "destroying the last session must end the connection")
	assert.True(t, errors.Is(err, errCloseAfterResponse), "must signal close-after-response")
	require.NotNil(t, response)

	assert.Equal(t, MessageTypeDisconnect, response.Type,
		"the reply must be a DisconnectMessage (i2cp.rst:802-804, :828-829)")
	assert.NotEqual(t, MessageTypeSessionStatus, response.Type,
		"the router never sends a SessionStatus(Destroyed) response (i2cp.rst:802-804)")

	// The payload must decode as a DisconnectPayload, not a 3-byte SessionStatus.
	_, decodeErr := ParseDisconnectPayload(response.Payload)
	assert.NoError(t, decodeErr, "payload must be a valid DisconnectMessage [String] reason")

	// processAndRespond must terminate the loop for this error.
	assert.True(t, shouldCloseConnection(err),
		"a destroyed session must terminate the connection loop")
}

// TestW8_DestroySession_EndToEndSocket verifies the prescribed behaviour over a
// real client socket: DestroySession is answered with a DisconnectMessage and
// then the socket is closed — never with a SessionStatus.
func TestW8_DestroySession_EndToEndSocket(t *testing.T) {
	server := newTestI2CPServer(t, "")
	conn := startServerAndConnect(t, server)
	sessionID := createSessionOnConn(t, conn)

	require.NoError(t, WriteMessage(conn, &Message{
		Type:      MessageTypeDestroySession,
		SessionID: sessionID,
		Payload:   prependSessionID(sessionID, nil),
	}), "WriteMessage() error")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	response, err := ReadMessage(conn, 0)
	require.NoError(t, err, "the router must answer before closing")

	assert.Equal(t, MessageTypeDisconnect, response.Type,
		"the reply to DestroySession must be a DisconnectMessage (i2cp.rst:802-804, :828-829)")
	assert.NotEqual(t, MessageTypeSessionStatus, response.Type,
		"the router never sends a SessionStatus(Destroyed) response (i2cp.rst:802-804)")

	// The socket must be closed right after the DisconnectMessage.
	_, err = ReadMessage(conn, 0)
	assert.Error(t, err, "the socket must be closed after the DisconnectMessage (i2cp.rst:828-829)")
}

// ---------------------------------------------------------------------------
// Finding 4: unsupported message type must disconnect (i2cp.rst:228-229)
// ---------------------------------------------------------------------------

// TestW8_UnsupportedMessageType_Disconnects verifies that an unknown message
// type terminates the connection instead of being logged and skipped.
// i2cp.rst:228-229: routers "generally disconnect the session upon reception of
// an unsupported message".
func TestW8_UnsupportedMessageType_Disconnects(t *testing.T) {
	server := newTestI2CPServer(t, "")

	var sessionPtr *Session
	_, err := server.handleMessage(nil, &Message{
		Type:      200,
		SessionID: SessionIDReservedControl,
		Payload:   []byte{0x00, 0x01},
	}, &sessionPtr)

	require.Error(t, err, "an unsupported message type must be a terminal error")
	assert.True(t, errors.Is(err, errUnsupportedMessageType),
		"error must be the unsupported-message-type sentinel, got %v", err)
	assert.True(t, shouldCloseConnection(err),
		"the connection loop must close on an unsupported message type")
}

// TestW8_UnsupportedMessageType_EndToEndConnectionLoop exercises the rule
// through a real client socket. The client sends an unsupported type and then a
// valid GetDate: a compliant router has already dropped the socket, so the
// GetDate can never be answered; a non-compliant one stays on the connection
// and replies.
func TestW8_UnsupportedMessageType_EndToEndConnectionLoop(t *testing.T) {
	server := newTestI2CPServer(t, "")
	conn := startServerAndConnect(t, server)

	require.NoError(t, WriteMessage(conn, &Message{
		Type:    200, // not assigned by the spec
		Payload: []byte{0x00, 0x00},
	}), "WriteMessage() error")

	// The socket must be CLOSED, which is distinguishable from the router simply
	// not replying: a close yields EOF immediately, a live-but-silent connection
	// yields a deadline-exceeded error only after the (long) timeout.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := ReadMessage(conn, 0)
	require.Error(t, err,
		"the connection must be terminated after an unsupported message type (i2cp.rst:228-229)")

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("the connection stayed open after an unsupported message type; "+
			"the read only hit the deadline (%v) instead of the router closing the socket (i2cp.rst:228-229)", err)
	}

	// A follow-up request on the same socket must never be answered.
	_ = WriteMessage(conn, &Message{Type: MessageTypeGetDate, Payload: []byte{0x00, 0x00}})
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	followUp, err := ReadMessage(conn, 0)
	if err == nil {
		assert.NotEqual(t, MessageTypeGetDate, followUp.Type,
			"the router must not keep serving a connection after an unsupported message type")
	}
}

// ---------------------------------------------------------------------------
// Finding 5: the session config Mapping must be sorted (i2cp.rst:410-412)
// ---------------------------------------------------------------------------

// TestW8_SessionConfigMapping_SortOrderEnforced verifies the spec requirement
// that the Mapping be sorted by key, delegated to upstream common/data, which
// validates the order on read (data/mapping_values.go validateMappingSortOrder).
// i2cp.rst:410-412: "The Mapping ... must be sorted ... otherwise the signature
// will not validate."
func TestW8_SessionConfigMapping_SortOrderEnforced(t *testing.T) {
	// "inbound.length" must precede "outbound.length"; this payload is sorted.
	sorted := buildMappingPayload(t, [][2]string{
		{"inbound.length", "3"},
		{"outbound.length", "3"},
	})
	_, err := parseSessionOptions(sorted)
	require.NoError(t, err, "a sorted Mapping must be accepted")

	// Same two options in the wrong order must be rejected.
	unsorted := buildMappingPayload(t, [][2]string{
		{"outbound.length", "3"},
		{"inbound.length", "3"},
	})
	_, err = parseSessionOptions(unsorted)
	require.Error(t, err, "an unsorted Mapping must be rejected (i2cp.rst:410-412)")
	assert.Contains(t, err.Error(), "sorted", "the error must name the sort-order violation")

	// End-to-end: an unsorted CreateSession options Mapping yields
	// SessionStatus(Invalid) rather than a silently-accepted session.
	server := newTestI2CPServer(t, "")
	id := generateTestIdentity(t)
	payload := buildSignedCreateSessionPayloadWithOptions(t, id, unsorted)

	var sessionPtr *Session
	response, err := server.handleCreateSession(&Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   payload,
	}, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Len(t, response.Payload, 3)
	assert.Equal(t, SessionStatusInvalid, response.Payload[2],
		"an unsorted (and therefore un-signable) session config must be refused")
}

// ---------------------------------------------------------------------------
// Finding 6: CreateLeaseSet2 store type must drive behaviour (i2cp.rst:668-672)
// ---------------------------------------------------------------------------

// TestW8_CreateLeaseSet2_StoreTypeSelectsFramingAndRecordType verifies that the
// one-byte store type selects the structure, the NetDB record type and the
// publication key.
func TestW8_CreateLeaseSet2_StoreTypeSelectsFramingAndRecordType(t *testing.T) {
	t.Run("LeaseSet2_type_3", func(t *testing.T) {
		session, ls2Bytes := createTestSessionWithLeaseSet(t)
		defer session.Stop()

		store := newMockNetDBStore()
		publisher := NewNetDBLeaseSetPublisher(store)
		session.SetLeaseSetPublisher(publisher)

		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeLeaseSet2, ls2Bytes, nil)
		sessionPtr := session
		_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
		require.NoError(t, err, "a valid LeaseSet2 with store type 3 must be accepted")

		assert.Equal(t, ls2Bytes, session.CurrentLeaseSet(),
			"the cached lease set must be exactly the framed LeaseSet2")
		assert.Equal(t, LeaseSetStoreTypeLeaseSet2, session.LeaseSetStoreType())

		key, err := leaseSetPublicationKey(LeaseSetStoreTypeLeaseSet2, ls2Bytes)
		require.NoError(t, err)
		require.Contains(t, store.stored, key, "published under the destination hash")
		assert.Equal(t, byte(LeaseSetStoreTypeLeaseSet2), store.dataTypes[key],
			"stored with the NetDB record type the client declared (i2cp.rst:668-672)")
	})

	t.Run("EncryptedLeaseSet_type_5", func(t *testing.T) {
		session, ls2Bytes := createTestSessionWithLeaseSet(t)
		defer session.Stop()

		// A spec-conformant blinded EncryptedLeaseSet (see buildBlindedEncryptedLeaseSet).
		elsBytes := buildBlindedEncryptedLeaseSet(t, session, ls2Bytes)

		store := newMockNetDBStore()
		session.SetLeaseSetPublisher(NewNetDBLeaseSetPublisher(store))
		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeEncryptedLeaseSet, elsBytes, nil)
		sessionPtr := session
		_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
		require.NoError(t, err, "a valid EncryptedLeaseSet with store type 5 must be accepted")

		assert.Equal(t, elsBytes, session.CurrentLeaseSet(),
			"the cached lease set must be the EncryptedLeaseSet, not a LeaseSet2")
		assert.Equal(t, LeaseSetStoreTypeEncryptedLeaseSet, session.LeaseSetStoreType())

		els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
		require.NoError(t, err)
		key := common.HashData(els.BlindedPublicKey())
		require.Contains(t, store.stored, key, "published under the blinded-key hash")
		assert.Equal(t, byte(LeaseSetStoreTypeEncryptedLeaseSet), store.dataTypes[key],
			"stored as an EncryptedLeaseSet record, not a LeaseSet2 record (i2cp.rst:668-672)")
	})

	t.Run("LeaseSet_type_1", func(t *testing.T) {
		// Type 1 is the deprecated [LeaseSet]_ the spec still accepts on this
		// message (i2cp.rst:668). It has a different wire layout from LeaseSet2,
		// so honouring the store type is observable: treating it as a LeaseSet2
		// (the pre-fix behaviour) cannot parse it at all.
		session, lsBytes := createTestSessionWithLeaseSetV1(t)
		defer session.Stop()

		store := newMockNetDBStore()
		session.SetLeaseSetPublisher(NewNetDBLeaseSetPublisher(store))
		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeLeaseSet, lsBytes, nil)
		sessionPtr := session
		_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
		require.NoError(t, err, "a valid LeaseSet with store type 1 must be accepted")

		assert.Equal(t, lsBytes, session.CurrentLeaseSet(),
			"the framed type-1 LeaseSet must be cached, not a mis-parsed slice")
		assert.Equal(t, LeaseSetStoreTypeLeaseSet, session.LeaseSetStoreType())

		key, err := leaseSetPublicationKey(LeaseSetStoreTypeLeaseSet, lsBytes)
		require.NoError(t, err)
		require.Contains(t, store.stored, key)
		assert.Equal(t, byte(LeaseSetStoreTypeLeaseSet), store.dataTypes[key],
			"stored as a LeaseSet record, not a LeaseSet2 record (i2cp.rst:668-672)")
	})

	t.Run("unknown_store_type_rejected", func(t *testing.T) {
		session, ls2Bytes := createTestSessionWithLeaseSet(t)
		defer session.Stop()
		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		for _, st := range []LeaseSetStoreType{0, 2, 4, 6, 8} {
			msg := buildCreateLeaseSet2Message(t, session.ID(), st, ls2Bytes, nil)
			sessionPtr := session
			_, err := server.handleCreateLeaseSet2(msg, &sessionPtr)
			assert.Error(t, err, "store type %d is not defined by the spec", uint8(st))
		}
	})

	t.Run("meta_leaseset_type_7_rejected", func(t *testing.T) {
		// i2cp.rst:660 — "MetaLeaseSet is not yet supported via I2CP."
		session, ls2Bytes := createTestSessionWithLeaseSet(t)
		defer session.Stop()
		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeMetaLeaseSet, ls2Bytes, nil)
		sessionPtr := session
		_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
		require.Error(t, err, "MetaLeaseSet must be rejected via I2CP (i2cp.rst:660)")
		assert.True(t, errors.Is(err, errMetaLeaseSetUnsupportedViaI2CP),
			"the rejection must name the spec's MetaLeaseSet exclusion, got %v", err)
	})

	t.Run("private_keys_parsed_per_spec_layout", func(t *testing.T) {
		session, ls2Bytes := createTestSessionWithLeaseSet(t)
		defer session.Stop()
		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		msg := buildCreateLeaseSet2Message(t, session.ID(), LeaseSetStoreTypeLeaseSet2, ls2Bytes,
			[]privateKeyEntry{{Type: 4, Data: key}})

		sessionPtr := session
		_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
		require.NoError(t, err)

		keys := session.ClientEncryptionKeys()
		require.Contains(t, keys, uint16(4), "the private key list must be stored by key type")
		assert.Equal(t, key, keys[4])
	})

	t.Run("truncated_private_key_list_rejected", func(t *testing.T) {
		session, ls2Bytes := createTestSessionWithLeaseSet(t)
		defer session.Stop()
		server, err := NewServer(&ServerConfig{})
		require.NoError(t, err)

		// Declares 2 keys but carries only 1.
		payload := buildCreateLeaseSet2Payload(t, LeaseSetStoreTypeLeaseSet2, ls2Bytes,
			[]privateKeyEntry{{Type: 4, Data: make([]byte, 32)}})
		// Layout is [storeType][lease set][count][keys...]; claim two keys but
		// only one is present.
		payload[1+len(ls2Bytes)] = 2
		msg := &Message{
			Type:      MessageTypeCreateLeaseSet2,
			SessionID: session.ID(),
			Payload:   prependSessionID(session.ID(), payload),
		}

		sessionPtr := session
		_, err = server.handleCreateLeaseSet2(msg, &sessionPtr)
		assert.Error(t, err, "a truncated private key list must be rejected")
	})
}

// TestW8_CreateLeaseSet2_StoreTypeDrivesMaintenance verifies the declared store
// type survives on the session, so a later re-publication uses the same record
// type instead of assuming LeaseSet2.
func TestW8_CreateLeaseSet2_StoreTypeDrivesMaintenance(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	store := newMockNetDBStore()
	session.SetLeaseSetPublisher(NewNetDBLeaseSetPublisher(store))

	elsBytes := buildBlindedEncryptedLeaseSet(t, session, ls2Bytes)
	session.SetCurrentLeaseSetWithType(elsBytes, LeaseSetStoreTypeEncryptedLeaseSet)

	require.NoError(t, session.publishLeaseSetToNetwork(session.CurrentLeaseSet()))

	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(elsBytes)
	require.NoError(t, err)
	key := common.HashData(els.BlindedPublicKey())
	require.Contains(t, store.stored, key)
	assert.Equal(t, byte(LeaseSetStoreTypeEncryptedLeaseSet), store.dataTypes[key],
		"re-publication must keep the store type declared by the client")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildSendMessageExpiresRequest builds a wire SendMessageExpires message with
// an explicit nonce.
func buildSendMessageExpiresRequest(t *testing.T, nonce uint32) (*Server, *Session, *Message) {
	t.Helper()

	server, err := NewServer(nil)
	require.NoError(t, err)
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)

	dest, err := createTestDestination()
	require.NoError(t, err)

	payload := &SendMessageExpiresPayload{
		Destination: *dest,
		Payload:     []byte("expires"),
		Nonce:       nonce,
		Flags:       0,
		Expiration:  uint64(time.Now().Add(time.Minute).UnixMilli()),
	}
	wire, err := payload.MarshalBinary()
	require.NoError(t, err)

	return server, session, &Message{
		Type:      MessageTypeSendMessageExpires,
		SessionID: session.ID(),
		Payload:   prependSessionID(session.ID(), wire),
	}
}

// buildSendMessageMessage wraps a SendMessagePayload into a wire Message.
func buildSendMessageMessage(t *testing.T, session *Session, payload *SendMessagePayload) *Message {
	t.Helper()
	wire, err := payload.MarshalBinary()
	require.NoError(t, err)
	return &Message{
		Type:      MessageTypeSendMessage,
		SessionID: session.ID(),
		Payload:   prependSessionID(session.ID(), wire),
	}
}

// newStatusTestServer builds a server with a registered session whose connection
// is a buffer, so the asynchronous status path can be observed on the wire.
func newStatusTestServer(t *testing.T) (*Server, *Session, *bytes.Buffer) {
	t.Helper()

	server, err := NewServer(&ServerConfig{})
	require.NoError(t, err)

	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.manager.DestroySession(session.ID()) })

	buf := &bytes.Buffer{}
	server.mu.Lock()
	if server.sessionConns == nil {
		server.sessionConns = make(map[uint16]net.Conn)
	}
	if server.connWriteMu == nil {
		server.connWriteMu = make(map[uint16]*sync.Mutex)
	}
	server.sessionConns[session.ID()] = &syncBufConn{Buffer: buf}
	server.connWriteMu[session.ID()] = &sync.Mutex{}
	server.mu.Unlock()

	return server, session, buf
}

// syncBufConn is a bytes.Buffer-backed net.Conn safe for concurrent writes.
type syncBufConn struct {
	*bytes.Buffer
	mu sync.Mutex
}

func (c *syncBufConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Buffer.Write(b)
}

func (c *syncBufConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *syncBufConn) Close() error                     { return nil }
func (c *syncBufConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *syncBufConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *syncBufConn) SetDeadline(time.Time) error      { return nil }
func (c *syncBufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *syncBufConn) SetWriteDeadline(time.Time) error { return nil }

// snapshot returns a copy of everything written so far.
func (c *syncBufConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.Buffer.Bytes()...)
}

// statusFrame is a decoded MessageStatus read off the wire.
type statusFrame struct {
	MessageID uint32
	Status    uint8
	Size      uint32
	Nonce     uint32
}

// waitForStatusFrames decodes the MessageStatus messages written to the mock
// connection, waiting until at least one arrives or the timeout expires.
//
// The I2CP wire framing is length(4) + type(1) + payload (i2cp.rst:216-222), so
// frames are decoded with the same header parser the server uses.
func waitForStatusFrames(t *testing.T, conn *syncBufConn, timeout time.Duration) []statusFrame {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		frames := decodeStatusFrames(conn.snapshot())
		if len(frames) > 0 || time.Now().After(deadline) {
			return frames
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func decodeStatusFrames(data []byte) []statusFrame {
	var frames []statusFrame
	for len(data) >= 5 {
		payloadLen := int(binary.BigEndian.Uint32(data[0:4]))
		msgType := data[4]
		if payloadLen < 0 || 5+payloadLen > len(data) {
			break
		}
		payload := data[5 : 5+payloadLen]
		if msgType == MessageTypeMessageStatus && len(payload) >= 15 {
			frames = append(frames, statusFrame{
				MessageID: binary.BigEndian.Uint32(payload[2:6]),
				Status:    payload[6],
				Size:      binary.BigEndian.Uint32(payload[7:11]),
				Nonce:     binary.BigEndian.Uint32(payload[11:15]),
			})
		}
		data = data[5+payloadLen:]
	}
	return frames
}

// stubResolver resolves any destination hash to a fixed encryption key.
type stubResolver struct{ key common.Hash }

func (r stubResolver) ResolveDestination(_ common.Hash) ([32]byte, error) {
	return r.key, nil
}

// privateKeyEntry is one CreateLeaseSet2 [PrivateKey]_ entry.
type privateKeyEntry struct {
	Type uint16
	Data []byte
}

// buildCreateLeaseSet2Payload assembles the spec layout:
// [store type (1)][lease set][num keys (1)][(type(2) len(2) key)...]
func buildCreateLeaseSet2Payload(t *testing.T, storeType LeaseSetStoreType, leaseSet []byte, keys []privateKeyEntry) []byte {
	t.Helper()

	out := make([]byte, 0, len(leaseSet)+3+8*len(keys))
	out = append(out, byte(storeType))
	out = append(out, leaseSet...)
	out = append(out, byte(len(keys)))
	for _, k := range keys {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], k.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(k.Data)))
		out = append(out, hdr[:]...)
		out = append(out, k.Data...)
	}
	return out
}

func buildCreateLeaseSet2Message(t *testing.T, sessionID uint16, storeType LeaseSetStoreType, leaseSet []byte, keys []privateKeyEntry) *Message {
	t.Helper()
	return &Message{
		Type:      MessageTypeCreateLeaseSet2,
		SessionID: sessionID,
		Payload:   prependSessionID(sessionID, buildCreateLeaseSet2Payload(t, storeType, leaseSet, keys)),
	}
}

// createTestSessionWithLeaseSetV1 builds a session whose destination uses the
// ElGamal encryption key a type-1 LeaseSet requires (lease_set.NewLeaseSet
// rejects non-ElGamal crypto), plus a signed LeaseSet for it.
func createTestSessionWithLeaseSetV1(t *testing.T) (*Session, []byte) {
	t.Helper()

	encPub, _, err := elg.GenerateKeyPair()
	require.NoError(t, err)

	keyStore, err := keys.NewDestinationKeyStore()
	require.NoError(t, err)
	sigKey, err := keyStore.SigningPublicKey()
	require.NoError(t, err)

	cert, err := key_certificate.NewKeyCertificateWithTypes(
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_ELG,
	)
	require.NoError(t, err)

	kac, err := keys_and_cert.NewKeysAndCert(
		cert,
		encPub,
		make([]byte, keys_and_cert.ExpectedPaddingSize(cert.CryptoSize(), cert.SigningPublicKeySize())),
		sigKey,
	)
	require.NoError(t, err)

	dest, err := destination.NewDestination(kac)
	require.NoError(t, err)

	ls, err := lease_set.NewLeaseSet(*dest, encPub, sigKey, nil, keyStore.SigningPrivateKey())
	require.NoError(t, err)
	require.NoError(t, ls.Verify(), "the fixture must be self-consistent")

	lsBytes, err := ls.Bytes()
	require.NoError(t, err)

	server, err := NewServer(&ServerConfig{})
	require.NoError(t, err)
	session, err := server.manager.CreateSession(dest, nil)
	require.NoError(t, err)

	return session, lsBytes
}

// buildBlindedEncryptedLeaseSet builds a spec-conformant blinded
// EncryptedLeaseSet for the session's destination: the blinded signing key
// derived per common-structures.rst §Blinding, signed with the blinded Red25519
// scalar (sigType 11), carrying the session's LeaseSet2 as encrypted inner data.
func buildBlindedEncryptedLeaseSet(t *testing.T, session *Session, innerLS2 []byte) []byte {
	t.Helper()

	const secret = "w8-test-blinding-secret!!!!!!!!!"
	date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	dest := session.Destination()
	spk, err := dest.SigningPublicKey()
	require.NoError(t, err)

	sigType := uint16(dest.KeyCertificate.SigningPublicKeyType())
	alpha, err := kdf.DeriveBlindingFactorI2P(spk.Bytes(), secret, sigType, date)
	require.NoError(t, err)

	blindedDest, err := encrypted_leaseset.CreateBlindedDestination(*dest, []byte(secret), date)
	require.NoError(t, err)
	blindedSPK, err := blindedDest.SigningPublicKey()
	require.NoError(t, err)

	priv := session.keys.SigningPrivateKey()
	var p64 []byte
	switch v := priv.(type) {
	case *ed25519.Ed25519PrivateKey:
		p64 = []byte(*v)
	default:
		p64 = v.(interface{ Bytes() []byte }).Bytes()
	}

	redPriv, err := red25519.ConvertEd25519PrivateKey(p64)
	require.NoError(t, err)
	blindedPriv, err := red25519.BlindPrivateKey(redPriv, red25519.BlindingFactor(alpha))
	require.NoError(t, err)

	els, err := encrypted_leaseset.NewEncryptedLeaseSet(
		uint16(blindedDest.KeyCertificate.SigningPublicKeyType()),
		blindedSPK.Bytes(),
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		innerLS2,
		blindedPriv,
	)
	require.NoError(t, err)

	require.NoError(t, els.Verify(), "the fixture must be self-consistent")

	elsBytes, err := els.Bytes()
	require.NoError(t, err)
	return elsBytes
}

// buildSignedCreateSessionPayloadWithOptions assembles a Session Config with an
// explicit options Mapping: [Destination][Mapping][Date][Signature].
func buildSignedCreateSessionPayloadWithOptions(t *testing.T, id testIdentity, options []byte) []byte {
	t.Helper()

	payload := make([]byte, 0, len(id.DestBytes)+len(options)+8+64)
	payload = append(payload, id.DestBytes...)
	payload = append(payload, options...)

	date := make([]byte, 8)
	binary.BigEndian.PutUint64(date, uint64(time.Now().UnixMilli()))
	payload = append(payload, date...)

	signer, err := id.SigPriv.NewSigner()
	require.NoError(t, err)
	signature, err := signer.Sign(payload)
	require.NoError(t, err)

	return append(payload, signature...)
}

// buildMappingPayload serialises an I2P Mapping in the given key order, so a
// test can exercise both the sorted and the unsorted case.
func buildMappingPayload(t *testing.T, pairs [][2]string) []byte {
	t.Helper()

	var body []byte
	for _, kv := range pairs {
		// An I2P String is a 1-byte length followed by the UTF-8 bytes
		// (common-structures.rst:57).
		body = append(body, byte(len(kv[0])))
		body = append(body, kv[0]...)
		body = append(body, '=')
		body = append(body, byte(len(kv[1])))
		body = append(body, kv[1]...)
		body = append(body, ';')
	}

	out := make([]byte, 2, 2+len(body))
	binary.BigEndian.PutUint16(out, uint16(len(body)))
	return append(out, body...)
}

// mustMarshal marshals a message or fails the test.
func (m *Message) mustMarshal(t *testing.T) []byte {
	t.Helper()
	b, err := m.MarshalBinary()
	require.NoError(t, err)
	return b
}
