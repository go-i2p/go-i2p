// C5 compliance tests: BlindingInfo (type 42) must parse the spec wire format
// and be recorded as advice about a blinded *peer* destination, without
// corrupting the session's own EncryptedLeaseSet configuration.
package i2cp

import (
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hashKey wraps a raw 32-byte blinded destination hash as a common.Hash, the
// key a type-0 (hash) BlindingInfo endpoint is stored under.
func hashKey(b []byte) common.Hash {
	var h common.Hash
	copy(h[:], b)
	return h
}

// buildBlindingInfoHashPayload assembles a spec BlindingInfo payload for a
// hash endpoint with the given flags, per-client key, and password.
func buildBlindingInfoHashPayload(sessionID uint16, flags byte, hash, privKey []byte, password string) []byte {
	data := make([]byte, 10)
	binary.BigEndian.PutUint16(data[0:2], sessionID)
	data[2] = flags
	data[3] = BlindingEndpointHash
	binary.BigEndian.PutUint16(data[4:6], 7) // blinded Ed25519 sig type
	binary.BigEndian.PutUint32(data[6:10], 1_900_000_000)
	data = append(data, hash...)
	if flags&blindingFlagPerClient != 0 {
		data = append(data, privKey...)
	}
	if flags&blindingFlagSecret != 0 {
		data = append(data, byte(len(password)))
		data = append(data, password...)
	}
	return data
}

// TestHandleBlindingInfo_RecordsPeerAdvice verifies the router stores the
// advice keyed by the blinded peer hash and sends no reply (spec: "The router
// does not send a reply to this message").
func TestHandleBlindingInfo_RecordsPeerAdvice(t *testing.T) {
	server := newTestI2CPServer(t, "")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)
	defer server.manager.DestroySession(session.ID())

	peerHash := make([]byte, 32)
	for i := range peerHash {
		peerHash[i] = byte(0xA0 + i)
	}
	payload := buildBlindingInfoHashPayload(session.ID(), 0x00, peerHash, nil, "")

	msg := &Message{Type: MessageTypeBlindingInfo, SessionID: session.ID(), Payload: payload}

	var sessionPtr *Session = session
	response, err := server.handleBlindingInfo(msg, &sessionPtr)
	require.NoError(t, err)
	assert.Nil(t, response, "BlindingInfo must not produce a reply")

	advice, ok := server.BlindingAdviceFor(hashKey(peerHash))
	require.True(t, ok, "advice must be recorded under the blinded peer hash")
	assert.Equal(t, session.ID(), advice.SessionID)
	assert.Equal(t, peerHash, advice.Hash)
}

// TestHandleBlindingInfo_DoesNotCorruptSessionConfig verifies the critical
// regression: the old handler flipped the session's own UseEncryptedLeaseSet
// and BlindingSecret from a message that only concerns a peer. A conforming
// session's own config must be untouched.
func TestHandleBlindingInfo_DoesNotCorruptSessionConfig(t *testing.T) {
	server := newTestI2CPServer(t, "")

	// A router-managed session that does NOT use an encrypted lease set.
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)
	defer server.manager.DestroySession(session.ID())

	require.False(t, session.Config().UseEncryptedLeaseSet, "baseline: encrypted LS disabled")

	peerHash := make([]byte, 32)
	privKey := make([]byte, 32)
	for i := range privKey {
		privKey[i] = byte(i + 1)
	}
	// flags: per-client (0x01) + secret (0x10) = 0x11
	payload := buildBlindingInfoHashPayload(session.ID(), 0x11, peerHash, privKey, "hunter2")

	msg := &Message{Type: MessageTypeBlindingInfo, SessionID: session.ID(), Payload: payload}
	_, err = server.handleBlindingInfo(msg, &session)
	require.NoError(t, err)

	assert.False(t, session.Config().UseEncryptedLeaseSet,
		"peer blinding advice must not enable the session's own encrypted lease set")
	assert.Nil(t, session.Config().BlindingSecret,
		"peer blinding advice must not set the session's own blinding secret")

	// The per-client key/password are stored with the advice, not applied to the session.
	advice, ok := server.BlindingAdviceFor(hashKey(peerHash))
	require.True(t, ok)
	assert.Equal(t, privKey, advice.PrivateKey)
	assert.Equal(t, "hunter2", advice.Password)
}

// TestHandleBlindingInfo_SessionIDMismatchRejected verifies a payload whose
// embedded session ID disagrees with the message header is refused.
func TestHandleBlindingInfo_SessionIDMismatchRejected(t *testing.T) {
	server := newTestI2CPServer(t, "")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)
	defer server.manager.DestroySession(session.ID())

	peerHash := make([]byte, 32)
	// Payload claims session 9999, but the message header carries session.ID().
	payload := buildBlindingInfoHashPayload(9999, 0x00, peerHash, nil, "")
	msg := &Message{Type: MessageTypeBlindingInfo, SessionID: session.ID(), Payload: payload}

	_, err = server.handleBlindingInfo(msg, &session)
	require.Error(t, err, "mismatched session ID must be rejected")
}

// TestHandleBlindingInfo_MalformedPayloadRejected verifies a truncated payload
// is refused with a parse error.
func TestHandleBlindingInfo_MalformedPayloadRejected(t *testing.T) {
	server := newTestI2CPServer(t, "")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)
	defer server.manager.DestroySession(session.ID())

	msg := &Message{Type: MessageTypeBlindingInfo, SessionID: session.ID(), Payload: []byte{0x01, 0x02}}
	_, err = server.handleBlindingInfo(msg, &session)
	require.Error(t, err, "malformed BlindingInfo payload must be rejected")
}

// TestForgetBlindingAdviceForSession verifies advice is dropped when a session
// goes away, so a departing client's per-client keys are not retained.
func TestForgetBlindingAdviceForSession(t *testing.T) {
	server := newTestI2CPServer(t, "")
	session, err := server.manager.CreateSession(nil, nil)
	require.NoError(t, err)

	peerHash := make([]byte, 32)
	payload := buildBlindingInfoHashPayload(session.ID(), 0x00, peerHash, nil, "")
	msg := &Message{Type: MessageTypeBlindingInfo, SessionID: session.ID(), Payload: payload}
	_, err = server.handleBlindingInfo(msg, &session)
	require.NoError(t, err)

	key := hashKey(peerHash)
	_, ok := server.BlindingAdviceFor(key)
	require.True(t, ok, "advice present before destroy")

	require.NoError(t, server.manager.DestroySession(session.ID()))
	server.forgetBlindingAdviceForSession(session.ID())

	_, ok = server.BlindingAdviceFor(key)
	assert.False(t, ok, "advice must be dropped when the session is destroyed")
}
