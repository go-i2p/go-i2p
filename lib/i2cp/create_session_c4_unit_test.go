// C4 compliance tests: I2CP CreateSession must accept a conforming client —
// a Destination plus a Session Config signed by the client's own signing key,
// with NO private keys transmitted to the router — and must reject a duplicate
// Destination per the spec's CreateSessionMessage notes.
package i2cp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildSignedCreateSessionPayload assembles the spec's Session Config wire
// format: [Destination][Mapping][Date][Signature], where the signature covers
// the first three fields and is produced by the destination's signing private
// key. The router verifies it with the signing PUBLIC key embedded in the
// Destination — the client never sends private keys.
func buildSignedCreateSessionPayload(t *testing.T, id testIdentity) []byte {
	t.Helper()
	return buildSignedCreateSessionPayloadAt(t, id, time.Now())
}

// buildSignedCreateSessionPayloadAt signs a Session Config carrying an
// arbitrary creation Date, for exercising the +/- 30 second clock-skew rule.
func buildSignedCreateSessionPayloadAt(t *testing.T, id testIdentity, when time.Time) []byte {
	t.Helper()

	destBytes, err := id.Dest.Bytes()
	require.NoError(t, err)

	// Empty options Mapping: a 2-byte size field of 0.
	mapping := []byte{0x00, 0x00}

	payload := make([]byte, 0, len(destBytes)+len(mapping)+8+64)
	payload = append(payload, destBytes...)
	payload = append(payload, mapping...)

	date := make([]byte, 8)
	binary.BigEndian.PutUint64(date, uint64(when.UnixMilli()))
	payload = append(payload, date...)

	signer, err := id.SigPriv.NewSigner()
	require.NoError(t, err)
	sig, err := signer.Sign(payload)
	require.NoError(t, err)

	return append(payload, sig...)
}

// TestHandleCreateSession_ConformingClientAccepted verifies the C4 fix: a real
// client CreateSession (destination + signature, no private keys) is accepted
// with SessionStatus(Created) and yields a live client-managed session,
// instead of the previous blanket SessionStatus(Refused).
func TestHandleCreateSession_ConformingClientAccepted(t *testing.T) {
	server := newTestI2CPServer(t, "")
	id := generateTestIdentity(t)

	msg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   buildSignedCreateSessionPayload(t, id),
	}

	var sessionPtr *Session
	response, err := server.handleCreateSession(msg, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Equal(t, MessageTypeSessionStatus, response.Type)
	require.Len(t, response.Payload, 3)
	assert.Equal(t, SessionStatusCreated, response.Payload[2],
		"a conforming client must not be refused")

	require.NotNil(t, sessionPtr, "session must be established")
	defer server.SessionManager().DestroySession(sessionPtr.ID())

	assert.True(t, sessionPtr.IsClientManaged(), "session adopts the client's public identity")
	assert.True(t, sessionPtr.Destination().Equals(id.Dest),
		"the router must keep the client's destination verbatim")
	assert.Equal(t, 1, server.SessionManager().SessionCount())
}

// TestHandleCreateSession_DuplicateDestinationRefused verifies the spec rule:
// "If there is already a session on the router for this Destination, the
// session will be rejected."
func TestHandleCreateSession_DuplicateDestinationRefused(t *testing.T) {
	server := newTestI2CPServer(t, "")
	id := generateTestIdentity(t)

	first := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   buildSignedCreateSessionPayload(t, id),
	}

	var sessionPtr *Session
	response, err := server.handleCreateSession(first, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, sessionPtr)
	require.Equal(t, SessionStatusCreated, response.Payload[2])
	sessionID := sessionPtr.ID()
	defer server.SessionManager().DestroySession(sessionID)

	// Second CreateSession for the same Destination must be refused.
	second := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   buildSignedCreateSessionPayload(t, id),
	}

	var dupPtr *Session
	response, err = server.handleCreateSession(second, &dupPtr)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Nil(t, dupPtr, "no session may be created for a duplicate destination")
	require.Len(t, response.Payload, 3)
	assert.Equal(t, SessionStatusRefused, response.Payload[2],
		"duplicate Destination must be refused")

	assert.Equal(t, 1, server.SessionManager().SessionCount(),
		"the existing session must remain and no second session be created")
}

// TestHandleCreateSession_TamperedSignatureRejected verifies the router still
// validates the Session Config signature: a payload signed by the client key
// but altered in transit must not be accepted.
func TestHandleCreateSession_TamperedSignatureRejected(t *testing.T) {
	server := newTestI2CPServer(t, "")
	id := generateTestIdentity(t)

	payload := buildSignedCreateSessionPayload(t, id)
	// Flip a byte in the destination region so the signature no longer matches.
	payload[10] ^= 0xFF

	msg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   payload,
	}

	var sessionPtr *Session
	response, err := server.handleCreateSession(msg, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Nil(t, sessionPtr, "a bad signature must not establish a session")
	assert.Equal(t, SessionStatusInvalid, response.Payload[2])
}

// TestHandleCreateSession_StaleDateRejected verifies the spec rule: "If the
// Date in the Session Config is too far (more than +/- 30 seconds) from the
// router's current time, the session will be rejected."
func TestHandleCreateSession_StaleDateRejected(t *testing.T) {
	server := newTestI2CPServer(t, "")
	id := generateTestIdentity(t)

	stale := buildSignedCreateSessionPayloadAt(t, id, time.Now().Add(-2*time.Minute))
	msg := &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   stale,
	}

	var sessionPtr *Session
	response, err := server.handleCreateSession(msg, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Nil(t, sessionPtr, "a stale creation date must not establish a session")
	assert.Equal(t, SessionStatusInvalid, response.Payload[2])

	// A small skew within tolerance must still be accepted.
	fresh := buildSignedCreateSessionPayloadAt(t, id, time.Now().Add(-10*time.Second))
	msg = &Message{
		Type:      MessageTypeCreateSession,
		SessionID: SessionIDReservedControl,
		Payload:   fresh,
	}
	response, err = server.handleCreateSession(msg, &sessionPtr)
	require.NoError(t, err)
	require.NotNil(t, sessionPtr)
	assert.Equal(t, SessionStatusCreated, response.Payload[2])
	server.SessionManager().DestroySession(sessionPtr.ID())
}

// TestCreateSession_ClientManagedMaintenanceSkipped verifies router-side
// LeaseSet maintenance is skipped (not failed) for client-managed sessions:
// the client publishes its own LeaseSet2 via CreateLeaseSet2.
func TestCreateSession_ClientManagedMaintenanceSkipped(t *testing.T) {
	sm := NewSessionManager()
	id := generateTestIdentity(t)

	session, err := sm.CreateSession(id.Dest, nil)
	require.NoError(t, err)
	defer sm.DestroySession(session.ID())

	require.True(t, session.IsClientManaged())

	// Maintenance must be a no-op rather than a signing failure.
	require.NoError(t, session.maintainLeaseSet(),
		"client-managed sessions skip router-side LeaseSet maintenance")

	// Router-side LeaseSet generation is explicitly refused.
	_, err = session.CreateLeaseSet()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client-managed")

	// A client-supplied LeaseSet2 is still accepted and cached.
	fakeLeaseSet := make([]byte, 400)
	fakeLeaseSet[0] = 3 // LeaseSet2 store type marker (validation is length/parse based)
	session.SetCurrentLeaseSet(fakeLeaseSet)
	assert.Equal(t, fakeLeaseSet, session.CurrentLeaseSet(),
		"CreateLeaseSet2-provided LeaseSet2 bytes are cached")
}
