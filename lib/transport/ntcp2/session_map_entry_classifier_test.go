// Regression tests for the session-map entry classifier misclassifying
// accepted (inbound) connections as an "unexpected session map entry type".
//
// Root cause: SessionRegistry.MarkAccepted stores the accepted marker as a
// pointer (*transport.AcceptedConn), but the NTCP2/SSU2 classifiers asserted
// the value form (transport.AcceptedConn). The pointer never matched, so a
// legitimately-present accepted entry fell through to entryIsUnexpected,
// producing spurious "unexpected session map entry type" errors and forcing
// redundant re-dials under concurrent accepted + dialed sessions.

package ntcp2

import (
	"testing"

	transportpkg "github.com/go-i2p/go-i2p/lib/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveSessionMapEntry_AcceptedConnPointerForm asserts that an entry
// stored as *transport.AcceptedConn — the form SessionRegistry.MarkAccepted
// actually writes — is classified as entryIsAcceptedConn, NOT entryIsUnexpected.
func TestResolveSessionMapEntry_AcceptedConnPointerForm(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	rawConn := newLiveMockConn("192.168.1.10:6001")
	defer rawConn.Close()

	// This is exactly what MarkAccepted stores: &AcceptedConn{Value: original}.
	marker := &transportpkg.AcceptedConn{Value: rawConn}

	resolution := transport.resolveSessionMapEntry(marker)
	require.NotEqual(t, entryIsUnexpected, resolution.kind,
		"*transport.AcceptedConn must not be classified as unexpected")
	assert.Equal(t, entryIsAcceptedConn, resolution.kind,
		"*transport.AcceptedConn should classify as entryIsAcceptedConn")
}

// TestResolveSessionMapEntry_AcceptedConnValueForm asserts the value form is
// still recognized (some tests and earlier code paths used the value form).
func TestResolveSessionMapEntry_AcceptedConnValueForm(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	rawConn := newLiveMockConn("192.168.1.11:6002")
	defer rawConn.Close()

	marker := transportpkg.AcceptedConn{Value: rawConn}

	resolution := transport.resolveSessionMapEntry(marker)
	require.NotEqual(t, entryIsUnexpected, resolution.kind,
		"transport.AcceptedConn (value) must not be classified as unexpected")
	assert.Equal(t, entryIsAcceptedConn, resolution.kind)
}

// TestFindExistingSession_AcceptedConnPointerForm verifies findExistingSession
// does not log "unexpected session map entry type" for a pointer-form accepted
// marker: it returns not-found (the Accept consumer owns the socket) rather
// than the unexpected-entry path, and leaves the entry in the map.
func TestFindExistingSession_AcceptedConnPointerForm(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	peerHash := newTestPeerHash("accepted-conn-ptr-find-test!!")
	rawConn := newLiveMockConn("192.168.1.12:6003")
	defer rawConn.Close()

	transport.sessionRegistry.StoreWithCount(peerHash, &transportpkg.AcceptedConn{Value: rawConn})

	session, found := transport.findExistingSession(peerHash)
	// The accepted conn is owned by Accept(); findExistingSession reports it as
	// not-reusable (no session), but crucially NOT via the unexpected-entry path.
	assert.Nil(t, session)
	assert.False(t, found)

	// The entry must remain in the map (not deleted as "corrupt").
	_, exists := transport.sessionRegistry.Load(peerHash)
	assert.True(t, exists, "accepted marker must not be evicted as corrupt")
}

// TestResolveExistingSession_AcceptedConnPointerForm verifies resolveExistingSession
// returns nil (Accept owns the socket) for a pointer-form accepted marker without
// taking the unexpected-entry branch.
func TestResolveExistingSession_AcceptedConnPointerForm(t *testing.T) {
	transport := newNilListenerTestTransport(t, 100)

	peerHash := newTestPeerHash("accepted-conn-ptr-resolve-test")
	rawConn := newLiveMockConn("192.168.1.13:6004")
	defer rawConn.Close()

	result := transport.resolveExistingSession(&transportpkg.AcceptedConn{Value: rawConn}, peerHash)
	assert.Nil(t, result, "accepted marker should resolve to nil (Accept owns socket)")
}

// TestIsAcceptedConnHelper verifies the shared recognition helper matches both
// the value and pointer forms and rejects other types.
func TestIsAcceptedConnHelper(t *testing.T) {
	rawConn := newLiveMockConn("192.168.1.14:6005")
	defer rawConn.Close()

	assert.True(t, transportpkg.IsAcceptedConn(transportpkg.AcceptedConn{Value: rawConn}))
	assert.True(t, transportpkg.IsAcceptedConn(&transportpkg.AcceptedConn{Value: rawConn}))
	assert.False(t, transportpkg.IsAcceptedConn(rawConn))
	assert.False(t, transportpkg.IsAcceptedConn("not-a-marker"))

	val, ok := transportpkg.AcceptedConnValue(&transportpkg.AcceptedConn{Value: rawConn})
	assert.True(t, ok)
	assert.Equal(t, rawConn, val)
}
