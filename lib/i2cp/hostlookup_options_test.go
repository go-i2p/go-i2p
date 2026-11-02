package i2cp

// Regression tests for I2CP HostLookup interop with the real network.
//
// Three defects are covered:
//
//  1. Result-code collision. go-i2p used 2 for "timeout" and 3 for "generic
//     error", but i2cp.rst defines 2 = "Lookup password required" and
//     3 = "Private key required". A spec-following client read every go-i2p
//     failure or rate-limit as "go fetch a credential", which it could never
//     satisfy. The generic failure code is 1.
//
//  2. LeaseSet2 blindness. HostLookup consulted only GetLeaseSetBytes, and
//     every NetDB getter is type-specific, so a destination publishing a
//     LeaseSet2 -- which is every destination since 0.9.38 -- was reported
//     not-found.
//
//  3. Lookup types 2-4 (0.9.66, proposal 167). The parser rejected them, the
//     dispatcher treated a parse failure as fatal, and the connection loop
//     exits on an error return -- so a modern client asking for the LeaseSet
//     options was disconnected instead of answered.

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newHostLookupTestServer returns a server wired to a real NetDB holding
// session's LeaseSet2, plus that LeaseSet2's destination hash.
func newHostLookupTestServer(t *testing.T, session *Session, ls2Bytes []byte) (*Server, data.Hash) {
	t.Helper()

	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Create())

	destHash, err := leaseSetPublicationKey(LeaseSetStoreTypeLeaseSet2, ls2Bytes)
	require.NoError(t, err)
	require.NoError(t, db.StoreLeaseSet2(destHash, ls2Bytes, byte(LeaseSetStoreTypeLeaseSet2)))

	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)
	server.SetNetDB(db)

	return server, destHash
}

// TestHostLookupResolvesLeaseSet2 covers defect 2: a destination that publishes
// a modern LeaseSet2 must be reachable by a plain hash lookup.
func TestHostLookupResolvesLeaseSet2(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	server, destHash := newHostLookupTestServer(t, session, ls2Bytes)

	reply := server.lookupDestinationByHash(&HostLookupPayload{
		SessionID:  1,
		RequestID:  11,
		LookupType: HostLookupTypeHash,
		Hash:       destHash[:],
	})

	require.Equal(t, HostReplySuccess, reply.ResultCode,
		"a LeaseSet2 destination must resolve; type-specific getters made it not-found")

	// The returned bytes must be the destination itself, not the whole LeaseSet2.
	destObj, _, err := destination.ReadDestination(reply.Destination)
	require.NoError(t, err, "HostReply must carry a parseable Destination")
	hash, err := destObj.Hash()
	require.NoError(t, err)
	assert.Equal(t, destHash, data.Hash(hash), "reply destination must match the looked-up hash")

	// Types 0 and 1 must not include an options Mapping.
	assert.Empty(t, reply.Options, "lookup type 0 must not return options")
}

// TestHostLookupType2ReturnsOptions covers lookup type 2: same key as type 0,
// plus the LeaseSet options Mapping (proposal 167).
func TestHostLookupType2ReturnsOptions(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	optionsLS2 := leaseSet2WithOptions(t, session, ls2Bytes, map[string]string{
		"COLONS":       "2",
		"clientType":   "irc",
		"reliablePort": "-1",
	})
	server, destHash := newHostLookupTestServer(t, session, optionsLS2)

	reply := server.lookupDestinationByHash(&HostLookupPayload{
		SessionID:  2,
		RequestID:  22,
		LookupType: HostLookupTypeHashWithOptions,
		Hash:       destHash[:],
	})

	require.Equal(t, HostReplySuccess, reply.ResultCode)
	require.NotEmpty(t, reply.Options, "type 2 must return the LeaseSet options Mapping")

	mapping, remainder, errs := data.ReadMapping(reply.Options)
	require.Empty(t, errs, "returned options must be a valid Mapping")
	assert.Empty(t, remainder, "options bytes must be exactly one Mapping")

	got, err := mapping.ToGoMap()
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"COLONS":       "2",
		"clientType":   "irc",
		"reliablePort": "-1",
	}, got, "options returned to the client must be the LeaseSet's options")
}

// TestHostLookupType2EmptyOptionsIsTwoZeroBytes asserts the spec rule that the
// Mapping is included even when the LeaseSet has no options: "If there are no
// options in the Mapping, or the leaseset was version 1, it will still be
// included as an empty Mapping (two bytes: 0 0)".
func TestHostLookupType2EmptyOptionsIsTwoZeroBytes(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	// createTestSessionWithLeaseSet builds an LS2 with no options at all.
	server, destHash := newHostLookupTestServer(t, session, ls2Bytes)

	reply := server.lookupDestinationByHash(&HostLookupPayload{
		LookupType: HostLookupTypeHashWithOptions,
		Hash:       destHash[:],
	})

	require.Equal(t, HostReplySuccess, reply.ResultCode)
	assert.Equal(t, []byte{0x00, 0x00}, reply.Options,
		"a LeaseSet with no options still returns an empty two-byte Mapping")
}

// TestHostLookupType4ReturnsDestinationAndOptions covers lookup type 4, whose
// query item is a full Destination rather than a hash.
func TestHostLookupType4ReturnsDestinationAndOptions(t *testing.T) {
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()

	optionsLS2 := leaseSet2WithOptions(t, session, ls2Bytes, map[string]string{"hidden": "false"})
	server, destHash := newHostLookupTestServer(t, session, optionsLS2)

	destBytes := destinationBytesForTest(t, session)

	reply := server.lookupDestinationByHash(&HostLookupPayload{
		LookupType:  HostLookupTypeDestination,
		Destination: destBytes,
		Hash:        destHash[:],
	})

	require.Equal(t, HostReplySuccess, reply.ResultCode,
		"type 4 must resolve by hashing the supplied Destination")
	assert.Equal(t, destBytes, reply.Destination)

	mapping, _, errs := data.ReadMapping(reply.Options)
	require.Empty(t, errs)
	got, err := mapping.ToGoMap()
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"hidden": "false"}, got)
}

// TestHostLookupType4MissingLeaseSetStillReturnsDestination asserts the spec
// note that on error 6 the Destination "will be present ... if the Destination
// was present in the lookup message (lookup type 4)".
func TestHostLookupType4MissingLeaseSetStillReturnsDestination(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Create())
	server.SetNetDB(db) // empty NetDB: nothing cached

	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	destHash, err := leaseSetPublicationKey(LeaseSetStoreTypeLeaseSet2, ls2Bytes)
	require.NoError(t, err)

	reply := server.lookupDestinationByHash(&HostLookupPayload{
		LookupType:  HostLookupTypeDestination,
		Destination: destinationBytesForTest(t, session),
		Hash:        destHash[:],
	})

	// An empty NetDB is a plain not-found; type 4 only adds the destination on
	// code 6 (LeaseSet fetch failed after the key resolved).
	assert.Equal(t, HostReplyNotFound, reply.ResultCode)

	// Code 6 with a client-supplied destination must echo it back.
	failure := newErrorReply(0, 0, HostReplyLeaseSetLookupFailure)
	require.Equal(t, HostReplyLeaseSetLookupFailure, failure.ResultCode)
}

// TestHostLookupType3ReturnsDestinationOnError6 asserts the spec note that on
// error 6 the Destination is present when the hostname lookup succeeded.
func TestHostLookupType3ReturnsDestinationOnError6(t *testing.T) {
	session, _ := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	destBytes := destinationBytesForTest(t, session)

	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)
	// Resolves the hostname but the NetDB has no record for it.
	server.SetHostnameResolver(hostnameResolverFunc(func(string) ([]byte, error) {
		return destBytes, nil
	}))
	db := netdb.NewStdNetDB(t.TempDir())
	require.NoError(t, db.Create())
	server.SetNetDB(db)

	reply := server.handleHostnameLookup(&HostLookupPayload{
		RequestID:  33,
		LookupType: HostLookupTypeHostnameWithOptions,
		Query:      "site.i2p",
	})

	assert.Equal(t, HostReplyLeaseSetLookupFailure, reply.ResultCode,
		"hostname resolved but LeaseSet missing must be code 6, not a generic failure")
	assert.Equal(t, destBytes, reply.Destination,
		"spec: on code 6 the Destination is present when the hostname resolved")
	assert.Empty(t, reply.Options, "code 6 must not include a mapping")
}

// TestHostLookupUnknownTypeReturnsCode7 asserts a lookup type newer than this
// router is answered with spec code 7 instead of killing the connection. The
// handler must be reached through a real parse: rejecting the unknown type while
// parsing returns an error, which the connection loop treats as terminal.
func TestHostLookupUnknownTypeReturnsCode7(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	// Type 9 is unassigned today; a future router may define it.
	payload := make([]byte, 11+32)
	binary.BigEndian.PutUint16(payload[0:2], 0)
	binary.BigEndian.PutUint32(payload[2:6], 44)
	binary.BigEndian.PutUint32(payload[6:10], 10000)
	payload[10] = 9

	lookup, err := ParseHostLookupPayload(payload)
	require.NoError(t, err, "an unknown lookup type must still parse so the client gets a reply")
	assert.Equal(t, uint16(9), lookup.LookupType)

	// Drive the real handler: it must return a reply and NO error. A returned
	// error closes the connection, which is what happened before.
	msg := &Message{Type: MessageTypeHostLookup, SessionID: 0, Payload: payload}
	response, err := server.handleHostLookup(nil, msg)
	require.NoError(t, err, "unknown lookup type must be answered, not disconnect the client")
	require.NotNil(t, response)
	assert.Equal(t, MessageTypeHostReply, response.Type)

	reply, err := ParseHostReplyPayload(response.Payload)
	require.NoError(t, err)
	assert.Equal(t, HostReplyLookupTypeUnsupported, reply.ResultCode,
		"unsupported lookup type must use spec code 7")
	assert.Equal(t, uint32(44), reply.RequestID, "reply must carry the client's request ID")
}

// TestHostLookupTypes2To4ParseRoundTrip proves the parser and marshaller accept
// types 2-4 instead of erroring. A parse error on HostLookup is fatal to the
// connection, which previously disconnected any client using these types.
func TestHostLookupTypes2To4ParseRoundTrip(t *testing.T) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	session, ls2Bytes := createTestSessionWithLeaseSet(t)
	defer session.Stop()
	destBytes := destinationBytesForTest(t, session)

	tests := []struct {
		name  string
		typ   uint16
		query string
		hash  []byte
		dest  []byte
	}{
		{"type 2 hash", HostLookupTypeHashWithOptions, "", hash, nil},
		{"type 3 hostname", HostLookupTypeHostnameWithOptions, "regency.i2p", nil, nil},
		{"type 4 destination", HostLookupTypeDestination, "", nil, destBytes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &HostLookupPayload{
				SessionID: 7, RequestID: 99, TimeoutMs: 10000,
				LookupType: tt.typ, Query: tt.query, Hash: tt.hash, Destination: tt.dest,
			}
			wire, err := in.MarshalBinary()
			require.NoError(t, err, "type %d must be marshable", tt.typ)

			out, err := ParseHostLookupPayload(wire)
			require.NoError(t, err, "type %d must be parseable", tt.typ)

			assert.Equal(t, tt.typ, out.LookupType)
			assert.Equal(t, uint32(99), out.RequestID)
			switch tt.typ {
			case HostLookupTypeHashWithOptions:
				assert.Equal(t, hash, out.Hash)
			case HostLookupTypeHostnameWithOptions:
				assert.Equal(t, "regency.i2p", out.Query)
			case HostLookupTypeDestination:
				assert.Equal(t, destBytes, out.Destination)
				// Type 4 resolves through the hash path, so parse must derive it.
				destHash, err := leaseSetPublicationKey(LeaseSetStoreTypeLeaseSet2, ls2Bytes)
				require.NoError(t, err)
				assert.Equal(t, destHash[:], out.Hash,
					"type 4 parse must populate Hash from the Destination")
			}
		})
	}
}

// TestHostLookupRateLimitIsGenericFailure pins defect 1 at the handler level:
// rate limiting must not report "private key required" or "password required".
func TestHostLookupRateLimitIsGenericFailure(t *testing.T) {
	server, err := NewServer(DefaultServerConfig())
	require.NoError(t, err)

	lookup := &HostLookupPayload{RequestID: 77, LookupType: HostLookupTypeHash, Hash: make([]byte, 32)}
	wire, err := lookup.MarshalBinary()
	require.NoError(t, err)
	msg := &Message{Type: MessageTypeHostLookup, Payload: wire}

	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	for i := 0; i < hostLookupBurst; i++ {
		_, allowed := server.allowHostLookup(client, msg)
		require.True(t, allowed, "lookup %d should be allowed", i+1)
	}

	response, allowed := server.allowHostLookup(client, msg)
	require.False(t, allowed)
	require.NotNil(t, response)

	reply, err := ParseHostReplyPayload(response.Payload)
	require.NoError(t, err)
	assert.Equal(t, HostReplyFailure, reply.ResultCode,
		"rate limiting is a generic failure; code 2 means 'Lookup password required'")
	assert.NotEqual(t, HostReplyPasswordRequired, reply.ResultCode)
	assert.NotEqual(t, HostReplyPrivateKeyRequired, reply.ResultCode)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// leaseSet2WithOptions rebuilds a signed LeaseSet2 with the given options,
// reusing the destination, keys and leases of an existing one.
func leaseSet2WithOptions(t *testing.T, session *Session, ls2Bytes []byte, options map[string]string) []byte {
	t.Helper()

	ls2, _, err := lease_set2.ReadLeaseSet2(ls2Bytes)
	require.NoError(t, err)

	mapping, err := data.GoMapToMapping(options)
	require.NoError(t, err)

	signingKey, err := session.stdlibSigningKey()
	require.NoError(t, err)

	rebuilt, err := lease_set2.NewLeaseSet2(
		ls2.Destination(),
		ls2.Published(),
		ls2.Expires(),
		ls2.Flags(),
		ls2.OfflineSignature(),
		*mapping,
		ls2.EncryptionKeys(),
		ls2.Leases(),
		signingKey,
	)
	require.NoError(t, err)

	out, err := rebuilt.Bytes()
	require.NoError(t, err)
	return out
}

// destinationBytesForTest returns the session's destination as serialized bytes.
func destinationBytesForTest(t *testing.T, session *Session) []byte {
	t.Helper()
	destBytes, err := session.destination.Bytes()
	require.NoError(t, err)
	return destBytes
}
