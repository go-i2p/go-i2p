// Regression tests for I2P-D-2: a Kademlia DatabaseLookup answered with a
// RouterInfo whose key is NOT the requested target (a "foreign" record) must be
// stored for NetDB growth but must NOT be mistaken for the resolved target.
//
// Before the fix, parseDatabaseStore rejected any key mismatch outright, so the
// valid foreign RouterInfo was discarded entirely — silently degrading DHT
// replication on the route that answered opportunistically.

package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDatabaseStoreForRI serializes ri into a DatabaseStore message keyed by
// storeKey, with the gzip+length-prefixed RouterInfo payload the resolver expects.
func buildDatabaseStoreForRI(t *testing.T, storeKey common.Hash, riBytes []byte) []byte {
	t.Helper()
	payload, err := i2np.BuildRouterInfoStorePayload(riBytes)
	require.NoError(t, err)
	store := i2np.NewDatabaseStore(storeKey, payload, i2np.DatabaseStoreTypeRouterInfo)
	// The resolver parses the DatabaseStore payload (key+type+replyToken+data),
	// not the full I2NP-framed message, so marshal the payload form.
	data, err := store.MarshalPayload()
	require.NoError(t, err)
	return data
}

// TestProcessDatabaseStoreResponse_ForeignRIStoredNotTreatedAsTarget proves the
// I2P-D-2 fix: a DatabaseStore whose key differs from the lookup target is
// stored (NetDB growth) but returned as (nil, nil) so the iterative lookup keeps
// walking toward the real target instead of terminating on the wrong record.
func TestProcessDatabaseStoreResponse_ForeignRIStoredNotTreatedAsTarget(t *testing.T) {
	ri := createValidRouterInfo(t)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)

	riHash, err := ri.IdentHash()
	require.NoError(t, err)

	// A target hash that is NOT the RI's own hash: the peer answered with a
	// foreign record.
	targetHash := common.Hash{0xAA, 0xBB, 0xCC, 0xDD}
	require.NotEqual(t, riHash, targetHash, "test setup: foreign key must differ from target")

	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	data := buildDatabaseStoreForRI(t, riHash, riBytes)

	got, err := resolver.processDatabaseStoreResponse(data, targetHash)
	require.NoError(t, err, "a foreign RI is a valid record, not an error")
	assert.Nil(t, got, "a foreign RI must not be returned as the resolved target (I2P-D-2)")

	// The foreign RI must still be stored so NetDB grows and replication works.
	require.Len(t, mockDB.storedRIs, 1, "the foreign RouterInfo must be stored (I2P-D-2)")
	storedHash, err := mockDB.storedRIs[0].IdentHash()
	require.NoError(t, err)
	assert.Equal(t, riHash.String(), storedHash.String(), "the stored RI must be the foreign record we received")
}

// TestProcessDatabaseStoreResponse_MatchingRIIsTarget is the positive control:
// when the DatabaseStore key equals the target, the RI is returned as resolved
// and stored.
func TestProcessDatabaseStoreResponse_MatchingRIIsTarget(t *testing.T) {
	ri := createValidRouterInfo(t)
	riBytes, err := ri.Bytes()
	require.NoError(t, err)

	riHash, err := ri.IdentHash()
	require.NoError(t, err)

	mockDB := newMockNetworkDatabase()
	resolver := &KademliaResolver{
		NetworkDatabase: mockDB,
		responseHandler: NewLookupResponseHandler(),
	}

	data := buildDatabaseStoreForRI(t, riHash, riBytes)

	got, err := resolver.processDatabaseStoreResponse(data, riHash)
	require.NoError(t, err)
	require.NotNil(t, got, "a matching RI must be returned as the resolved target")
	gotHash, err := got.IdentHash()
	require.NoError(t, err)
	assert.Equal(t, riHash.String(), gotHash.String())
	assert.Len(t, mockDB.storedRIs, 1, "the matching RI must also be stored")
}
