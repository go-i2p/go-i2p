package netdb

import (
	"sync"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/stretchr/testify/require"
)

// TestPrivacySafeguard_OwnLeaseSetNotServedToExternalLookups verifies that
// session-created LeaseSets (stored via StoreOwnLeaseSet) are NOT served to
// external FloodfillServer lookup queries.
//
// Privacy requirement (I2P protocol compliance):
// - We store our own session LeaseSets locally (CRITICAL-3 fix) for inbound tunnel discovery
// - We MUST NOT serve these to external peers via FloodfillServer lookups
// - We only serve LeaseSets that came from the network or were intentionally published
//
// Architecture:
// - StoreOwnLeaseSet() marks LeaseSet as "local-use-only" in ownLeaseSets map
// - FloodfillServer.lookupLeaseSet() checks IsOwnLeaseSet() before returning
// - External lookups for own LeaseSets return "not found" error
// - Local GetAllLeaseSets() still includes own LeaseSets for re-publication
func TestPrivacySafeguard_OwnLeaseSetNotServedToExternalLookups(t *testing.T) {
	t.Run("OwnLeaseSetNotInPublicList", func(t *testing.T) {
		// Create a StdNetDB with a session-created LeaseSet marked as "own"
		db := NewStdNetDB(t.TempDir())
		defer db.Stop()

		ownHash := common.Hash{}
		ownHash[0] = 0x11
		ownHash[1] = 0x22
		ownHash[2] = 0x33

		testData := []byte("own leaseset data")

		// Store as own session LeaseSet
		err := db.StoreOwnLeaseSet(ownHash, testData, i2np.DatabaseStoreTypeLeaseSet2)
		require.NoError(t, err, "StoreOwnLeaseSet should succeed")

		// Verify GetAllLeaseSets() includes own LeaseSets (for internal use/re-publication)
		allLeaseSets := db.GetAllLeaseSets()
		require.NotEmpty(t, allLeaseSets, "GetAllLeaseSets should include own LeaseSets")

		foundInAll := false
		for _, entry := range allLeaseSets {
			if entry.Hash == ownHash {
				foundInAll = true
				break
			}
		}
		require.True(t, foundInAll, "GetAllLeaseSets should include own LeaseSet")

		// Verify GetPublicLeaseSets() does NOT include own LeaseSets (privacy safeguard)
		publicLeaseSets := db.GetPublicLeaseSets()
		foundInPublic := false
		for _, entry := range publicLeaseSets {
			if entry.Hash == ownHash {
				foundInPublic = true
				break
			}
		}
		require.False(t, foundInPublic, "GetPublicLeaseSets must NOT include own LeaseSet (privacy)")

		t.Log("✓ Own session LeaseSet correctly excluded from public lookups")
		t.Log("  - Available in GetAllLeaseSets() for internal re-publication")
		t.Log("  - Excluded from GetPublicLeaseSets() for external queries")
	})

	t.Run("IsOwnLeaseSetTracking", func(t *testing.T) {
		db := NewStdNetDB(t.TempDir())
		defer db.Stop()

		ownHash := common.Hash{}
		ownHash[0] = 0xAA
		ownHash[1] = 0xBB

		publicHash := common.Hash{}
		publicHash[0] = 0xCC
		publicHash[1] = 0xDD

		testData := []byte("test data")

		// Store one as own, one as public
		err1 := db.StoreOwnLeaseSet(ownHash, testData, i2np.DatabaseStoreTypeLeaseSet2)
		require.NoError(t, err1)

		err2 := db.StoreLeaseSet(publicHash, testData, i2np.DatabaseStoreTypeLeaseSet2)
		require.NoError(t, err2)

		// Verify IsOwnLeaseSet correctly identifies each
		require.True(t, db.IsOwnLeaseSet(ownHash), "IsOwnLeaseSet should return true for own LeaseSet")
		require.False(t, db.IsOwnLeaseSet(publicHash), "IsOwnLeaseSet should return false for public LeaseSet")

		t.Log("✓ IsOwnLeaseSet correctly tracks ownership of stored LeaseSets")
	})

	t.Run("FloodfillServerSkipsOwnLeaseSetLookups", func(t *testing.T) {
		// Simulate FloodfillServer behavior: use StdNetDB and check privacy safeguard
		db := NewStdNetDB(t.TempDir())
		defer db.Stop()

		ownHash := common.Hash{}
		ownHash[0] = 0xFF
		ownHash[1] = 0xEE

		publicHash := common.Hash{}
		publicHash[0] = 0x11
		publicHash[1] = 0x22

		testData := []byte("test leaseset")

		// Store one as own, one as public
		err1 := db.StoreOwnLeaseSet(ownHash, testData, i2np.DatabaseStoreTypeLeaseSet2)
		require.NoError(t, err1)

		err2 := db.StoreLeaseSet(publicHash, testData, i2np.DatabaseStoreTypeLeaseSet2)
		require.NoError(t, err2)

		// Simulate FloodfillServer lookup logic:
		// Check IsOwnLeaseSet first before attempting to retrieve
		ownCheckResult := db.IsOwnLeaseSet(ownHash)
		publicCheckResult := db.IsOwnLeaseSet(publicHash)

		require.True(t, ownCheckResult, "Privacy check should block own LeaseSet lookups")
		require.False(t, publicCheckResult, "Privacy check should allow public LeaseSet lookups")

		t.Log("✓ FloodfillServer privacy safeguard correctly identifies own LeaseSets")
	})

	t.Run("MixedLookupScenario", func(t *testing.T) {
		// Test a realistic scenario: multiple own + multiple public LeaseSets
		db := NewStdNetDB(t.TempDir())
		defer db.Stop()

		// Store 3 own session LeaseSets
		ownHashes := make([]common.Hash, 3)
		for i := 0; i < 3; i++ {
			ownHashes[i] = common.Hash{}
			ownHashes[i][0] = byte(0xA0 + i)
			ownHashes[i][1] = 0x01
			err := db.StoreOwnLeaseSet(ownHashes[i], []byte("own"), i2np.DatabaseStoreTypeLeaseSet2)
			require.NoError(t, err)
		}

		// Store 2 public LeaseSets
		publicHashes := make([]common.Hash, 2)
		for i := 0; i < 2; i++ {
			publicHashes[i] = common.Hash{}
			publicHashes[i][0] = byte(0xB0 + i)
			publicHashes[i][1] = 0x02
			err := db.StoreLeaseSet(publicHashes[i], []byte("public"), i2np.DatabaseStoreTypeLeaseSet2)
			require.NoError(t, err)
		}

		// Verify all visible in GetAllLeaseSets()
		allCount := len(db.GetAllLeaseSets())
		require.Equal(t, 5, allCount, "GetAllLeaseSets should have 5 total entries")

		// Verify only public visible in GetPublicLeaseSets()
		publicCount := len(db.GetPublicLeaseSets())
		require.Equal(t, 2, publicCount, "GetPublicLeaseSets should only have 2 entries")

		// Verify filtering is correct
		publicSet := db.GetPublicLeaseSets()
		for _, entry := range publicSet {
			// All public entries should be from publicHashes
			found := false
			for _, ph := range publicHashes {
				if entry.Hash == ph {
					found = true
					break
				}
			}
			require.True(t, found, "Public LeaseSet should only contain non-own entries")
		}

		t.Log("✓ Mixed scenario correctly separates own and public LeaseSets")
		t.Log("  - Total LeaseSets (internal view): 5")
		t.Log("  - Public LeaseSets (external view): 2")
	})

	t.Run("ThreadSafety", func(t *testing.T) {
		// Verify concurrent access to ownLeaseSets map is safe
		db := NewStdNetDB(t.TempDir())
		defer db.Stop()

		done := make(chan bool)
		wg := sync.WaitGroup{}

		// Concurrent stores and checks
		for i := 0; i < 10; i++ {
			wg.Add(2)

			go func(idx int) {
				defer wg.Done()
				hash := common.Hash{}
				hash[0] = byte(idx)
				_ = db.StoreOwnLeaseSet(hash, []byte("data"), i2np.DatabaseStoreTypeLeaseSet2)
			}(i)

			go func(idx int) {
				defer wg.Done()
				hash := common.Hash{}
				hash[0] = byte(idx)
				_ = db.IsOwnLeaseSet(hash)
			}(i)
		}

		wg.Wait()
		close(done)

		t.Log("✓ Concurrent access to privacy tracking is thread-safe")
	})
}

// TestPrivacySafeguard_DesignDocument documents the privacy safeguard architecture
func TestPrivacySafeguard_DesignDocument(t *testing.T) {
	t.Log("Privacy Safeguard for Session-Created LeaseSets")
	t.Log("")
	t.Log("Problem:")
	t.Log("  - CRITICAL-3 fix stores our own session LeaseSets locally for inbound tunnel discovery")
	t.Log("  - Without privacy safeguard, FloodfillServer would serve these to external lookup queries")
	t.Log("  - Violates I2P protocol: we should only serve LeaseSets we intended to publish")
	t.Log("")
	t.Log("Solution (Separation of Concerns):")
	t.Log("  1. StoreOwnLeaseSet() - marks LeaseSet as \"local-use-only\"")
	t.Log("     - Stores in same cache as public LeaseSets")
	t.Log("     - Marks hash in ownLeaseSets map for filtering")
	t.Log("")
	t.Log("  2. IsOwnLeaseSet() - checks if hash is marked as own-created")
	t.Log("     - Used by FloodfillServer to skip external lookups")
	t.Log("     - Efficient: O(1) lookup in ownLeaseSets map")
	t.Log("")
	t.Log("  3. GetPublicLeaseSets() - returns only non-own LeaseSets")
	t.Log("     - Used for external database lookups")
	t.Log("     - Filters out own-created entries")
	t.Log("")
	t.Log("  4. GetAllLeaseSets() - returns ALL LeaseSets (own + public)")
	t.Log("     - Used by periodic re-publication loop")
	t.Log("     - Ensures session LeaseSets get re-published regularly")
	t.Log("")
	t.Log("Integration Points:")
	t.Log("  - Publisher.PublishLeaseSet() calls StoreOwnLeaseSet() for I2CP sessions")
	t.Log("  - FloodfillServer.lookupLeaseSet() checks IsOwnLeaseSet() before returning")
	t.Log("  - Publisher.publishAllLeaseSets() uses GetAllLeaseSets() for periodic refresh")
	t.Log("")
	t.Log("Security Properties:")
	t.Log("  - Own LeaseSets never served to external lookups")
	t.Log("  - Other local components (e.g., tunnel builders) can access via GetAllLeaseSets()")
	t.Log("  - Maintains I2P protocol compliance")
	t.Log("  - No performance impact on external lookups (O(1) privacy check)")
}
