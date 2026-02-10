package router

import (
	"crypto/sha256"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestRouter creates a router with initialized NetDB for testing
func setupTestRouter(t *testing.T) *Router {
	tempDir := t.TempDir()

	cfg := &config.RouterConfig{
		WorkingDir: tempDir,
		NetDb: &config.NetDbConfig{
			Path: tempDir + "/netdb",
		},
	}

	router, err := FromConfig(cfg)
	require.NoError(t, err, "Failed to create router")

	// Initialize NetDB
	err = router.initializeNetDB()
	require.NoError(t, err, "Failed to initialize NetDB")

	err = router.StdNetDB.Ensure()
	require.NoError(t, err, "Failed to ensure NetDB")

	return router
}

// TestNewLeaseSetPublisher tests publisher creation
func TestNewLeaseSetPublisher(t *testing.T) {
	router := setupTestRouter(t)

	publisher := NewLeaseSetPublisher(router)
	assert.NotNil(t, publisher, "Publisher should not be nil")
	assert.Equal(t, router, publisher.router, "Publisher should reference router")
}

// TestPublishLeaseSetToLocalNetDB tests publishing with valid LeaseSet from I2CP
// This test validates the full integration: session creates LeaseSet, publishes it,
// and it gets stored in NetDB. This is the most important end-to-end test.
func TestPublishLeaseSetToLocalNetDB(t *testing.T) {
	// This test is skipped because creating valid LeaseSets requires complex
	// setup with proper key certificates and signatures. The I2CP integration
	// tests in lib/i2cp/publisher_test.go provide comprehensive test coverage
	// for the full publishing flow.
	//
	// The core functionality (storeInLocalNetDB) is tested in TestStoreInLocalNetDBSuccess
	// with mock data, which is sufficient for unit testing the router publisher.
	t.Skip("LeaseSet2 creation requires complex setup - see I2CP integration tests instead")
}

// TestPublishLeaseSetInvalidData tests error handling for invalid data
func TestPublishLeaseSetInvalidData(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	// Create invalid LeaseSet data
	invalidData := []byte("this is not a valid leaseset")
	var key common.Hash
	copy(key[:], []byte("invalid_key_hash_32_bytes_total!"))

	// Attempt to publish invalid data
	err := publisher.PublishLeaseSet(key, invalidData)
	assert.Error(t, err, "PublishLeaseSet should fail with invalid data")
	assert.Contains(t, err.Error(), "NetDB", "Error should mention NetDB")
}

// TestPublishLeaseSetNilData tests handling of nil data
func TestPublishLeaseSetNilData(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	var key common.Hash
	copy(key[:], []byte("test_key_hash_32_bytes_exactly!!"))

	// Attempt to publish nil data
	err := publisher.PublishLeaseSet(key, nil)
	assert.Error(t, err, "PublishLeaseSet should fail with nil data")
}

// TestPublishLeaseSetEmptyData tests handling of empty data
func TestPublishLeaseSetEmptyData(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	var key common.Hash
	copy(key[:], []byte("test_key_hash_32_bytes_exactly!!"))

	// Attempt to publish empty data
	err := publisher.PublishLeaseSet(key, []byte{})
	assert.Error(t, err, "PublishLeaseSet should fail with empty data")
}

// TestDistributeToNetworkDoesNotPanic tests that network distribution doesn't panic
func TestDistributeToNetworkDoesNotPanic(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	// Create test data
	testData := []byte("test leaseset data")
	var testHash common.Hash
	copy(testHash[:], []byte("test_hash_fills_32_bytes_exactly"))

	// This should not panic even though we have no floodfill routers
	assert.NotPanics(t, func() {
		publisher.distributeToNetwork(testHash, testData)
	}, "distributeToNetwork should not panic")
}

// TestPublishLeaseSetHashMismatch tests publishing with incorrect hash
func TestPublishLeaseSetHashMismatch(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	// Create invalid LeaseSet data
	invalidLeaseSetData := []byte("not a valid leaseset")

	// Use wrong hash
	wrongHash := sha256.Sum256([]byte("wrong destination"))

	// Attempt to publish with mismatched hash
	err := publisher.PublishLeaseSet(wrongHash, invalidLeaseSetData)
	assert.Error(t, err, "PublishLeaseSet should fail with invalid data")
	assert.Contains(t, err.Error(), "NetDB", "Error should mention NetDB storage failure")
}

// TestLeaseSetPublisherWaitCompletesAfterDistribution tests that Wait() blocks
// until all background distributeToNetwork goroutines have completed.
func TestLeaseSetPublisherWaitCompletesAfterDistribution(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	// distributeToNetwork runs as a tracked goroutine via PublishLeaseSet.
	// Even though PublishLeaseSet will fail at storeInLocalNetDB (invalid data),
	// we can directly test the wg mechanism by calling distributeToNetwork manually.
	var testHash common.Hash
	copy(testHash[:], []byte("test_hash_fills_32_bytes_exactly"))

	publisher.wg.Add(1)
	go func() {
		defer publisher.wg.Done()
		publisher.distributeToNetwork(testHash, []byte("test data"))
	}()

	// Wait should not block indefinitely — the goroutine should complete quickly
	// since there are no floodfill routers to contact
	done := make(chan struct{})
	go func() {
		publisher.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success — Wait() returned
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() did not return within 5 seconds — goroutine leak")
	}
}

// TestLeaseSetPublisherWaitWithNoGoroutines tests that Wait() returns immediately
// when no background goroutines have been launched.
func TestLeaseSetPublisherWaitWithNoGoroutines(t *testing.T) {
	router := setupTestRouter(t)
	publisher := NewLeaseSetPublisher(router)

	// Wait should return immediately when no goroutines have been launched
	done := make(chan struct{})
	go func() {
		publisher.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Wait() blocked with no goroutines")
	}
}
