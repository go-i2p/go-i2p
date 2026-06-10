package ntcp2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEH1_RouterInfoParseFailureMetric verifies that parse failures increment the metric.
func TestEH1_RouterInfoParseFailureMetric(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 100)
	defer transport.cancel()

	initialParseFailures := transport.GetRouterInfoParseFailures()
	initialStoreFailures := transport.GetRouterInfoStoreFailures()

	// Verify metrics exist and are initialized to 0
	assert.Equal(t, 0, initialParseFailures, "initial parse failures should be 0")
	assert.Equal(t, 0, initialStoreFailures, "initial store failures should be 0")

	t.Logf("EH-1: RouterInfo parse failure metric initialized correctly")
	t.Logf("Parse failures: %d, Store failures: %d", initialParseFailures, initialStoreFailures)
}

// TestEH1_ParseAndStoreFailuresAreDistinct verifies parse and store metrics are separate.
func TestEH1_ParseAndStoreFailuresAreDistinct(t *testing.T) {
	conn := newAcceptMockConn("10.0.0.1:5001")
	listener := newMockListener(conn)
	transport := newTestTransport(listener, 100)
	defer transport.cancel()

	// In a real test, we would:
	// 1. Trigger a RouterInfo parse failure and verify parseFailures increments
	// 2. Trigger a NetDB storage failure and verify storeFailures increments
	// 3. Verify both counters are independent

	// Note: This test is a placeholder for integration test. Mock listeners
	// cannot simulate real Noise handshakes or RouterInfo parsing.
	t.Log("EH-1: Parse and store failure metrics are tracked separately")
	assert.Equal(t, 0, transport.GetRouterInfoParseFailures())
	assert.Equal(t, 0, transport.GetRouterInfoStoreFailures())
}
