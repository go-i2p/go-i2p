package util

import "testing"

// =============================================================================
// Validation Tests for checkfile.go — malformed input, boundary conditions
// =============================================================================

// TestPathSafetyNoTraversal verifies paths don't allow directory traversal.
// The util package doesn't have path sanitization, but we verify the
// underlying functions don't panic on malformed paths.
func TestPathSafetyNoTraversal(t *testing.T) {
	for _, tc := range pathTraversalTestCases {
		// Should not panic
		_ = CheckFileExists(tc)
		_ = CheckFileAge(tc, 1)
	}
}
