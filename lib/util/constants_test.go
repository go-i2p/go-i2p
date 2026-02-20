package util

import "strings"

// =============================================================================
// Shared Test Constants and Fixtures
// =============================================================================

// nonExistentFilePath is a path guaranteed not to exist on the filesystem,
// used across multiple test functions for negative-case testing.
const nonExistentFilePath = "/tmp/definitely_does_not_exist_12345_abcde.txt"

// pathTraversalTestCases contains paths that exercise directory traversal,
// absolute path injection, empty string, and excessively long path scenarios.
// Used in validation tests to ensure functions handle malformed input safely.
var pathTraversalTestCases = []string{
	"../../../etc/passwd",
	"..\\..\\windows\\system32",
	"/etc/passwd",
	"",
	strings.Repeat("a", 10000), // Very long path
}
