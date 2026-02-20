package util

import (
	"os"
	"testing"
)

// =============================================================================
// Unit Tests for home.go — UserHome
// =============================================================================

// TestUserHomeReturnsValidPath verifies UserHome returns a non-empty, valid path.
func TestUserHomeReturnsValidPath(t *testing.T) {
	home := UserHome()
	if home == "" {
		t.Fatal("UserHome returned empty string")
	}

	// Verify the path exists
	info, err := os.Stat(home)
	if err != nil {
		t.Fatalf("UserHome returned non-existent path: %s, error: %v", home, err)
	}
	if !info.IsDir() {
		t.Fatalf("UserHome returned non-directory: %s", home)
	}
}
