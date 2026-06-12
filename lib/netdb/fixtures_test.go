package netdb

import "testing"

// newTestNetDB creates a temporary NetDB for testing purposes.
// It automatically creates the underlying directory structure and ensures the database is initialized.
// The temporary directory is automatically cleaned up when the test completes via t.TempDir().
func newTestNetDB(t *testing.T) *StdNetDB {
	tempDir := t.TempDir()
	db := NewStdNetDB(tempDir)
	if err := db.Create(); err != nil {
		t.Fatalf("Failed to create test NetDB: %v", err)
	}
	return db
}
