package keys

import (
	"os"
	"testing"
)

// assertNotAllZeros fails the test if all bytes in data are zero.
func assertNotAllZeros(t testing.TB, data []byte, msg string) {
	t.Helper()
	for _, b := range data {
		if b != 0 {
			return
		}
	}
	t.Fatal(msg)
}

// assertAllZeros fails the test if any byte in data is non-zero.
func assertAllZeros(t testing.TB, data []byte, msg string) {
	t.Helper()
	for _, b := range data {
		if b != 0 {
			t.Error(msg)
			return
		}
	}
}

// assertKeyFilePermissions verifies that the file at path exists and has the expected permissions.
func assertKeyFilePermissions(t *testing.T, path string, expectedPerms os.FileMode) {
	t.Helper()
	fileInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		t.Errorf("Key file was not created at expected path: %s", path)
		return
	}
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}
	perm := fileInfo.Mode().Perm()
	if perm != expectedPerms {
		t.Errorf("Expected file permissions %o, got %o", expectedPerms, perm)
	}
}
