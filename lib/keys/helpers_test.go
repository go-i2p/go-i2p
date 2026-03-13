package keys

import (
	"os"
	"runtime"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
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

// setupPermissionTest skips the test on Windows, creates a temp directory
// (cleaned up via t.Cleanup), and generates a fresh Ed25519 key pair.
func setupPermissionTest(t *testing.T, tempDirPrefix string) (string, types.PrivateKey) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file permission test on Windows")
	}
	tmpDir, err := os.MkdirTemp("", tempDirPrefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	_, privateKey, err := ed25519.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return tmpDir, privateKey
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
