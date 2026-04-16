package ssu2

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPersistentConfig_DirectoryPermissions asserts the SSU2 persistent
// config directory is created with 0o700. See AUDIT.md MEDIUM —
// "Transport working directory is created with mode 0o755..." (2026-04-16).
func TestPersistentConfig_DirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not enforced on Windows")
	}
	dir := filepath.Join(t.TempDir(), "ssu2-working")
	pc := NewPersistentConfig(dir)
	if _, err := pc.LoadOrGenerateObfuscationIV(); err != nil {
		t.Fatalf("LoadOrGenerateObfuscationIV: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat working dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("expected dir mode 0o700, got %#o", perm)
	}
}
