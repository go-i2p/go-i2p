package keys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	data := []byte("secret-key-material")

	if err := atomicWriteFile(path, data, 0o600); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestAtomicWriteFileOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	if err := atomicWriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := atomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("got %q, want %q", got, "new")
	}
}

func TestAtomicWriteFileNoTempLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	if err := atomicWriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "test.key" {
			t.Errorf("unexpected file left behind: %s", e.Name())
		}
	}
}

func TestAtomicWriteFileBadDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent", "sub", "test.key")
	err := atomicWriteFile(path, []byte("data"), 0o600)
	if err == nil {
		t.Error("expected error for nonexistent directory, got nil")
	}
}
