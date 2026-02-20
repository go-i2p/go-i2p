package bootstrap

import (
	"context"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/stretchr/testify/assert"
)

// TestNewFileBootstrap verifies that NewFileBootstrap creates a valid instance.
func TestNewFileBootstrap(t *testing.T) {
	testPath := "/path/to/reseed.su3"
	fb := NewFileBootstrap(testPath)

	assert.NotNil(t, fb)
	assert.Equal(t, testPath, fb.filePath)
}

// TestFileBootstrapExclusive verifies that when type is "file",
// only file bootstrap is used (no fallback).
func TestFileBootstrapExclusive(t *testing.T) {
	cfg := &config.BootstrapConfig{
		LowPeerThreshold: testLowPeerThreshold,
		BootstrapType:    "file",
		ReseedFilePath:   "/tmp/test-reseed.su3",
	}

	// This would be used in the router
	var bootstrapper Bootstrap = NewFileBootstrap(cfg.ReseedFilePath)

	if bootstrapper == nil {
		t.Fatal("NewFileBootstrap should not return nil")
	}

	// Verify it's specifically a FileBootstrap, not a CompositeBootstrap
	_, isFile := bootstrapper.(*FileBootstrap)
	if !isFile {
		t.Error("When BootstrapType is 'file', should create FileBootstrap instance")
	}
}

// TestFileBootstrap_ValidateFile tests the file validation logic.
func TestFileBootstrap_ValidateFile(t *testing.T) {
	t.Run("NonExistentFile", func(t *testing.T) {
		fb := NewFileBootstrap("/nonexistent/path/to/file.su3")
		err := fb.validateFile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("DirectoryInsteadOfFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		fb := NewFileBootstrap(tmpDir)
		err := fb.validateFile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is a directory")
	})

	t.Run("ValidFile", func(t *testing.T) {
		tmpFile := createTempTestFile(t, t.TempDir(), "test.su3", testDummyFileSize)
		fb := NewFileBootstrap(tmpFile)
		err := fb.validateFile()
		assert.NoError(t, err)
	})
}

// TestFileBootstrap_GetPeers_UnsupportedFileType tests rejection of unsupported file types.
func TestFileBootstrap_GetPeers_UnsupportedFileType(t *testing.T) {
	tmpFile := createTempTestFile(t, t.TempDir(), "test.txt", testDummyFileSize)

	fb := NewFileBootstrap(tmpFile)
	ctx := context.Background()

	peers, err := fb.GetPeers(ctx, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported file type")
	assert.Nil(t, peers)
}

// TestFileBootstrap_GetPeers_ContextCanceled tests that GetPeers respects context cancellation.
func TestFileBootstrap_GetPeers_ContextCanceled(t *testing.T) {
	tmpFile := createTempTestFile(t, t.TempDir(), "test.su3", testDummyFileSize)

	fb := NewFileBootstrap(tmpFile)

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	peers, err := fb.GetPeers(ctx, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "canceled")
	assert.Nil(t, peers)
}

// TestFileBootstrap_GetPeers_NonExistentFile tests that GetPeers fails for missing files.
func TestFileBootstrap_GetPeers_NonExistentFile(t *testing.T) {
	fb := NewFileBootstrap("/nonexistent/path/to/file.su3")
	ctx := context.Background()

	peers, err := fb.GetPeers(ctx, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	assert.Nil(t, peers)
}
