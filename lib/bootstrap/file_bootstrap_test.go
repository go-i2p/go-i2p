package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileBootstrap_ValidateFile(t *testing.T) {
	t.Run("NonExistentFile", func(t *testing.T) {
		fb := NewFileBootstrap("/nonexistent/path/to/file.su3")
		err := fb.validateFile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("DirectoryInsteadOfFile", func(t *testing.T) {
		// Create a temporary directory
		tmpDir := t.TempDir()

		fb := NewFileBootstrap(tmpDir)
		err := fb.validateFile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is a directory")
	})

	t.Run("ValidFile", func(t *testing.T) {
		// Create a temporary file with sufficient size (100+ bytes)
		tmpFile := filepath.Join(t.TempDir(), "test.su3")
		// Create content that's at least 100 bytes
		content := make([]byte, 100)
		for i := range content {
			content[i] = byte('A' + (i % 26))
		}
		err := os.WriteFile(tmpFile, content, 0o644)
		require.NoError(t, err)

		fb := NewFileBootstrap(tmpFile)
		err = fb.validateFile()
		assert.NoError(t, err)
	})
}

func TestFileBootstrap_GetPeers_UnsupportedFileType(t *testing.T) {
	// Create a temporary file with unsupported extension and sufficient size
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	// Create content that's at least 100 bytes
	content := make([]byte, 100)
	for i := range content {
		content[i] = byte('A' + (i % 26))
	}
	err := os.WriteFile(tmpFile, content, 0o644)
	require.NoError(t, err)

	fb := NewFileBootstrap(tmpFile)
	ctx := context.Background()

	peers, err := fb.GetPeers(ctx, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported file type")
	assert.Nil(t, peers)
}

func TestFileBootstrap_GetPeers_ContextCanceled(t *testing.T) {
	// Create a temporary file with sufficient size
	tmpFile := filepath.Join(t.TempDir(), "test.su3")
	// Create content that's at least 100 bytes
	content := make([]byte, 100)
	for i := range content {
		content[i] = byte('A' + (i % 26))
	}
	err := os.WriteFile(tmpFile, content, 0o644)
	require.NoError(t, err)

	fb := NewFileBootstrap(tmpFile)

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	peers, err := fb.GetPeers(ctx, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "canceled")
	assert.Nil(t, peers)
}

func TestFileBootstrap_GetPeers_NonExistentFile(t *testing.T) {
	fb := NewFileBootstrap("/nonexistent/path/to/file.su3")
	ctx := context.Background()

	peers, err := fb.GetPeers(ctx, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	assert.Nil(t, peers)
}

func TestNewFileBootstrap(t *testing.T) {
	testPath := "/path/to/reseed.su3"
	fb := NewFileBootstrap(testPath)

	assert.NotNil(t, fb)
	assert.Equal(t, testPath, fb.filePath)
}

// Note: Full integration tests with actual SU3/ZIP files would require:
// 1. Sample reseed files (which are large and should not be in the repo)
// 2. Valid RouterInfo data structures
// 3. SU3 signature verification setup
// These tests focus on the bootstrap logic, file validation, and error handling.
// The actual SU3/ZIP processing is tested through the reseed package.
