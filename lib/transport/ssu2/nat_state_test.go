package ssu2

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNatState_SetAndGet(t *testing.T) {
	ns := &natState{}
	ns.set(ssu2noise.NATCone, "1.2.3.4:5678")

	natType, valid := ns.get()
	assert.True(t, valid)
	assert.Equal(t, ssu2noise.NATCone, natType)
}

func TestNatState_GetExpired(t *testing.T) {
	ns := &natState{}
	ns.set(ssu2noise.NATSymmetric, "10.0.0.1:9000")

	// Manually force expiry by backdating the timestamp.
	ns.mu.Lock()
	ns.updated = time.Now().Add(-natResultTTL - time.Second)
	ns.mu.Unlock()

	natType, valid := ns.get()
	assert.False(t, valid)
	assert.Equal(t, ssu2noise.NATUnknown, natType)
}

func TestNatState_GetEmpty(t *testing.T) {
	ns := &natState{}
	natType, valid := ns.get()
	assert.False(t, valid)
	assert.Equal(t, ssu2noise.NATUnknown, natType)
}

func TestSaveAndLoadNATState(t *testing.T) {
	dir := t.TempDir()
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}

	// Set and save.
	tr.natStateCache.set(ssu2noise.NATRestricted, "5.6.7.8:1234")
	tr.saveNATState()

	// Verify file exists.
	path := filepath.Join(dir, natStateFilename)
	_, err := os.Stat(path)
	require.NoError(t, err)

	// Load into a fresh transport.
	tr2 := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	loaded := tr2.loadNATState()
	assert.True(t, loaded)

	natType, valid := tr2.natStateCache.get()
	assert.True(t, valid)
	assert.Equal(t, ssu2noise.NATRestricted, natType)
}

func TestLoadNATState_Expired(t *testing.T) {
	dir := t.TempDir()
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}

	// Set, backdate, and save.
	tr.natStateCache.set(ssu2noise.NATCone, "1.1.1.1:80")
	tr.natStateCache.mu.Lock()
	tr.natStateCache.updated = time.Now().Add(-natResultTTL - time.Minute)
	tr.natStateCache.mu.Unlock()
	tr.saveNATState()

	// Loading should reject the stale data.
	tr2 := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr2.loadNATState())
}

func TestLoadNATState_NoWorkingDir(t *testing.T) {
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: ""},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr.loadNATState())
}

func TestLoadNATState_MissingFile(t *testing.T) {
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: t.TempDir()},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr.loadNATState())
}

func TestSaveNATState_NoWorkingDir(t *testing.T) {
	tr := &SSU2Transport{
		config:        &Config{WorkingDir: ""},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	// Should be a no-op, not panic.
	tr.saveNATState()
}

func TestLoadNATState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, natStateFilename)
	require.NoError(t, os.WriteFile(path, []byte("{invalid json"), 0o600))

	tr := &SSU2Transport{
		config:        &Config{WorkingDir: dir},
		natStateCache: &natState{},
		logger:        testLogger(),
	}
	assert.False(t, tr.loadNATState())
}

func testLogger() *logger.Entry {
	return logger.WithField("test", "nat_state")
}
