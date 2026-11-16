package netdb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewStdNetDBWithExpirationCheck_StoresInterval is the C1 guard for
// netdb.expiration_check_interval: the operator's cadence must reach the
// StdNetDB that runs the expiration cleaner. Before this fix the cleaner always
// used the hardcoded leaseSetCleanupInterval and the knob was dead. The interval
// is a constructor parameter (not a setter) because the cleaner's ticker is
// created once at startup, so this test pins that the constructor records it.
func TestNewStdNetDBWithExpirationCheck_StoresInterval(t *testing.T) {
	db := NewStdNetDBWithExpirationCheck(t.TempDir(), 90*time.Second)
	defer db.Stop()

	assert.Equal(t, 90*time.Second, db.expirationCheckInterval,
		"expiration_check_interval must be recorded so the cleaner ticker uses it")
}

// TestNewStdNetDB_DefaultExpirationCheck pins that the plain constructor leaves
// the interval zero, which StartExpirationCleaner resolves to the built-in
// leaseSetCleanupInterval (no behavior change for callers that pass no config).
func TestNewStdNetDB_DefaultExpirationCheck(t *testing.T) {
	db := NewStdNetDB(t.TempDir())
	defer db.Stop()

	assert.Zero(t, db.expirationCheckInterval,
		"default constructor must leave the interval zero so the built-in default applies")
}
