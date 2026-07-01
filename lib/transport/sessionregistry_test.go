package transport

import (
	"errors"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionRegistry_Promote_PreflightFailureRollsBack(t *testing.T) {
	registry := NewSessionRegistry(log.WithField("test", t.Name()))

	var peerHash data.Hash
	peerHash[0] = 1

	original := &struct{ id string }{id: "raw-conn"}
	promoted := &struct{ id string }{id: "session"}
	registry.StoreWithCount(peerHash, original)

	callbackSet := false
	workersStarted := false

	result, ok := registry.Promote(peerHash, original, promoted, PromoteOptions{
		PreflightCheck: func() error {
			return errors.New("invariant violation")
		},
		SetCallback: func(callback func()) {
			callbackSet = true
		},
		StartWorkers: func() {
			workersStarted = true
		},
	})

	assert.False(t, ok)
	assert.Nil(t, result)
	assert.False(t, callbackSet, "cleanup callback must not be installed when preflight fails")
	assert.False(t, workersStarted, "workers must not start when preflight fails")

	current, exists := registry.Load(peerHash)
	require.True(t, exists, "entry should remain present after rollback")
	assert.Same(t, original, current, "registry entry must be rolled back to original owner")
	assert.Equal(t, int32(1), registry.Count(), "session count should not change on failed promotion")
}

func TestSessionRegistry_Promote_PreflightFailureIsFatal(t *testing.T) {
	registry := NewSessionRegistry(log.WithField("test", t.Name()))

	var peerHash data.Hash
	peerHash[0] = 2

	original := &struct{ id string }{id: "raw-conn"}
	promoted := &struct{ id string }{id: "session"}
	registry.StoreWithCount(peerHash, original)

	callbackSet := false
	workersStarted := false

	result, ok := registry.Promote(peerHash, original, promoted, PromoteOptions{
		PreflightCheck: func() error {
			registry.Delete(peerHash)
			return errors.New("forced failure")
		},
		SetCallback: func(callback func()) {
			callbackSet = true
		},
		StartWorkers: func() {
			workersStarted = true
		},
	})

	assert.False(t, ok)
	assert.Nil(t, result)
	assert.False(t, callbackSet, "cleanup callback must not be installed when preflight fails")
	assert.False(t, workersStarted, "workers must not start when preflight fails")

	_, exists := registry.Load(peerHash)
	assert.False(t, exists, "entry should remain absent after fatal preflight path")
}
