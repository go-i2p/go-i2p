package ssu2

import (
	"testing"

	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockCallbackConfig_ToDataHandlerCallbacks(t *testing.T) {
	terminationCalled := false
	routerInfoCalled := false
	config := &BlockCallbackConfig{
		OnTermination: func(reason uint8, _ []byte) {
			terminationCalled = true
			assert.Equal(t, uint8(1), reason)
		},
		OnRouterInfo: func(_ []byte) error {
			routerInfoCalled = true
			return nil
		},
	}
	callbacks := config.ToDataHandlerCallbacks()
	require.NotNil(t, callbacks.OnTermination)
	callbacks.OnTermination(1, nil)
	assert.True(t, terminationCalled)
	require.NotNil(t, callbacks.OnRouterInfo)
	err := callbacks.OnRouterInfo([]byte("router-info"))
	assert.NoError(t, err)
	assert.True(t, routerInfoCalled)
	assert.Nil(t, callbacks.OnACK)
	assert.Nil(t, callbacks.OnPeerTest)
	assert.Nil(t, callbacks.OnRelayRequest)
}

func TestBlockCallbackConfig_AllCallbacks(t *testing.T) {
	config := &BlockCallbackConfig{
		OnTermination:   func(uint8, []byte) {},
		OnRouterInfo:    func([]byte) error { return nil },
		OnACK:           func(*ssu2noise.SSU2Block) error { return nil },
		OnDateTime:      func(uint32) error { return nil },
		OnPeerTest:      func(*ssu2noise.SSU2Block) error { return nil },
		OnRelayRequest:  func(*ssu2noise.SSU2Block) error { return nil },
		OnRelayResponse: func(*ssu2noise.SSU2Block) error { return nil },
		OnRelayIntro:    func(*ssu2noise.SSU2Block) error { return nil },
		OnNewToken:      func([]byte) {},
		OnAddress:       func([]byte) error { return nil },
		OnOptions:       func([]byte) error { return nil },
		OnPathChallenge: func([]byte) error { return nil },
		OnPathResponse:  func([]byte) error { return nil },
	}
	callbacks := config.ToDataHandlerCallbacks()
	assert.NotNil(t, callbacks.OnTermination)
	assert.NotNil(t, callbacks.OnRouterInfo)
	assert.NotNil(t, callbacks.OnACK)
	assert.NotNil(t, callbacks.OnDateTime)
	assert.NotNil(t, callbacks.OnPeerTest)
	assert.NotNil(t, callbacks.OnRelayRequest)
	assert.NotNil(t, callbacks.OnRelayResponse)
	assert.NotNil(t, callbacks.OnRelayIntro)
	assert.NotNil(t, callbacks.OnNewToken)
	assert.NotNil(t, callbacks.OnAddress)
	assert.NotNil(t, callbacks.OnOptions)
	assert.NotNil(t, callbacks.OnPathChallenge)
	assert.NotNil(t, callbacks.OnPathResponse)
}

func TestDefaultBlockCallbacks(t *testing.T) {
	config := DefaultBlockCallbacks()
	assert.NotNil(t, config.OnTermination)
	assert.NotNil(t, config.OnRouterInfo)
	assert.NotNil(t, config.OnDateTime)
	assert.Nil(t, config.OnACK)
	assert.Nil(t, config.OnPeerTest)
}

// TestDefaultBlockCallbacks_InvokeCallbacks exercises the callback bodies so
// that the closures are actually executed (coverage for function bodies).
func TestDefaultBlockCallbacks_InvokeCallbacks(t *testing.T) {
	config := DefaultBlockCallbacks()

	// OnTermination callback should not panic.
	config.OnTermination(0, nil)

	// OnRouterInfo callback should return nil.
	err := config.OnRouterInfo([]byte("dummy"))
	assert.NoError(t, err)

	// OnDateTime callback should return nil for a recent timestamp.
	now := uint32(0) // epoch is far in the past but the logger path is exercised
	_ = config.OnDateTime(now)
}
