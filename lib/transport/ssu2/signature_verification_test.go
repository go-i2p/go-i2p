package ssu2

import (
	"crypto/ed25519"
	"net"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/stretchr/testify/assert"
)

// TestVerifyRelayRequestSignature_MissingRouterLookupFunc verifies that
// verification gracefully skips when RouterLookupFunc is unavailable.
func TestVerifyRelayRequestSignature_MissingRouterLookupFunc(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.RouterLookupFunc = nil

	block := &ssu2noise.RelayRequestBlock{
		Nonce:     12345,
		RelayTag:  1,
		Timestamp: 1234567890,
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.ParseIP("192.0.2.1"),
		Signature: make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	valid, err := tr.verifyRelayRequestSignature(block, senderHash)

	assert.NoError(t, err, "should not error when RouterLookupFunc is nil")
	assert.False(t, valid, "should return false when RouterLookupFunc is nil")
}

// TestVerifyRelayRequestSignature_RouterInfoLookupFails verifies that
// verification fails closed when NetDB lookup fails.
func TestVerifyRelayRequestSignature_RouterInfoLookupFails(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}

	block := &ssu2noise.RelayRequestBlock{
		Nonce:     12345,
		RelayTag:  1,
		Timestamp: 1234567890,
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.ParseIP("192.0.2.1"),
		Signature: make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	valid, err := tr.verifyRelayRequestSignature(block, senderHash)

	assert.Error(t, err, "should error when NetDB lookup fails")
	assert.False(t, valid, "should return false when NetDB lookup fails")
}

// TestVerifyPeerTestSignature_MissingRouterLookupFunc verifies that
// verification gracefully skips when RouterLookupFunc is unavailable.
func TestVerifyPeerTestSignature_MissingRouterLookupFunc(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.RouterLookupFunc = nil

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		AlicePort:   9000,
		AliceIP:     net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	valid, err := tr.verifyPeerTestSignature(block, senderHash)

	assert.NoError(t, err, "should not error when RouterLookupFunc is nil")
	assert.False(t, valid, "should return false when RouterLookupFunc is nil")
}

// TestVerifyPeerTestSignature_RouterInfoLookupFails verifies that
// verification fails closed when NetDB lookup fails.
func TestVerifyPeerTestSignature_RouterInfoLookupFails(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestRequest,
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		AlicePort:   9000,
		AliceIP:     net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	valid, err := tr.verifyPeerTestSignature(block, senderHash)

	assert.Error(t, err, "should error when NetDB lookup fails")
	assert.False(t, valid, "should return false when NetDB lookup fails")
}

// TestVerifyRelayResponseSignature_MissingRouterLookupFunc verifies that
// verification gracefully skips when RouterLookupFunc is unavailable.
func TestVerifyRelayResponseSignature_MissingRouterLookupFunc(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.RouterLookupFunc = nil

	block := &ssu2noise.RelayResponseBlock{
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	valid, err := tr.verifyRelayResponseSignature(block, senderHash)

	assert.NoError(t, err, "should not error when RouterLookupFunc is nil")
	assert.False(t, valid, "should return false when RouterLookupFunc is nil")
}

// TestVerifyRelayResponseSignature_RouterInfoLookupFails verifies that
// verification fails closed when NetDB lookup fails.
func TestVerifyRelayResponseSignature_RouterInfoLookupFails(t *testing.T) {
	tr := makeMinimalTransport()
	tr.config.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}

	block := &ssu2noise.RelayResponseBlock{
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	valid, err := tr.verifyRelayResponseSignature(block, senderHash)

	assert.Error(t, err, "should error when NetDB lookup fails")
	assert.False(t, valid, "should return false when NetDB lookup fails")
}

// TestExtractSenderHash_NilSession verifies graceful handling of nil session.
func TestExtractSenderHash_NilSession(t *testing.T) {
	hash := extractSenderHash(nil)
	assert.Equal(t, data.Hash{}, hash, "should return zero hash for nil session")
}
