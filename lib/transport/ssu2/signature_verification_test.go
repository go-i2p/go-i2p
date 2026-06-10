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
// verification fails closed (returns error) when RouterLookupFunc is unavailable.
func TestVerifyRelayRequestSignature_MissingRouterLookupFunc(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = nil
	tr.config.Store(cfg)

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

	assert.Error(t, err, "should error when RouterLookupFunc is nil (fail-closed)")
	assert.False(t, valid, "should return false when RouterLookupFunc is nil")
}

// TestVerifyRelayRequestSignature_RouterInfoLookupFails verifies that
// verification fails closed when NetDB lookup fails.
func TestVerifyRelayRequestSignature_RouterInfoLookupFails(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

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
// verification fails closed (returns error) when RouterLookupFunc is unavailable.
func TestVerifyPeerTestSignature_MissingRouterLookupFunc(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = nil
	tr.config.Store(cfg)

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
	err := tr.verifyPeerTestSignature(block, senderHash)

	assert.Error(t, err, "should error when RouterLookupFunc is nil (fail-closed)")
}

// TestVerifyPeerTestSignature_RouterInfoLookupFails verifies that
// verification fails closed when NetDB lookup fails.
func TestVerifyPeerTestSignature_RouterInfoLookupFails(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

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
	err := tr.verifyPeerTestSignature(block, senderHash)

	assert.Error(t, err, "should error when NetDB lookup fails")
}

// TestVerifyRelayResponseSignature_MissingRouterLookupFunc verifies that
// verification fails closed (returns error) when RouterLookupFunc is unavailable.
func TestVerifyRelayResponseSignature_MissingRouterLookupFunc(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = nil
	tr.config.Store(cfg)

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

	assert.Error(t, err, "should error when RouterLookupFunc is nil (fail-closed)")
	assert.False(t, valid, "should return false when RouterLookupFunc is nil")
}

// TestVerifyRelayResponseSignature_RouterInfoLookupFails verifies that
// verification fails closed when NetDB lookup fails.
func TestVerifyRelayResponseSignature_RouterInfoLookupFails(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

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

// TestVerifyPeerTestSignature_Code3_NilRouterHashFailsClosed verifies that for
// PeerTestResponse (code 3) — which requires Alice's hash in the signed data —
// the verifier fails closed when the block carries no RouterHash, rather than
// silently substituting the sender's hash. Regression for AUDIT.md H-1.
func TestVerifyPeerTestSignature_Code3_NilRouterHashFailsClosed(t *testing.T) {
	tr := makeMinimalTransport()
	// Provide a RouterLookupFunc that would succeed if reached; the test must
	// fail before lookup because RouterHash is nil.
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		t.Fatalf("RouterLookupFunc must not be called when RouterHash is nil for code 3")
		return router_info.RouterInfo{}, nil
	}
	tr.config.Store(cfg)

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestResponse,
		RouterHash:  nil,
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		AlicePort:   9000,
		AliceIP:     net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	err := tr.verifyPeerTestSignature(block, senderHash)

	assert.Error(t, err, "code 3 with nil RouterHash must fail closed")
}

// TestVerifyPeerTestSignature_Code4_NilRouterHashFailsClosed verifies that for
// PeerTestResult (code 4) — which requires Alice's hash in the signed data —
// the verifier fails closed when the block carries no RouterHash, rather than
// silently substituting the sender's hash. Regression for AUDIT.md H-1.
func TestVerifyPeerTestSignature_Code4_NilRouterHashFailsClosed(t *testing.T) {
	tr := makeMinimalTransport()
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		t.Fatalf("RouterLookupFunc must not be called when RouterHash is nil for code 4")
		return router_info.RouterInfo{}, nil
	}
	tr.config.Store(cfg)

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestResult,
		RouterHash:  nil,
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		AlicePort:   9000,
		AliceIP:     net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	senderHash := data.Hash{}
	err := tr.verifyPeerTestSignature(block, senderHash)

	assert.Error(t, err, "code 4 with nil RouterHash must fail closed")
}

// TestVerifyPeerTestSignature_Code4_UsesBlockRouterHashNotSenderHash verifies
// that when the block does carry a RouterHash distinct from the senderHash,
// the verifier uses block.RouterHash (Alice) for signature verification — not
// senderHash. We assert this indirectly: NetDB lookup is invoked with
// senderHash (Bob in code 4), and the signature still fails because the
// RouterInfo we return cannot satisfy a real signature, but the verifier must
// reach the lookup path (i.e. it must not short-circuit). Regression for
// AUDIT.md H-1.
func TestVerifyPeerTestSignature_Code4_UsesBlockRouterHashNotSenderHash(t *testing.T) {
	tr := makeMinimalTransport()
	lookupCalledWith := data.Hash{}
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		lookupCalledWith = hash
		// Return error so verification stops at the lookup boundary; the test
		// only needs to confirm we reached lookup with senderHash and did not
		// reject upfront.
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

	aliceHash := data.Hash{}
	for i := range aliceHash {
		aliceHash[i] = 0xAA
	}
	senderHash := data.Hash{}
	for i := range senderHash {
		senderHash[i] = 0xBB
	}

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestResult,
		RouterHash:  &aliceHash,
		Nonce:       12345,
		Timestamp:   1234567890,
		Version:     2,
		AlicePort:   9000,
		AliceIP:     net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	err := tr.verifyPeerTestSignature(block, senderHash)

	assert.Error(t, err, "lookup error should propagate")
	assert.Equal(t, senderHash, lookupCalledWith, "NetDB lookup must use senderHash to fetch Bob's signing key")
	assert.NotEqual(t, aliceHash, lookupCalledWith, "lookup must not use Alice's hash for the signing-key fetch")
}
