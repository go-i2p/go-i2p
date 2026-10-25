// Tests for relay request signature verification. Verifies that relay
// requests are only accepted with a valid router signature, and fail
// closed when the router cannot be looked up.

package ssu2

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

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

// TestVerifyPeerTestSignature_Code4_SignerIsCharlieFromBlockHash verifies that
// for PeerTestResult (code 4, Bob -> Alice, we are Alice) the signing key is
// fetched for block.RouterHash -- Charlie, who produced the agreement being
// signed -- and NOT for senderHash (Bob, who merely forwarded the block).
//
// ssu2.rst §"Signatures": "Charlie signs the response and includes it in
// message 3; Bob forwards it in message 4 to Alice", with bhash = Bob's hash
// and the Alice hash used as ahash. Verifying with Bob's key (the previous
// behavior) could never succeed on a genuine message 4, since Bob did not sign
// it. Regression for AUDIT.md H-1.
func TestVerifyPeerTestSignature_Code4_SignerIsCharlieFromBlockHash(t *testing.T) {
	tr := makeMinimalTransport()
	lookupCalledWith := data.Hash{}
	cfg := tr.config.Load()
	cfg.RouterLookupFunc = func(hash data.Hash) (router_info.RouterInfo, error) {
		lookupCalledWith = hash
		// Return error so verification stops at the lookup boundary; the test
		// only needs to confirm which hash the signing-key fetch used.
		return router_info.RouterInfo{}, assert.AnError
	}
	tr.config.Store(cfg)

	charlieHash := data.Hash{}
	for i := range charlieHash {
		charlieHash[i] = 0xAA
	}
	bobHash := data.Hash{}
	for i := range bobHash {
		bobHash[i] = 0xBB
	}

	block := &ssu2noise.PeerTestBlock{
		MessageCode: ssu2noise.PeerTestResult,
		RouterHash:  &charlieHash,
		Nonce:       12345,
		Timestamp:   uint32(time.Now().Unix()),
		Version:     2,
		AlicePort:   9000,
		AliceIP:     net.ParseIP("192.0.2.1"),
		Signature:   make([]byte, ed25519.SignatureSize),
	}

	err := tr.verifyPeerTestSignature(block, bobHash)

	assert.Error(t, err, "lookup error should propagate")
	assert.Equal(t, charlieHash, lookupCalledWith, "signing key must be fetched for Charlie (block.RouterHash)")
	assert.NotEqual(t, bobHash, lookupCalledWith, "signing key must not be fetched for Bob, who only forwarded the block")
}
