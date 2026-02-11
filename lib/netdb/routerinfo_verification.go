package netdb

import (
	"fmt"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// verifyRouterInfoSignature verifies the cryptographic signature of a RouterInfo.
// It extracts the signing public key from the RouterInfo's identity, creates a verifier,
// reconstructs the signed data (everything except the trailing signature), and verifies
// the signature against it.
//
// Per the I2P specification, RouterInfos received from other routers MUST have their
// signatures verified before being stored in the NetDB. Storing unverified RouterInfos
// could allow forged entries (Sybil attacks, routing manipulation, traffic interception).
func verifyRouterInfoSignature(ri router_info.RouterInfo) error {
	// Get the router identity which contains the signing public key
	identity := ri.RouterIdentity()
	if identity == nil {
		return fmt.Errorf("RouterInfo has nil RouterIdentity, cannot verify signature")
	}

	// Extract the signing public key from the identity's KeysAndCert
	signingPubKey, err := identity.SigningPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get signing public key from RouterInfo: %w", err)
	}

	// Create a verifier for this key type (Ed25519, ECDSA, RSA, etc.)
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	// Get the full serialized RouterInfo (includes signature at the end)
	fullBytes, err := ri.Bytes()
	if err != nil {
		return fmt.Errorf("failed to serialize RouterInfo for verification: %w", err)
	}

	// Get the signature bytes
	sig := ri.Signature()
	sigBytes := sig.Bytes()
	sigLen := len(sigBytes)

	if sigLen == 0 {
		return fmt.Errorf("RouterInfo has empty signature")
	}

	if sigLen >= len(fullBytes) {
		return fmt.Errorf("RouterInfo signature length (%d) >= total length (%d)", sigLen, len(fullBytes))
	}

	// The data-to-be-verified is everything except the trailing signature
	dataToVerify := fullBytes[:len(fullBytes)-sigLen]

	// Verify the signature
	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithFields(logger.Fields{
			"error":    err.Error(),
			"sig_len":  sigLen,
			"data_len": len(dataToVerify),
		}).Warn("RouterInfo signature verification failed")
		return fmt.Errorf("RouterInfo signature verification failed: %w", err)
	}

	return nil
}
