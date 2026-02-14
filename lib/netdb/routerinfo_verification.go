package netdb

import (
	"fmt"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// verifyRouterInfoSignature verifies the cryptographic signature of a RouterInfo.
// It extracts the signing public key, creates a verifier, and checks the signature
// against the signed data (everything except the trailing signature bytes).
func verifyRouterInfoSignature(ri router_info.RouterInfo) error {
	verifier, err := createRouterInfoVerifier(ri)
	if err != nil {
		return err
	}

	dataToVerify, sigBytes, err := extractSignatureComponents(ri)
	if err != nil {
		return err
	}

	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithFields(logger.Fields{
			"error":    err.Error(),
			"sig_len":  len(sigBytes),
			"data_len": len(dataToVerify),
		}).Warn("RouterInfo signature verification failed")
		return fmt.Errorf("RouterInfo signature verification failed: %w", err)
	}

	return nil
}

// createRouterInfoVerifier extracts the signing public key from a RouterInfo's identity
// and creates a signature verifier appropriate for the key type (Ed25519, ECDSA, RSA, etc.).
func createRouterInfoVerifier(ri router_info.RouterInfo) (interface{ Verify([]byte, []byte) error }, error) {
	identity := ri.RouterIdentity()
	if identity == nil {
		return nil, fmt.Errorf("RouterInfo has nil RouterIdentity, cannot verify signature")
	}

	signingPubKey, err := identity.SigningPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing public key from RouterInfo: %w", err)
	}

	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create signature verifier: %w", err)
	}

	return verifier, nil
}

// extractSignatureComponents separates a serialized RouterInfo into the data-to-verify
// and the trailing signature bytes. Returns an error if the signature is empty or
// longer than the total serialized data.
func extractSignatureComponents(ri router_info.RouterInfo) (dataToVerify, sigBytes []byte, err error) {
	fullBytes, err := ri.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize RouterInfo for verification: %w", err)
	}

	sig := ri.Signature()
	sigBytes = sig.Bytes()

	if len(sigBytes) == 0 {
		return nil, nil, fmt.Errorf("RouterInfo has empty signature")
	}

	if len(sigBytes) >= len(fullBytes) {
		return nil, nil, fmt.Errorf("RouterInfo signature length (%d) >= total length (%d)", len(sigBytes), len(fullBytes))
	}

	dataToVerify = fullBytes[:len(fullBytes)-len(sigBytes)]
	return dataToVerify, sigBytes, nil
}
