package ntcp2

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/go-noise/ntcp2"
	"github.com/samber/oops"
)

// ExtractPeerStaticKey extracts the NTCP2 static public key ("s=" option)
// from a peer's RouterInfo. This key is required by the Noise XK pattern
// because the initiator must know the responder's static key before the
// handshake begins.
//
// The static key is published in the peer's RouterInfo as a base64-encoded
// 32-byte Curve25519 public key in the "s=" option of the NTCP2 address.
//
// Returns the 32-byte static key or an error if:
//   - The RouterInfo has no NTCP2 addresses
//   - No NTCP2 address has a valid "s=" option
//   - The "s=" value cannot be decoded or is not 32 bytes
func ExtractPeerStaticKey(routerInfo router_info.RouterInfo) ([]byte, error) {
	addresses := routerInfo.RouterAddresses()
	for _, addr := range addresses {
		style := addr.TransportStyle()
		styleStr, err := style.Data()
		if err != nil {
			continue
		}
		if !strings.EqualFold(styleStr, "ntcp2") {
			continue
		}

		staticKey, err := extractStaticKeyFromAddress(addr)
		if err != nil {
			continue
		}
		return staticKey, nil
	}

	return nil, oops.Errorf("no valid NTCP2 static key found in RouterInfo")
}

// extractStaticKeyFromAddress attempts to extract the static key from a single
// NTCP2 router address using the StaticKey() accessor.
func extractStaticKeyFromAddress(addr *router_address.RouterAddress) ([]byte, error) {
	staticKey, err := addr.StaticKey()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to extract static key")
	}
	return staticKey[:], nil
}

// ExtractPeerIV extracts the NTCP2 AES obfuscation IV ("i=" option)
// from a peer's RouterInfo. This IV is used for AES-CBC obfuscation of the
// ephemeral key in message 1.
//
// Returns the 16-byte IV or an error if not found.
func ExtractPeerIV(routerInfo router_info.RouterInfo) ([]byte, error) {
	addresses := routerInfo.RouterAddresses()
	for _, addr := range addresses {
		style := addr.TransportStyle()
		styleStr, err := style.Data()
		if err != nil {
			continue
		}
		if !strings.EqualFold(styleStr, "ntcp2") {
			continue
		}

		iv, err := addr.InitializationVector()
		if err != nil {
			continue
		}
		return iv[:], nil
	}

	return nil, oops.Errorf("no valid NTCP2 IV found in RouterInfo")
}

// ConfigureDialConfig sets the peer's static key and obfuscation IV on a
// Config for outbound connections. This is required for the Noise XK
// handshake pattern where the initiator must know the responder's static key.
//
// Spec reference: https://geti2p.net/spec/ntcp2 — Noise XK pattern requires
// the initiator to pre-know the responder's static public key.
func ConfigureDialConfig(config *ntcp2.Config, peerInfo router_info.RouterInfo) error {
	// Extract and set the peer's static key as the *remote* static key.
	// The Noise XK pre-message is "← s": the initiator must know the
	// responder's static public key before the handshake begins.
	// WithStaticKey sets the local key; WithRemoteStaticKey sets the peer's key.
	staticKey, err := ExtractPeerStaticKey(peerInfo)
	if err != nil {
		return oops.Wrapf(err, "failed to extract peer static key for XK handshake")
	}

	config.WithRemoteStaticKey(staticKey)

	log.WithFields(map[string]interface{}{
		"static_key_len": len(staticKey),
		"static_key_b64": base64.StdEncoding.EncodeToString(staticKey[:8]),
	}).Debug("Configured peer remote static key for XK handshake")

	// Extract and set the peer's obfuscation IV
	iv, err := ExtractPeerIV(peerInfo)
	if err != nil {
		// IV extraction failure is non-fatal — AES obfuscation may not be
		// available for all peers.
		log.WithError(err).Debug("Could not extract peer IV (AES obfuscation may be unavailable)")
	} else {
		config.WithAESObfuscation(true, iv)
		log.WithField("iv_len", len(iv)).Debug("Configured peer IV for AES obfuscation")
	}

	return nil
}

// VerifyStaticKeyConsistency checks that the Noise static private key stored in the
// transport config produces the same public key that was published in the NTCP2
// RouterInfo "s=" option.
//
// A mismatch means every remote peer will reject our Noise message 1 immediately
// after verifying our static key, causing 100% outbound NTCP2 handshake failures
// and making us unreachable to all NTCP2 peers.
//
// Should be called once at startup after the RouterInfo has been built and signed.
// Returns a descriptive error (with both keys base64-encoded) if a mismatch is found.
func VerifyStaticKeyConsistency(transport *NTCP2Transport, identity router_info.RouterInfo) error {
	privKeyBytes, err := getValidatedPrivateKey(transport)
	if err != nil {
		return err
	}

	livePublicKey, err := deriveLivePublicKey(privKeyBytes)
	if err != nil {
		return err
	}

	publishedPublicKey, err := ExtractPeerStaticKey(identity)
	if err != nil {
		return oops.Wrapf(err, "failed to extract static key from local RouterInfo")
	}

	return verifyKeyConsistency(livePublicKey, publishedPublicKey)
}

// getValidatedPrivateKey retrieves and validates the transport's static private key.
func getValidatedPrivateKey(transport *NTCP2Transport) ([]byte, error) {
	// HIGH-1.3 fix: Load config atomically
	cfg := transport.config.Load()
	if cfg == nil || cfg.Config == nil {
		return nil, oops.Errorf("transport config is not initialized")
	}

	privKeyBytes := cfg.Config.StaticKey
	if len(privKeyBytes) != 32 {
		return nil, oops.Errorf("static key is not 32 bytes: got %d", len(privKeyBytes))
	}

	return privKeyBytes, nil
}

// deriveLivePublicKey derives the public key from the private key bytes.
func deriveLivePublicKey(privKeyBytes []byte) ([]byte, error) {
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(privKeyBytes)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create Curve25519 private key from static key")
	}

	pubKey, err := privKey.Public()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive public key from static private key")
	}

	return pubKey.Bytes(), nil
}

// verifyKeyConsistency compares the live and published public keys.
func verifyKeyConsistency(livePublicKey, publishedPublicKey []byte) error {
	if !bytes.Equal(livePublicKey, publishedPublicKey) {
		return oops.Errorf(
			"NTCP2 static key mismatch: live Noise public key %s does not match published RouterInfo key %s — "+
				"every peer will reject our handshake; check that the encryption key in RouterInfoKeystore matches "+
				"the key used when the RouterInfo was built",
			base64.StdEncoding.EncodeToString(livePublicKey),
			base64.StdEncoding.EncodeToString(publishedPublicKey),
		)
	}

	log.WithField("at", "VerifyStaticKeyConsistency").Debug("NTCP2 static key consistency verified: live key matches published RouterInfo")
	return nil
}

// verifyLocalRouterInfoMatchesStaticKey derives the Curve25519 public key from
// staticPriv (32-byte scalar) and checks that at least one NTCP2 RouterAddress
// in localRI publishes that exact key as its "s=" option.
//
// This mirrors i2pd's RouterInfo::GetNTCP2AddressWithStaticKey check that runs
// inside HandleSessionConfirmedReceived: if no matching address is found, i2pd
// silently closes the TCP connection with zero data-phase bytes (no termination
// frame), producing the "frame #0 EOF" symptom.
//
// Returns nil if a matching address is found, otherwise a structured error with
// the derived key and every published key in base64 for easy comparison.
func verifyLocalRouterInfoMatchesStaticKey(localRI router_info.RouterInfo, staticPriv []byte) error {
	derivedPubKey, err := derivePublicKeyFromPrivate(staticPriv)
	if err != nil {
		return err
	}

	publishedKeys, ntcp2Count := extractPublishedNTCP2Keys(localRI)

	if matchFound := checkForKeyMatch(derivedPubKey, publishedKeys); matchFound {
		return nil
	}

	return buildKeyMismatchError(derivedPubKey, publishedKeys, ntcp2Count)
}

// derivePublicKeyFromPrivate derives the Curve25519 public key from a private key.
func derivePublicKeyFromPrivate(staticPriv []byte) ([]byte, error) {
	if len(staticPriv) != 32 {
		return nil, oops.Errorf("static key is %d bytes (want 32)", len(staticPriv))
	}

	priv, err := i2pcurve25519.NewCurve25519PrivateKey(staticPriv)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Curve25519 private key")
	}

	pub, err := priv.Public()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive Curve25519 public key")
	}

	return pub.Bytes(), nil
}

// extractPublishedNTCP2Keys extracts all published NTCP2 static keys from RouterInfo.
func extractPublishedNTCP2Keys(localRI router_info.RouterInfo) ([][]byte, int) {
	var publishedKeys [][]byte
	var ntcp2Count int

	for _, addr := range localRI.RouterAddresses() {
		styleStr, err := addr.TransportStyle().Data()
		if err != nil || !strings.EqualFold(styleStr, "ntcp2") {
			continue
		}
		ntcp2Count++

		publishedStaticKey, err := addr.StaticKey()
		if err != nil {
			continue
		}
		publishedKeys = append(publishedKeys, publishedStaticKey[:])
	}

	return publishedKeys, ntcp2Count
}

// checkForKeyMatch checks if the derived key matches any published key.
func checkForKeyMatch(derivedPubKey []byte, publishedKeys [][]byte) bool {
	for _, pubKey := range publishedKeys {
		if bytes.Equal(pubKey, derivedPubKey) {
			return true
		}
	}
	return false
}

// buildKeyMismatchError constructs a detailed error for key mismatches.
func buildKeyMismatchError(derivedPubKey []byte, publishedKeys [][]byte, ntcp2Count int) error {
	pubB64 := base64.StdEncoding.EncodeToString(derivedPubKey)
	var publishedB64 []string
	for _, k := range publishedKeys {
		publishedB64 = append(publishedB64, base64.StdEncoding.EncodeToString(k))
	}

	return oops.
		Code("STATIC_KEY_RI_MISMATCH").
		With("derived_public_key_b64", pubB64).
		With("published_ntcp2_keys_b64", publishedB64).
		With("ntcp2_address_count", ntcp2Count).
		Errorf("derived public key from live NTCP2 static private key is not "+
			"published as `s=` in any of %d NTCP2 router addresses",
			ntcp2Count)
}
