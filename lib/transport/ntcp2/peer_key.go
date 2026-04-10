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

// ConfigureDialConfig sets the peer's static key and obfuscation IV on an
// NTCP2Config for outbound connections. This is required for the Noise XK
// handshake pattern where the initiator must know the responder's static key.
//
// Spec reference: https://geti2p.net/spec/ntcp2 — Noise XK pattern requires
// the initiator to pre-know the responder's static public key.
func ConfigureDialConfig(config *ntcp2.NTCP2Config, peerInfo router_info.RouterInfo) error {
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
	if transport.config == nil || transport.config.NTCP2Config == nil {
		return oops.Errorf("transport config is not initialized")
	}
	privKeyBytes := transport.config.NTCP2Config.StaticKey
	if len(privKeyBytes) != 32 {
		return oops.Errorf("static key is not 32 bytes: got %d", len(privKeyBytes))
	}

	// Derive the public key from the live Noise static private key.
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(privKeyBytes)
	if err != nil {
		return oops.Wrapf(err, "failed to create Curve25519 private key from static key")
	}
	pubKey, err := privKey.Public()
	if err != nil {
		return oops.Wrapf(err, "failed to derive public key from static private key")
	}
	livePublicKey := pubKey.Bytes()

	// Extract the public key published in the RouterInfo NTCP2 "s=" option.
	publishedPublicKey, err := ExtractPeerStaticKey(identity)
	if err != nil {
		return oops.Wrapf(err, "failed to extract static key from local RouterInfo")
	}

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
