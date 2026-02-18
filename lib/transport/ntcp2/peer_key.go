package ntcp2

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-noise/ntcp2"
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

	return nil, fmt.Errorf("no valid NTCP2 static key found in RouterInfo")
}

// extractStaticKeyFromAddress attempts to extract the static key from a single
// NTCP2 router address using the StaticKey() accessor.
func extractStaticKeyFromAddress(addr *router_address.RouterAddress) ([]byte, error) {
	staticKey, err := addr.StaticKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract static key: %w", err)
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

	return nil, fmt.Errorf("no valid NTCP2 IV found in RouterInfo")
}

// ConfigureDialConfig sets the peer's static key and obfuscation IV on an
// NTCP2Config for outbound connections. This is required for the Noise XK
// handshake pattern where the initiator must know the responder's static key.
//
// Spec reference: https://geti2p.net/spec/ntcp2 — Noise XK pattern requires
// the initiator to pre-know the responder's static public key.
func ConfigureDialConfig(config *ntcp2.NTCP2Config, peerInfo router_info.RouterInfo) error {
	// Extract and set the peer's static key
	staticKey, err := ExtractPeerStaticKey(peerInfo)
	if err != nil {
		return fmt.Errorf("failed to extract peer static key for XK handshake: %w", err)
	}

	config, err = config.WithStaticKey(staticKey)
	if err != nil {
		return fmt.Errorf("failed to set peer static key: %w", err)
	}

	log.WithFields(map[string]interface{}{
		"static_key_len": len(staticKey),
		"static_key_b64": base64.StdEncoding.EncodeToString(staticKey[:8]),
	}).Debug("Configured peer static key for XK handshake")

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
