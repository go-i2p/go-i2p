package ntcp

import (
	"bytes"
	"crypto/rand"

	"github.com/flynn/noise"
	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// Modify ComposeInitiatorHandshakeMessage in outgoing_handshake.go
// At the moment, remoteStatic is stored in the NTCP2Session() and doesn't need to be passed as an argument.
// You actually get it directly out of the remote RouterInfo, which the NoiseSession also has access to.
// So maybe, the interface should change so that we:
//   - A: get the localStatic out of the parent NTCP2Transport's routerInfo, which is the "local" routerInfo
//   - B: get the remoteStatic out of the NTCP2Session router, which is the "remote" routerInfo
func (c *NTCP2Session) ComposeInitiatorHandshakeMessage(
	localStatic noise.DHKey,
	remoteStatic []byte,
	payload []byte,
	ephemeralPrivate []byte,
) (
	negotiationData,
	handshakeMessage []byte,
	handshakeState *noise.HandshakeState,
	err error,
) {
	// Create session request with obfuscated ephemeral key
	request, err := c.CreateSessionRequest()
	if err != nil {
		return nil, nil, nil, err
	}

	// Initialize negotiation data with NTCP2 protocol specifics
	negotiationData = initNegotiationData(nil)

	// Buffer for the complete message
	buf := new(bytes.Buffer)

	obfuscatedKey, err := c.ObfuscateEphemeral(request.XContent[:])
	if err != nil {
		return nil, nil, nil, err
	}
	if wrote, err := buf.Write(obfuscatedKey); err != nil {
		return nil, nil, nil, err
	} else {
		log.Debugf("Wrote %d bytes of obfuscated key", wrote)
	}

	// Write options block
	if wrote, err := buf.Write(request.Options.Data()); err != nil {
		return nil, nil, nil, err
	} else {
		log.Debugf("Wrote %d bytes of obfuscated key", wrote)
	}

	// Initialize Noise
	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		StaticKeypair: localStatic,
		PeerStatic:    remoteStatic, // Add the peer's static key
		Random:        rand.Reader,
	}

	handshakeState, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create Noise message - this contains the encrypted payload (options block)
	// WriteMessage encrypts the payload and returns the message
	handshakeMessage, _, _, err = handshakeState.WriteMessage(nil, buf.Bytes())
	if err != nil {
		return nil, nil, nil, err
	}

	// Add padding
	handshakeMessage = append(handshakeMessage, request.Padding...)

	// Return the complete handshake message
	return negotiationData, handshakeMessage, handshakeState, nil
}
