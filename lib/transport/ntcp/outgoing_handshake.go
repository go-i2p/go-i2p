package ntcp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

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
	// Create session request
	request, err := c.CreateSessionRequest()
	if err != nil {
		return nil, nil, nil, err
	}

	// Buffer for the complete message
	buf := new(bytes.Buffer)

	// Write obfuscated key
	buf.Write(request.ObfuscatedKey)

	// Write timestamp
	binary.BigEndian.PutUint32(buf.Next(4), request.Timestamp)

	// Initialize Noise
	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		StaticKeypair: localStatic,
		Random:        rand.Reader,
	}

	handshakeState, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create Noise message
	handshakeMessage, _, _, err = handshakeState.WriteMessage(nil, buf.Bytes())
	if err != nil {
		return nil, nil, nil, err
	}

	// Add padding
	handshakeMessage = append(handshakeMessage, request.Padding...)

	// Ensure entire message is written at once
	return nil, handshakeMessage, handshakeState, nil
}
