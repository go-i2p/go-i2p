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
func (c *NTCP2Session) ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
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
		StaticKeypair: s,
		Random:        rand.Reader,
	}

	state, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create Noise message
	msg, _, _, err = state.WriteMessage(nil, buf.Bytes())
	if err != nil {
		return nil, nil, nil, err
	}

	// Add padding
	msg = append(msg, request.Padding...)

	// Ensure entire message is written at once
	return nil, msg, state, nil
}
