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
	// Create session request with obfuscated ephemeral key
	request, err := c.CreateSessionRequest()
	if err != nil {
		return nil, nil, nil, err
	}

	// Initialize negotiation data with NTCP2 protocol specifics
	negotiationData = initNegotiationData(nil)

	// Buffer for the complete message
	buf := new(bytes.Buffer)

	// Write obfuscated key - this has already been obfuscated in CreateSessionRequest()
	if _, err := buf.Write(request.ObfuscatedKey); err != nil {
		return nil, nil, nil, err
	}

	// Create options block - 16 bytes
	options := make([]byte, 16)

	// Set network ID (2 for production I2P)
	options[0] = 2
	// Set protocol version (2 for NTCP2)
	options[1] = NTCP_PROTOCOL_VERSION

	// Set padding length (bytes 2-3, big endian)
	binary.BigEndian.PutUint16(options[2:4], uint16(len(request.Padding)))

	// Set message 3 part 2 length (bytes 4-5) - placeholder for now
	// This is the size of the second AEAD frame in SessionConfirmed
	binary.BigEndian.PutUint16(options[4:6], 0) // Will need to be updated with actual size

	// Set timestamp (bytes 8-11, big endian)
	binary.BigEndian.PutUint32(options[8:12], request.Timestamp)

	// Reserved bytes (6-7, 12-15) should be set to 0

	// Write options block
	if _, err := buf.Write(options); err != nil {
		return nil, nil, nil, err
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
