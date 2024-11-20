package ntcp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/util/logger"
)

var log = logger.GetGoI2PLogger()

func (c *NTCP2Session) ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
	log.Debug("Starting ComposeInitiatorHandshakeMessage")

	if len(rs) != 0 && len(rs) != noise.DH25519.DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}

	negData = make([]byte, 6)
	copy(negData, initNegotiationData(nil))
	pattern := noise.HandshakeXK
	negData[5] = NOISE_PATTERN_XK

	var random io.Reader
	if len(ePrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ePrivate)
	}

	// obfuscate our 32 byte public key with the remote's 32 byte static public key
	eph, err := c.ObfuscateEphemeral(s.Public)
	if err != nil {
		return nil, nil, nil, err
	}
	// copy the obfuscated ephemeral public key to the negData
	copy(negData[6:], eph)

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       pattern,
		Initiator:     true,
		StaticKeypair: s,
		Random:        random,
	}

	state, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Write message, expecting no CipherStates yet since this is message 1
	msg, cs0, cs1, err := state.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify no CipherStates are returned yet
	if cs0 != nil || cs1 != nil {
		return nil, nil, nil, errors.New("unexpected cipher states in message 1")
	}

	return negData, msg, state, nil
}
