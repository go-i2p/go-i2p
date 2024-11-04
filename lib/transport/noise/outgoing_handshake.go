package noise

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/flynn/noise"
)

func (c *NoiseSession) RunOutgoingHandshake() error {
	log.Debug("Starting outgoing handshake")

	negData, msg, state, err := ComposeInitiatorHandshakeMessage(c.HandKey, nil, nil, nil)
	if err != nil {
		log.WithError(err).Error("Failed to compose initiator handshake message")
		return err
	}
	log.WithFields(logrus.Fields{
		"negData_length": len(negData),
		"msg_length":     len(msg),
	}).Debug("Initiator handshake message composed")
	c.HandshakeState = &HandshakeState{
		HandshakeState: state,
	}

	if _, err = c.Write(negData); err != nil {
		log.WithError(err).Error("Failed to write negotiation data")
		return err
	}
	log.Debug("Negotiation data written successfully")

	if _, err = c.Write(msg); err != nil {
		log.WithError(err).Error("Failed to write handshake message")
		return err
	}
	log.Debug("Handshake message written successfully")
	log.WithField("state", state).Debug("Handshake state after message write")
	log.Println(state)
	c.handshakeComplete = true
	log.Debug("Outgoing handshake completed successfully")
	return nil
}

func ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
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

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
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
