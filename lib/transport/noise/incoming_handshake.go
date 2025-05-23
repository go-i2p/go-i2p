package noise

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/transport/noise/handshake"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

func (c *NoiseSession) RunIncomingHandshake() error {
	log.Debug("Starting incoming handshake")

	negData, msg, state, err := c.ComposeReceiverHandshakeMessage(*c.HandshakeKey(), nil, nil, nil)
	if err != nil {
		log.WithError(err).Error("Failed to compose receiver handshake message")
		return err
	}
	c.HandshakeState = &handshake.NoiseHandshakeState{
		HandshakeState: state,
	}
	log.WithFields(logrus.Fields{
		"negData_length": len(negData),
		"msg_length":     len(msg),
	}).Debug("Receiver handshake message composed")
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
	c.CompleteHandshake()
	log.Debug("Incoming handshake completed successfully")
	return nil
}

func (c *NoiseSession) ComposeReceiverHandshakeMessage(localStatic noise.DHKey, remoteStatic []byte, payload []byte, ephemeralPrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
	log.Debug("Starting ComposeReceiverHandshakeMessage")

	if len(remoteStatic) != 0 && len(remoteStatic) != noise.DH25519.DHLen() {
		log.WithField("rs_length", len(remoteStatic)).Error("Invalid remote static key length")
		return nil, nil, nil, oops.Errorf("only 32 byte curve25519 public keys are supported")
	}

	negData = make([]byte, 6)
	copy(negData, initNegotiationData(nil))
	pattern := noise.HandshakeXK
	negData[5] = NOISE_PATTERN_XK

	var random io.Reader
	if len(ephemeralPrivate) == 0 {
		random = rand.Reader
		log.Debug("Using crypto/rand as random source")
	} else {
		random = bytes.NewBuffer(ephemeralPrivate)
	}

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       pattern,
		Initiator:     false,
		StaticKeypair: localStatic,
		Random:        random,
	}

	state, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Write message 2, expecting no CipherStates yet
	msg, cs0, cs1, err := state.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify no CipherStates are returned yet
	if cs0 != nil || cs1 != nil {
		return nil, nil, nil, oops.Errorf("unexpected cipher states in message 2")
	}

	return negData, msg, state, nil
}
