package noise

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/flynn/noise"
	"github.com/samber/oops"
)

func (c *NoiseSession) RunOutgoingHandshake() error {
	log.Debug("Starting outgoing handshake")

	negData, msg, state, err := c.ComposeInitiatorHandshakeMessage(nil, nil)
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

func (c *NoiseSession) ComposeInitiatorHandshakeMessage(
	payload []byte,
	ephemeralPrivate []byte,
) (
	negotiationData,
	handshakeMessage []byte,
	handshakeState *noise.HandshakeState,
	err error,
) {
	log.Debug("Starting ComposeInitiatorHandshakeMessage")

	remoteStatic, err := c.peerStaticKey()
	if err != nil {
		return nil, nil, nil, oops.Errorf("Peer static key retrieval error: %s", err)
	}

	/*localStatic, err := c.localStaticKey()
	if err != nil {
		return nil, nil, nil, oops.Errorf("Local static key retrieval error: %s", err)
	}
	localStaticDH := noise.DHKey{
		Public: localStatic[:],
		Private: localStatic[:],
	}*/
	localStaticDH := *c.HandshakeKey()

	if len(remoteStatic) != 0 && len(remoteStatic) != noise.DH25519.DHLen() {
		return nil, nil, nil, oops.Errorf("only 32 byte curve25519 public keys are supported")
	}

	negotiationData = make([]byte, 6)
	copy(negotiationData, initNegotiationData(nil))
	pattern := noise.HandshakeXK
	negotiationData[5] = NOISE_PATTERN_XK

	var random io.Reader
	if len(ephemeralPrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ephemeralPrivate)
	}

	config := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       pattern,
		Initiator:     true,
		StaticKeypair: localStaticDH,
		Random:        random,
	}

	handshakeState, err = noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Write message, expecting no CipherStates yet since this is message 1
	handshakeMessage, cs0, cs1, err := handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify no CipherStates are returned yet
	if cs0 != nil || cs1 != nil {
		return nil, nil, nil, oops.Errorf("unexpected cipher states in message 1")
	}

	return negotiationData, handshakeMessage, handshakeState, nil
}
