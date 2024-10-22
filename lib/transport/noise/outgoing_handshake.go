package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/flynn/noise"
)

func ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
	log.Debug("Starting ComposeInitiatorHandshakeMessage")
	if len(rs) != 0 && len(rs) != noise.DH25519.DHLen() {
		log.WithField("rs_length", len(rs)).Error("Invalid remote static key length")
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	negData = make([]byte, 6)
	copy(negData, initNegotiationData(nil))
	pattern := noise.HandshakeXK
	negData[5] = NOISE_PATTERN_XK
	log.WithField("pattern", "XK").Debug("Noise pattern set")
	var random io.Reader
	if len(ePrivate) == 0 {
		random = rand.Reader
		log.Debug("Using crypto/rand as random source")
	} else {
		random = bytes.NewBuffer(ePrivate)
		log.Debug("Using provided ePrivate as random source")
	}
	prologue := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)
	log.WithField("prologue_length", len(prologue)).Debug("Prologue created")
	// prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		PeerStatic:    rs,
		Prologue:      prologue,
		Random:        random,
	})
	if err != nil {
		log.WithError(err).Error("Failed to create new handshake state")
		return
	}
	log.Debug("Handshake state created successfully")
	padBuf := make([]byte, 2+len(payload))
	copy(padBuf[2:], payload)
	msg, _, _, err = state.WriteMessage(msg, padBuf)
	if err != nil {
		log.WithError(err).Error("Failed to write handshake message")
		return
	}
	log.WithField("message_length", len(msg)).Debug("Handshake message composed successfully")

	return
}

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
