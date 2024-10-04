package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"

	"github.com/flynn/noise"
)

func ComposeReceiverHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
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
	prologue := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)
	// prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s,
		Initiator:     false,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		PeerStatic:    rs,
		Prologue:      prologue,
		Random:        random,
	})
	if err != nil {
		return
	}
	padBuf := make([]byte, 2+len(payload))
	copy(padBuf[2:], payload)
	msg, _, _, err = state.WriteMessage(msg, padBuf)
	return
}

func (c *NoiseSession) RunIncomingHandshake() error {
	negData, msg, state, err := ComposeReceiverHandshakeMessage(c.HandKey, nil, nil, nil)
	if err != nil {
		return err
	}
	if _, err = c.Write(negData); err != nil {
		return err
	}
	if _, err = c.Write(msg); err != nil {
		return err
	}
	log.Println(state)
	c.handshakeComplete = true
	return nil
}
