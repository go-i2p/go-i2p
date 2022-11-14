package noise

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/flynn/noise"
)

func ComposeInitiatorHandshakeMessage(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {
	if len(rs) != 0 && len(rs) != noise.DH25519.DHLen() {

		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")

	}
	var pattern noise.HandshakePattern
	negData = make([]byte, 6)
	copy(negData, initNegotiationData(nil))
	pattern = noise.HandshakeIK
	negData[5] = NOISE_PATTERN_IK
	var random io.Reader
	if len(ePrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ePrivate)
	}
	prologue := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)
	//prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashBLAKE2b),
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
	var (
		negData, msg []byte
		state        *noise.HandshakeState
		err          error
	)
	if negData, msg, state, err = ComposeInitiatorHandshakeMessage(c.DHKey, nil, nil, nil); err != nil {
		return err
	}
	if _, err = c.Write(negData); err != nil {
		return err
	}
	if _, err = c.Write(msg); err != nil {
		return err
	}
	//read negotiation data
	/*if err := c.readPacket(); err != nil {
		return err
	}
	negotiationData := c.handshakeBuffer.Next(c.handshakeBuffer.Len())
	//read noise message
	if err := c.readPacket(); err != nil {
		return err
	}
	msg = c.handshakeBuffer.Next(c.handshakeBuffer.Len())
	if len(negotiationData) != 0 || len(msg) == 0 {
		return errors.New("Server returned error")
	}
	// cannot reuse msg for read, need another buf
	inBlock := c.NoiseTransport.newBlock()
	inBlock.reserve(len(msg))*/
	var payload []byte
	payload, c.CipherState, c.NoiseTransport.CipherState, err = state.ReadMessage(inBlock.data, msg)
	/*if err != nil {
		c.NoiseTransport.freeBlock(inBlock)
		return err
	}*/
	err = c.processCallback(state.PeerStatic(), payload)
	if err != nil {
		c.NoiseTransport.freeBlock(inBlock)
		return err
	}
	/*c.NoiseTransport.freeBlock(inBlock)
	if c.CipherState == nil && c.NoiseTransport.CipherState == nil {
		b := c.newBlock()
		if b.data, c.CipherState, c.NoiseTransport.CipherState, err = state.WriteMessage(b.data, pad(c.config.Payload)); err != nil {
			c.freeBlock(b)
			return err
		}
		if _, err = c.Write(nil); err != nil {
			c.freeBlock(b)
			return err
		}
		if _, err = c.Write(b.data); err != nil {
			c.freeBlock(b)
			return err
		}
		c.freeBlock(b)
		if c.CipherState == nil || c.NoiseTransport.CipherState == nil {
			log.WithFields(log.Fields{
				"at":     "(NoiseSession) RunIncomingHandshake",
				"reason": "unsupported session",
			}).Error("unsupported session")
			return errors.New("unsupported session")
		}
	}
	*/
	//c.in.padding, c.out.padding = c.config.Padding, c.config.Padding
	//c.channelBinding = state.ChannelBinding()
	c.handshakeComplete = true
	return nil
}
