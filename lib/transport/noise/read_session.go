package noise

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

func (c *NoiseSession) Read(b []byte) (int, error) {
	log.WithField("buffer_length", len(b)).Debug("Starting NoiseSession Read")
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			log.WithFields(logrus.Fields{
				"at":     "(NoiseSession) Read",
				"reason": "session is closed",
			}).Error("session is closed")
			return 0, oops.Errorf("session is closed")
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
		log.Debug("NoiseSession Read: retrying atomic operation")
	}
	if !c.HandshakeComplete() {
		log.Debug("NoiseSession Read: handshake not complete, running incoming handshake")
		if err := c.RunIncomingHandshake(); err != nil {
			log.WithError(err).Error("NoiseSession Read: failed to run incoming handshake")
			return 0, err
		}
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.HandshakeComplete() {
		log.Error("NoiseSession Read: internal error - handshake still not complete after running")
		return 0, oops.Errorf("internal error")
	}
	n, err := c.readPacketLocked(b)
	if err != nil {
		log.WithError(err).Error("NoiseSession Read: failed to read packet")
	} else {
		log.WithField("bytes_read", n).Debug("NoiseSession Read: successfully read packet")
	}
	return n, err
}

func (c *NoiseSession) decryptPacket(data []byte) (int, []byte, error) {
	log.WithField("data_length", len(data)).Debug("NoiseSession: Starting packet decryption")

	if c.CipherState == nil {
		log.Error("NoiseSession: decryptPacket - readState is nil")
		return 0, nil, oops.Errorf("readState is nil")
	}

	if len(data) < 2 {
		log.Error("NoiseSession: decryptPacket - packet too short")
		return 0, nil, oops.Errorf("packet too short")
	}

	// Extract payload length from prefix
	payloadLen := binary.BigEndian.Uint16(data[:2])
	if len(data[2:]) < int(payloadLen) {
		log.Error("NoiseSession: decryptPacket - incomplete packet")
		return 0, nil, oops.Errorf("incomplete packet")
	}

	// Decrypt payload
	decryptedData, err := c.CipherState.Decrypt(nil, nil, data[2:2+payloadLen])
	if err != nil {
		log.WithError(err).Error("NoiseSession: decryptPacket - failed to decrypt data")
		return 0, nil, oops.Errorf("failed to decrypt: %w", err)
	}

	m := len(decryptedData)
	log.WithFields(logrus.Fields{
		"encrypted_length": payloadLen,
		"decrypted_length": m,
	}).Debug("NoiseSession: decryptPacket - packet decrypted successfully")

	return m, decryptedData, nil
}

func (c *NoiseSession) readPacketLocked(data []byte) (int, error) {
	log.WithField("data_length", len(data)).Debug("Starting readPacketLocked")

	var n int
	if len(data) == 0 { // Handle special case where data length is zero during handshake
		log.Debug("readPacketLocked: special case - reading 2 bytes during handshake")
		if _, err := c.Conn.Read(make([]byte, 2)); err != nil {
			log.WithError(err).Error("readPacketLocked: failed to read 2 bytes during handshake")
			return 0, err
		}
	}
	for len(data) > 0 {
		_, b, err := c.decryptPacket(data)
		if err != nil {
			log.WithError(err).Error("readPacketLocked: failed to encrypt packet")
			return 0, err
		}
		bytesRead, err := c.Conn.Read(b)
		if err != nil {
			log.WithError(err).WithField("bytes_read", bytesRead).Error("readPacketLocked: failed to read from connection")
			return bytesRead, err
		}
		n += bytesRead
		data = data[bytesRead:]
		log.WithFields(logrus.Fields{
			"bytes_read":     n,
			"remaining_data": len(data),
		}).Debug("readPacketLocked: read packet chunk")
	}
	return n, nil
}
