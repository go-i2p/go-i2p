package noise

import (
	"errors"
	"github.com/sirupsen/logrus"
	"sync/atomic"
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
			return 0, errors.New("session is closed")
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
		log.Debug("NoiseSession Read: retrying atomic operation")
	}
	if !c.handshakeComplete {
		log.Debug("NoiseSession Read: handshake not complete, running incoming handshake")
		if err := c.RunIncomingHandshake(); err != nil {
			log.WithError(err).Error("NoiseSession Read: failed to run incoming handshake")
			return 0, err
		}
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.handshakeComplete {
		log.Error("NoiseSession Read: internal error - handshake still not complete after running")
		return 0, errors.New("internal error")
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
	log.WithField("data_length", len(data)).Debug("Starting packet decryption")

	if c.CipherState == nil {
		log.Error("Packet decryption: CipherState is nil")
		return 0, nil, errors.New("CipherState is nil")
	}
	// Decrypt
	decryptedData, err := c.CipherState.Decrypt(nil, nil, data)
	if err != nil {
		log.WithError(err).Error("Packet decryption: failed to decrypt data")
		return 0, nil, err
	}
	m := len(decryptedData)
	log.WithField("decrypted_length", m).Debug("Packet decryption: successfully decrypted data")
	return m, decryptedData, nil
	/*packet := c.InitializePacket()
	maxPayloadSize := c.maxPayloadSizeForRead(packet)
	if m > int(maxPayloadSize) {
		m = int(maxPayloadSize)
	}
	if c.CipherState != nil {
		////fmt.Println("writing encrypted packet:", m)
		packet.reserve(uint16Size + uint16Size + m + macSize)
		packet.resize(uint16Size + uint16Size + m)
		copy(packet.data[uint16Size+uint16Size:], data[:m])
		binary.BigEndian.PutUint16(packet.data[uint16Size:], uint16(m))
		//fmt.Println("encrypt size", uint16(m))
	} else {
		packet.resize(len(packet.data) + len(data))
		copy(packet.data[uint16Size:len(packet.data)], data[:m])
		binary.BigEndian.PutUint16(packet.data, uint16(len(data)))
	}
	b := c.encryptIfNeeded(packet)*/
	//c.freeBlock(packet)
}

func (c *NoiseSession) readPacketLocked(data []byte) (int, error) {
	log.WithField("data_length", len(data)).Debug("Starting readPacketLocked")

	var n int
	if len(data) == 0 { // special case to answer when everything is ok during handshake
		log.Debug("readPacketLocked: special case - reading 2 bytes during handshake")
		if _, err := c.Conn.Read(make([]byte, 2)); err != nil {
			log.WithError(err).Error("readPacketLocked: failed to read 2 bytes during handshake")
			return 0, err
		}
	}
	for len(data) > 0 {
		m, b, err := c.encryptPacket(data)
		if err != nil {
			log.WithError(err).Error("readPacketLocked: failed to encrypt packet")
			return 0, err
		}
		/*
			if n, err := c.Conn.Read(b); err != nil {
				return n, err
			} else {
				n += m
				data = data[m:]
			}
		*/
		n, err := c.Conn.Read(b)
		if err != nil {
			log.WithError(err).WithField("bytes_read (aka n)", n).Error("readPacketLocked: failed to read from connection")
			return n, err
		}
		n += m
		data = data[m:]
		log.WithFields(logrus.Fields{
			"bytes_read":     n,
			"remaining_data": len(data),
		}).Debug("readPacketLocked: read packet chunk")
	}
	return n, nil
}
