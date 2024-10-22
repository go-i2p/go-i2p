package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"sync/atomic"
)

func (c *NoiseSession) Write(b []byte) (int, error) {
	log.WithField("data_length", len(b)).Debug("NoiseSession: Starting Write operation")
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			log.WithFields(logrus.Fields{
				"at":     "(NoiseSession) Write",
				"reason": "session is closed",
			}).Error("session is closed")
			return 0, errors.New("session is closed")
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
		log.Debug("NoiseSession: Write - retrying atomic operation")
	}
	if !c.handshakeComplete {
		log.Debug("NoiseSession: Write - handshake not complete, running outgoing handshake")
		if err := c.RunOutgoingHandshake(); err != nil {
			log.WithError(err).Error("NoiseSession: Write - failed to run outgoing handshake")
			return 0, err
		}
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.handshakeComplete {
		log.Error("NoiseSession: Write - internal error, handshake still not complete")
		return 0, errors.New("internal error")
	}
	n, err := c.writePacketLocked(b)
	if err != nil {
		log.WithError(err).Error("NoiseSession: Write - failed to write packet")
	} else {
		log.WithField("bytes_written", n).Debug("NoiseSession: Write - successfully wrote packet")
	}
	return n, err
}

func (c *NoiseSession) encryptPacket(data []byte) (int, []byte, error) {
	log.WithField("data_length", len(data)).Debug("NoiseSession: Starting packet encryption")

	m := len(data)
	if c.CipherState == nil {
		log.Error("NoiseSession: encryptPacket - CipherState is nil")
		return 0, nil, errors.New("CipherState is nil")
	}

	// Encrypt the data
	encryptedData, err := c.CipherState.Encrypt(nil, nil, data)
	if err != nil {
		log.WithError(err).Error("NoiseSession: encryptPacket - failed to encrypt data")
		return 0, nil, fmt.Errorf("failed to encrypt: '%w'", err)
	}
	// m := len(encryptedData)

	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(encryptedData)))

	// Append encr data to prefix
	packet := append(lengthPrefix, encryptedData...)
	log.WithFields(logrus.Fields{
		"original_length":  m,
		"encrypted_length": len(encryptedData),
		"packet_length":    len(packet),
	}).Debug("NoiseSession: encryptPacket - packet encrypted successfully")
	return m, packet, nil
	/*packet := c.InitializePacket()
	maxPayloadSize := c.maxPayloadSizeForWrite(packet)
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

func (c *NoiseSession) writePacketLocked(data []byte) (int, error) {
	log.WithField("data_length", len(data)).Debug("NoiseSession: Starting writePacketLocked")

	var n int
	if len(data) == 0 { // special case to answer when everything is ok during handshake
		log.Debug("NoiseSession: writePacketLocked - special case, writing 2 empty bytes")
		if _, err := c.Conn.Write(make([]byte, 2)); err != nil {
			log.WithError(err).Error("NoiseSession: writePacketLocked - failed to write empty bytes")
			return 0, err
		}
	}
	for len(data) > 0 {
		m, b, err := c.encryptPacket(data)
		if err != nil {
			log.WithError(err).Error("NoiseSession: writePacketLocked - failed to encrypt packet")
			return 0, err
		}
		if n, err := c.Conn.Write(b); err != nil {
			log.WithError(err).WithField("bytes_written", n).Error("NoiseSession: writePacketLocked - failed to write to connection")
			return n, err
		} else {
			n += m
			data = data[m:]
			log.WithFields(logrus.Fields{
				"bytes_written":  n,
				"remaining_data": len(data),
			}).Debug("NoiseSession: writePacketLocked - wrote packet chunk")
		}
	}

	log.WithField("total_bytes_written", n).Debug("NoiseSession: writePacketLocked - completed writing all packets")
	return n, nil
}
