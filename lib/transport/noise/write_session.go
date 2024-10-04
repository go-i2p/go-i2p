package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

func (c *NoiseSession) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			log.WithFields(log.Fields{
				"at":     "(NoiseSession) Write",
				"reason": "session is closed",
			}).Error("session is closed")
			return 0, errors.New("session is closed")
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
	}
	if !c.handshakeComplete {
		if err := c.RunOutgoingHandshake(); err != nil {
			return 0, err
		}
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.handshakeComplete {
		return 0, errors.New("internal error")
	}
	n, err := c.writePacketLocked(b)
	return n, err
}

func (c *NoiseSession) encryptPacket(data []byte) (int, []byte, error) {
	m := len(data)
	if c.CipherState == nil {
		return 0, nil, errors.New("CipherState is nil")
	}

	// Encrypt the data
	encryptedData, err := c.CipherState.Encrypt(nil, nil, data)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to encrypt: '%w'", err)
	}
	//m := len(encryptedData)

	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(encryptedData)))

	// Append encr data to prefix
	packet := append(lengthPrefix, encryptedData...)
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
	var n int
	if len(data) == 0 { //special case to answer when everything is ok during handshake
		if _, err := c.Conn.Write(make([]byte, 2)); err != nil {
			return 0, err
		}
	}
	for len(data) > 0 {
		m, b, err := c.encryptPacket(data)
		if err != nil {
			return 0, err
		}
		if n, err := c.Conn.Write(b); err != nil {
			return n, err
		} else {
			n += m
			data = data[m:]
		}
	}
	return n, nil
}
