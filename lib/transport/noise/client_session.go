package noise

import (
	"encoding/binary"
	"errors"
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
	if err := c.RunClientHandshake(); err != nil {
		return 0, err
	}
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	if !c.handshakeComplete {
		return 0, errors.New("internal error")
	}
	n, err := c.writePacketLocked(b)
	return n, err
}

func (c *NoiseSession) writePacketLocked(data []byte) (int, error) {
	var n int
	if len(data) == 0 { //special case to answer when everything is ok during handshake
		if _, err := c.Conn.Write(make([]byte, 2)); err != nil {
			return 0, err
		}
	}
	for len(data) > 0 {
		/*m := len(data)
		packet := c.InitializePacket()
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
		b := c.encryptIfNeeded(packet)
		c.freeBlock(packet)
		////fmt.Println(hex.EncodeToString(b))
		if _, err := c.conn.Write(b); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
		*/
	}
	return n, nil
}

func initNegotiationData(negotiationData []byte) []byte {
	if negotiationData != nil {
		return negotiationData
	}
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) //version
	negotiationData[2] = NOISE_DH_CURVE25519
	negotiationData[3] = NOISE_CIPHER_AESGCM
	negotiationData[4] = NOISE_HASH_BLAKE2b
	return negotiationData
}
