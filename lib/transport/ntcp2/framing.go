package ntcp2

import (
	"net"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// Frame an I2NP message for transmission over NTCP2
func FrameI2NPMessage(msg i2np.I2NPMessage) ([]byte, error) {
	// Convert I2NP message to bytes
	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Create a framed message with length prefix
	length := len(data)
	framedMessage := make([]byte, 4+length)
	copy(framedMessage[4:], data)

	// Write the length prefix
	framedMessage[0] = byte(length >> 24)
	framedMessage[1] = byte(length >> 16)
	framedMessage[2] = byte(length >> 8)
	framedMessage[3] = byte(length)

	return framedMessage, nil
}

// Unframe I2NP messages from NTCP2 data stream
func UnframeI2NPMessage(conn net.Conn) (i2np.I2NPMessage, error) {
	// Read the next message from the connection
	unframer := NewI2NPUnframer(conn)
	return unframer.ReadNextMessage()
}

// Stream-based unframing for continuous reading
type I2NPUnframer struct {
	conn net.Conn
}

func NewI2NPUnframer(conn net.Conn) *I2NPUnframer {
	return &I2NPUnframer{
		conn: conn,
	}
}

func (u *I2NPUnframer) ReadNextMessage() (i2np.I2NPMessage, error) {
	// Read the NTCP2 length prefix (4 bytes)
	lengthBuf := make([]byte, 4)
	if err := u.readFull(lengthBuf); err != nil {
		return nil, err
	}

	// Extract length from big-endian bytes
	length := int(lengthBuf[0])<<24 | int(lengthBuf[1])<<16 | int(lengthBuf[2])<<8 | int(lengthBuf[3])

	// Read the I2NP message data
	messageBuf := make([]byte, length)
	if err := u.readFull(messageBuf); err != nil {
		return nil, err
	}

	// Unmarshal the I2NP message
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(messageBuf); err != nil {
		return nil, err
	}

	return msg, nil
}

func (u *I2NPUnframer) readFull(buf []byte) error {
	// Read from the connection until the buffer is full
	for len(buf) > 0 {
		n, err := u.conn.Read(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

// Log the successful creation of the session
