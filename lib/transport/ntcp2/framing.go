package ntcp2

import (
	"fmt"
	"io"
	"net"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// Frame an I2NP message for transmission over NTCP2
func FrameI2NPMessage(msg i2np.I2NPMessage) ([]byte, error) {
	log.WithField("message_type", msg.Type()).Debug("Framing I2NP message")

	// Convert I2NP message to bytes
	data, err := msg.MarshalBinary()
	if err != nil {
		log.WithError(err).Error("Failed to marshal I2NP message")
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

	log.WithFields(map[string]interface{}{
		"message_type":   msg.Type(),
		"message_length": length,
		"framed_length":  len(framedMessage),
	}).Debug("I2NP message framed successfully")
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
	conn           net.Conn
	bytesRead      int // Track bytes read in last operation
	totalBytesRead int // Track cumulative bytes read
}

func NewI2NPUnframer(conn net.Conn) *I2NPUnframer {
	return &I2NPUnframer{
		conn:           conn,
		bytesRead:      0,
		totalBytesRead: 0,
	}
}

// BytesRead returns the number of bytes read during the last ReadNextMessage call
func (u *I2NPUnframer) BytesRead() int {
	return u.bytesRead
}

func (u *I2NPUnframer) ReadNextMessage() (i2np.I2NPMessage, error) {
	log.Debug("Reading next framed message from connection")

	// Reset byte counter for this read operation
	u.bytesRead = 0

	// Read the NTCP2 length prefix (4 bytes)
	lengthBuf := make([]byte, 4)
	if err := u.readFull(lengthBuf); err != nil {
		log.WithError(err).Error("Failed to read message length prefix")
		return nil, err
	}

	// Extract length from big-endian bytes
	length := int(lengthBuf[0])<<24 | int(lengthBuf[1])<<16 | int(lengthBuf[2])<<8 | int(lengthBuf[3])
	log.WithField("message_length", length).Debug("Read message length prefix")

	// Validate message length to prevent memory exhaustion attacks
	// NTCP2 limit is approximately 64KB - 20 = 65516 bytes per I2NP specification
	const maxI2NPMessageSize = 65516
	if length > maxI2NPMessageSize || length < 0 {
		log.WithFields(map[string]interface{}{
			"length":   length,
			"max_size": maxI2NPMessageSize,
		}).Error("Message length exceeds maximum allowed size")
		return nil, fmt.Errorf("message length %d exceeds max %d", length, maxI2NPMessageSize)
	}

	// Read the I2NP message data
	messageBuf := make([]byte, length)
	if err := u.readFull(messageBuf); err != nil {
		log.WithError(err).WithField("expected_length", length).Error("Failed to read message data")
		return nil, err
	}

	// Unmarshal the I2NP message
	msg := &i2np.BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(messageBuf); err != nil {
		log.WithError(err).WithField("message_length", length).Error("Failed to unmarshal I2NP message")
		return nil, err
	}

	log.WithFields(map[string]interface{}{
		"message_type":   msg.Type(),
		"message_length": length,
		"bytes_read":     u.bytesRead,
	}).Debug("Successfully read and unframed I2NP message")
	return msg, nil
}

func (u *I2NPUnframer) readFull(buf []byte) error {
	n, err := io.ReadFull(u.conn, buf)
	u.bytesRead += n
	u.totalBytesRead += n
	return err
}

// Log the successful creation of the session
