package i2np

import "encoding/binary"

// Serialize produces the spec-compliant wire-format clove:
// DeliveryInstructions (variable) + 9-byte short header (type||msgID||exp) + body.
func (c GarlicClove) Serialize() []byte {
	header := make([]byte, 9)
	header[0] = byte(c.Message.Type())
	binary.BigEndian.PutUint32(header[1:5], uint32(c.Message.MessageID()))
	binary.BigEndian.PutUint32(header[5:9], uint32(c.Expiration.Unix()))
	payload, _ := c.Message.MarshalBinary()
	return append(header, payload...)
}
