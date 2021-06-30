package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIntegerBigEndian(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	integer, err := NewInteger(bytes)
	assert.Nil(err)

	assert.Equal(integer.Value(), 1, "Integer() did not parse bytes big endian")

	checkbytes := integer.Bytes()

	assert.Equal(bytes, checkbytes, "IntegerBytes() did not match original bytes")
}

func TestWorksWithOneByte(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00}
	integer, err := NewInteger(bytes)
	assert.Nil(err)

	assert.Equal(integer.Value(), 0, "Integer() did not correctly parse single byte slice")

	checkbytes := integer.Bytes()

	assert.Equal(bytes, checkbytes, "IntegerBytes() did not match original bytes")
}
