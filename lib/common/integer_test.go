package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntegerBigEndian(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	integer := NewInteger(bytes)

	assert.Equal(integer.Int(), 1, "NewInteger() did not parse bytes big endian")
}

func TestWorksWithOneByte(t *testing.T) {
	assert := assert.New(t)

	integer := NewInteger([]byte{0x01})

	assert.Equal(integer.Int(), 1, "NewInteger() did not correctly parse single byte slice")
}

func TestIsZeroWithNoData(t *testing.T) {
	assert := assert.New(t)

	integer := NewInteger([]byte{})

	assert.Equal(integer.Int(), 0, "NewInteger() did not correctly parse zero length byte slice")
}
