package i2np

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/certificate"
	"github.com/samber/oops"
)

/*
I2P I2NP Garlic
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

Encrypted:

+----+----+----+----+----+----+----+----+
|      length       | data              |
+----+----+----+----+                   +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

length ::
       4 byte Integer
       number of bytes that follow 0 - 64 KB

data ::
     $length bytes
     ElGamal encrypted data

Unencrypted data:

+----+----+----+----+----+----+----+----+
| num|  clove 1                         |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|         clove 2 ...                   |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Certificate  |   Message_ID      |
+----+----+----+----+----+----+----+----+
          Expiration               |
+----+----+----+----+----+----+----+

num ::
     1 byte Integer number of GarlicCloves to follow

clove ::  a GarlicClove

Certificate :: always NULL in the current implementation (3 bytes total, all zeroes)

Message_ID :: 4 byte Integer

Expiration :: Date (8 bytes)
*/

// GarlicElGamal represents an ElGamal encrypted garlic message with proper structure
type GarlicElGamal struct {
	Length uint32
	Data   []byte
}

// NewGarlicElGamal creates a new GarlicElGamal from raw bytes
func NewGarlicElGamal(bytes []byte) (*GarlicElGamal, error) {
	if len(bytes) < 4 {
		return nil, oops.Errorf("insufficient data for GarlicElGamal: need at least 4 bytes for length, got %d", len(bytes))
	}

	length := binary.BigEndian.Uint32(bytes[0:4])

	if len(bytes) < int(4+length) {
		return nil, oops.Errorf("insufficient data for GarlicElGamal: length indicates %d bytes but only %d available", length, len(bytes)-4)
	}

	data := make([]byte, length)
	copy(data, bytes[4:4+length])

	return &GarlicElGamal{
		Length: length,
		Data:   data,
	}, nil
}

// Bytes serializes the GarlicElGamal to bytes
func (g *GarlicElGamal) Bytes() ([]byte, error) {
	if g == nil {
		return nil, oops.Errorf("cannot serialize nil GarlicElGamal")
	}

	result := make([]byte, 4+len(g.Data))
	binary.BigEndian.PutUint32(result[0:4], g.Length)
	copy(result[4:], g.Data)

	return result, nil
}

type Garlic struct {
	Count       int
	Cloves      []GarlicClove
	Certificate certificate.Certificate
	MessageID   int
	Expiration  time.Time
}

// GetCloves returns the garlic cloves
func (g *Garlic) GetCloves() []GarlicClove {
	return g.Cloves
}

// GetCloveCount returns the number of cloves
func (g *Garlic) GetCloveCount() int {
	return g.Count
}

// Compile-time interface satisfaction check
var _ GarlicProcessor = (*Garlic)(nil)
