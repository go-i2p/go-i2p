package i2np

import (
	"time"

	"github.com/go-i2p/common/certificate"
)

/*
I2P I2NP Garlic
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
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
     encrypted data

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

// Garlic represents an I2NP Garlic message (type 11) containing one or more
// encrypted garlic cloves for anonymous message delivery. Each clove is
// addressed to a different hop, so a single Garlic message can carry a
// message through a tunnel without revealing the full path to any single
// router.
// See [I2P Spec: ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/ecies.rst) for the ECIES garlic message format.
// See also [GarlicClove], [GarlicBuilder], [GarlicProcessor].
type Garlic struct {
	Count       int
	Cloves      []GarlicClove
	Certificate certificate.Certificate
	MessageID   int
	Expiration  time.Time
}

// GetCloves returns the garlic cloves in the order they appear in the
// message. Each clove is processed by the router it is addressed to.
// See also [GarlicClove].
func (g *Garlic) GetCloves() []GarlicClove {
	return g.Cloves
}

// GetCloveCount returns the number of cloves in the message. This is the
// count field from the Garlic header and must match the number of cloves
// actually present.
func (g *Garlic) GetCloveCount() int {
	return g.Count
}

// Compile-time interface satisfaction check
var _ GarlicProcessor = (*Garlic)(nil)
