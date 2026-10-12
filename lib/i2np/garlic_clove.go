package i2np

import (
	"time"

	"github.com/go-i2p/common/certificate"
)

/*
I2P I2NP GarlicClove
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Accurate for version 0.9.28

Unencrypted:

+----+----+----+----+----+----+----+----+
| Delivery Instructions                 |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| I2NP Message                          |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|    Clove ID       |     Expiration
+----+----+----+----+----+----+----+----+
                    | Certificate  |
+----+----+----+----+----+----+----+

Delivery Instructions :: as defined below
       Length varies but is typically 1, 33, or 37 bytes

I2NP Message :: Any I2NP Message

Clove ID :: 4 byte Integer

Expiration :: Date (8 bytes)

Certificate :: Always NULL in the current implementation (3 bytes total, all zeroes)
*/

// GarlicClove represents a single clove within an I2NP Garlic message.
// Each clove carries delivery instructions, an embedded I2NP message, a
// unique clove ID, an expiration timestamp, and a certificate (always NULL
// in the current implementation). Cloves are the unit of anonymous delivery
// in the Garlic format.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [Garlic], [GarlicCloveDeliveryInstructions].
type GarlicClove struct {
	DeliveryInstructions GarlicCloveDeliveryInstructions
	Message              Message
	CloveID              int
	Expiration           time.Time
	Certificate          certificate.Certificate
}
