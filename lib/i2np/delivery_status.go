package i2np

import (
	"time"
)

/*
I2P I2NP DeliveryStatus
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+----+----+----+----+
| msg_id            |           time_stamp                  |
+----+----+----+----+----+----+----+----+----+----+----+----+

msg_id :: Integer
       4 bytes
       unique ID of the message we deliver the DeliveryStatus for (see
       I2NPMessageHeader for details)

time_stamp :: Date
             8 bytes
             time the message was successfully created or delivered
*/

// DeliveryStatus is a lightweight representation of the I2NP DeliveryStatus
// payload (type 10), which confirms the successful delivery or creation of
// a message. It carries the 4-byte message ID and the 8-byte timestamp.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [DeliveryStatusMessage].
type DeliveryStatus struct {
	MessageID int
	Timestamp time.Time
}
