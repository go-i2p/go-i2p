package i2np

/*
I2P I2NP Data
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Accurate for version 0.9.28

+----+----+----+----+----+-//-+
| length            | data... |
+----+----+----+----+----+-//-+

length ::
       4 bytes
       length of the payload

data ::
     $length bytes
     actual payload of this message
*/

// Data represents the payload portion of an I2NP Data message (type 20).
// It holds the length and raw bytes of the data being delivered through a
// tunnel. This type is used when parsing the inner payload after the
// length prefix has been read.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [DataMessage].
type Data struct {
	Length int
	Data   []byte
}
