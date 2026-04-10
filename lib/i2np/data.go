package i2np

/*
I2P I2NP Data
https://geti2p.net/spec/i2np
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

// Data represents an I2NP Data message used to encapsulate an arbitrary payload for delivery through a tunnel.
type Data struct {
	Length int
	Data   []byte
}
