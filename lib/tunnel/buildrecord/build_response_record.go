package buildrecord

import (
	"errors"

	common "github.com/go-i2p/common/data"
)

/*
I2P I2NP BuildResponseRecord
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Accurate for version 0.9.65

Encrypted:

bytes 0-527 :: AES-encrypted record (note: same size as BuildRequestRecord)

Unencrypted:

+----+----+----+----+----+----+----+----+
|                                       |
+                                       +
|                                       |
+   SHA-256 Hash of following bytes     +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| random data...                        |
~                                       ~
|                                       |
+                                  +----+
|                                  | ret|
+----+----+----+----+----+----+----+----+

bytes 0-31   :: SHA-256 Hash of bytes 32-527
bytes 32-526 :: random data
byte  527    :: reply

total length: 528
*/

// ErrBuildResponseRecordNotEnoughData is returned when a byte slice is too short for a BuildResponseRecord field.
var ErrBuildResponseRecordNotEnoughData = errors.New("not enough build response record data")

/*
BuildResponseRecord struct contains a response to BuildRequestRecord
concerning the creation of one hop in the tunnel
*/
// BuildResponseRecord represents a single response record in a tunnel build reply, indicating whether a hop accepted or rejected the tunnel build request.
type BuildResponseRecord struct {
	Hash       common.Hash
	RandomData [495]byte
	Reply      byte
}
