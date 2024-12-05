package offline_signature

import (
	. "github.com/go-i2p/go-i2p/lib/common/data"
)

const (
	OFFLINE_SIGNATURE_EXPIRY_SIZE  = 4
	OFFLINE_SIGNATURE_SIGTYPE_SIZE = 2
)

/*
[OfflineSignature]
Accurate for version 0.9.63

Description
This is an optional part of the LeaseSet2Header. Also used in streaming and I2CP. Supported as of 0.9.38; see proposal 123 for more information.
Contents

Contains an expiration, a sigtype and transient SigningPublicKey, and a Signature.

+----+----+----+----+----+----+----+----+
|     expires       | sigtype |         |
+----+----+----+----+----+----+         +
|       transient_public_key            |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|           signature                   |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

expires :: 4 byte date
           length -> 4 bytes
           Seconds since the epoch, rolls over in 2106.

sigtype :: 2 byte type of the transient_public_key
           length -> 2 bytes

transient_public_key :: SigningPublicKey
                        length -> As inferred from the sigtype

signature :: Signature
             length -> As inferred from the sigtype of the signing public key
                       in the Destination that preceded this offline signature.
             Signature of expires timestamp, transient sig type, and public key,
             by the destination public key.

https://geti2p.net/spec/common-structures#struct-offlinesignature

*/

// OfflineSignature represents the optional part of the LeaseSet2Header in I2P.
// It contains an expiration timestamp, signature type, transient public key, and a signature.
type OfflineSignature struct {
	Expires            Integer
	SigType            Integer
	TransientPublicKey []byte
	Signature          []byte
}
