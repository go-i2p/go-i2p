package i2np

import (
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

/*
I2P I2NP BuildRequestRecord
https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst
Accurate for version 0.9.28

ElGamal and AES encrypted:

+----+----+----+----+----+----+----+----+
| encrypted data...                     |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

encrypted_data :: ElGamal and AES encrypted data
                  length -> 528

total length: 528

ElGamal encrypted:

+----+----+----+----+----+----+----+----+
| toPeer                                |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| encrypted data...                     |
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

toPeer :: First 16 bytes of the SHA-256 Hash of the peer's RouterIdentity
          length -> 16 bytes

encrypted_data :: ElGamal-2048 encrypted data (see notes)
                  length -> 512

total length: 528

Cleartext:

+----+----+----+----+----+----+----+----+
| receiveTunnel    | our_ident         |
+----+----+----+----+                   +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                   +----+----+----+----+
|                   | nextTunnel       |
+----+----+----+----+----+----+----+----+
| next_ident                            |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| layer_key                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| iv_key                                |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| reply_key                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
| reply_iv                              |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|flag| request_time      | send_msg_id
+----+----+----+----+----+----+----+----+
     |                                  |
+----+                                  +
|         29 bytes padding              |
+                                       +
|                                       |
+                             +----+----+
|                             |
+----+----+----+----+----+----+

receiveTunnel :: TunnelId
                  length -> 4 bytes

our_ident :: Hash
             length -> 32 bytes

nextTunnel :: TunnelId
               length -> 4 bytes

next_ident :: Hash
              length -> 32 bytes

layer_key :: SessionKey
             length -> 32 bytes

iv_key :: SessionKey
          length -> 32 bytes

reply_key :: SessionKey
             length -> 32 bytes

reply_iv :: data
            length -> 16 bytes

flag :: Integer
        length -> 1 byte

request_time :: Integer
                length -> 4 bytes
                Hours since the epoch, i.e. current time / 3600

sendMessageID :: Integer
                   length -> 4 bytes

padding :: Data
           length -> 29 bytes
           source -> random

total length: 222
*/

// BuildRequestRecord is a type alias for buildrecord.BuildRequestRecord,
// the canonical definition. Both lib/tunnel and lib/i2np share this type
// without import cycles. Parsing, serialization, and accessor methods are
// defined in lib/tunnel/buildrecord.
type BuildRequestRecord = buildrecord.BuildRequestRecord

// ReadShortBuildRequestRecord parses the 154-byte STBM cleartext payload into a BuildRequestRecord.
// It delegates to buildrecord.ReadShortBuildRequestRecord and translates any error to
// ErrBuildRequestRecordNotEnoughData. The original buildrecord error is discarded
// so callers get one uniform error for every parse failure; the I2P spec does not
// distinguish between parse-failure modes.
//
// The long (222-byte cleartext / 528-byte encrypted) record parser that used to
// sit beside this one was removed with the deprecated long-record path — see the
// "Tunnel build message coverage (known gap)" section of this package's doc.go.
func ReadShortBuildRequestRecord(data []byte) (BuildRequestRecord, error) {
	rec, err := buildrecord.ReadShortBuildRequestRecord(data)
	if err != nil {
		return rec, ErrBuildRequestRecordNotEnoughData
	}
	return rec, nil
}

// Compile-time interface satisfaction checks
var (
	_ TunnelIdentifier   = (*BuildRequestRecord)(nil)
	_ HashProvider       = (*BuildRequestRecord)(nil)
	_ SessionKeyProvider = (*BuildRequestRecord)(nil)
)
