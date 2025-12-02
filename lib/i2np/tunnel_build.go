package i2np

import (
	"github.com/samber/oops"
)

/*
I2P I2NP TunnelBuild
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
| Record 0 ...                          |

|                                       |
+----+----+----+----+----+----+----+----+
| Record 1 ...                          |

~ .....                                 ~
|                                       |
+----+----+----+----+----+----+----+----+
| Record 7 ...                          |

|                                       |
+----+----+----+----+----+----+----+----+

Just 8 BuildRequestRecords attached together
record size: 528 bytes
total size: 8*528 = 4224 bytes
*/

// TunnelBuild represents the raw 8 build request records
type TunnelBuild [8]BuildRequestRecord

// TunnelBuildMessage wraps TunnelBuild to implement I2NPMessage interface
type TunnelBuildMessage struct {
	*BaseI2NPMessage
	Records TunnelBuild
}

// GetBuildRecords returns the build request records
func (t *TunnelBuild) GetBuildRecords() []BuildRequestRecord {
	return t[:]
}

// GetRecordCount returns the number of build records
func (t *TunnelBuild) GetRecordCount() int {
	return 8
}

// NewTunnelBuilder creates a new TunnelBuild and returns it as TunnelBuilder interface
func NewTunnelBuilder(records [8]BuildRequestRecord) TunnelBuilder {
	tb := TunnelBuild(records)
	return &tb
}

// NewTunnelBuildMessage creates a new TunnelBuild I2NP message
//
// SPECIFICATION COMPLIANCE NOTE:
// According to I2P specification (https://geti2p.net/spec/i2np), BuildRequestRecords
// MUST be encrypted before transmission using either:
//   - ElGamal-2048 encryption (legacy format, 528 bytes)
//   - ECIES-X25519-AEAD-Ratchet encryption (modern format, I2P 0.9.44+)
//
// CURRENT LIMITATION:
// This implementation currently creates CLEARTEXT records (222 bytes + 306 padding = 528 bytes).
// For specification-compliant tunnel building, use EncryptBuildRequestRecord() from build_record_crypto.go
// which implements proper ECIES-X25519-AEAD encryption.
//
// For specification-compliant tunnel building, encryption must be added using:
//  1. Recipient router's encryption public key (from RouterInfo)
//  2. ECIES-X25519-AEAD encryption (see build_record_crypto.go)
//  3. Proper padding and formatting per specification
//
// Use EncryptBuildRequestRecord() function (defined in build_record_crypto.go) that takes:
//   - BuildRequestRecord (cleartext)
//   - Recipient RouterInfo (for encryption public key)
//   - Returns encrypted 528-byte record
//
// This method is suitable for:
//   - Local testing with cooperating routers that accept cleartext
//   - Internal message structure creation before encryption
//   - Unit testing of serialization logic
//
// DO NOT USE for production tunnel building without implementing encryption first.
func NewTunnelBuildMessage(records [8]BuildRequestRecord) *TunnelBuildMessage {
	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_TUNNEL_BUILD),
		Records:         TunnelBuild(records),
	}

	// Serialize cleartext records (NOT specification-compliant for network transmission)
	// Each record: 222 bytes cleartext + 306 bytes padding = 528 bytes total
	data := make([]byte, 8*528)
	for i := 0; i < 8; i++ {
		cleartext := records[i].Bytes() // 222 bytes cleartext per I2P spec
		copy(data[i*528:i*528+222], cleartext)
		// Remaining 306 bytes: zero padding (spec requires random padding for encrypted records)
	}
	msg.SetData(data)

	return msg
}

// GetBuildRecords implements TunnelBuilder interface
func (msg *TunnelBuildMessage) GetBuildRecords() []BuildRequestRecord {
	return msg.Records[:]
}

// GetRecordCount implements TunnelBuilder interface
func (msg *TunnelBuildMessage) GetRecordCount() int {
	return 8
}

// MarshalBinary serializes the TunnelBuild message using BaseI2NPMessage
func (msg *TunnelBuildMessage) MarshalBinary() ([]byte, error) {
	return msg.BaseI2NPMessage.MarshalBinary()
}

// UnmarshalBinary deserializes the TunnelBuild message
//
// SPECIFICATION COMPLIANCE NOTE:
// According to I2P specification, BuildRequestRecords in TunnelBuild messages are
// encrypted with ECIES-X25519-AEAD. This implementation assumes CLEARTEXT
// records (for testing or from trusted sources).
//
// For specification-compliant processing of network messages:
//  1. Decrypt each 528-byte chunk using DecryptBuildRequestRecord() from build_record_crypto.go
//  2. This function uses local router's private encryption key
//  3. Verifies AEAD authentication and extracts 222-byte cleartext
//  4. Parse using ReadBuildRequestRecord()
//
// CURRENT LIMITATION:
// This method parses cleartext records directly from the 528-byte chunks without decryption.
// Encrypted records from production I2P routers will FAIL to parse correctly.
//
// Use DecryptBuildRequestRecord() (defined in build_record_crypto.go) that takes:
//   - 528-byte encrypted record
//   - Local router's decryption private key
//   - Returns decrypted BuildRequestRecord
func (msg *TunnelBuildMessage) UnmarshalBinary(data []byte) error {
	if err := msg.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return oops.Wrapf(err, "failed to unmarshal base I2NP message")
	}

	recordData := msg.GetData()
	if len(recordData) != 8*528 {
		return oops.Errorf("invalid TunnelBuild data size: expected %d bytes, got %d", 8*528, len(recordData))
	}

	// Parse each 528-byte chunk as cleartext BuildRequestRecord
	// WARNING: Does NOT handle encrypted records (non-compliant with I2P spec for network messages)
	for i := 0; i < 8; i++ {
		record, err := ReadBuildRequestRecord(recordData[i*528 : (i+1)*528])
		if err != nil {
			return oops.Wrapf(err, "failed to parse build request record %d", i)
		}
		msg.Records[i] = record
	}

	return nil
}

// Compile-time interface satisfaction checks
var (
	_ TunnelBuilder = (*TunnelBuild)(nil)
	_ TunnelBuilder = (*TunnelBuildMessage)(nil)
	_ I2NPMessage   = (*TunnelBuildMessage)(nil)
)
