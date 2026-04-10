package i2np

import (
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
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
	Records   TunnelBuild
	encrypted bool // true when records have been encrypted for network transmission
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

// newTunnelBuildMessage creates a new TunnelBuild I2NP message
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
func newTunnelBuildMessage(records [8]BuildRequestRecord) *TunnelBuildMessage {
	log.WithFields(logger.Fields{
		"at":           "newTunnelBuildMessage",
		"record_count": 8,
	}).Debug("Creating new TunnelBuild message")

	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
		Records:         TunnelBuild(records),
	}

	// Serialize cleartext records (NOT specification-compliant for network transmission)
	// Each record: 222 bytes cleartext + 306 bytes random padding = 528 bytes total
	data := make([]byte, 8*528)
	for i := 0; i < 8; i++ {
		cleartext := records[i].Bytes() // 222 bytes cleartext per I2P spec
		copy(data[i*528:i*528+222], cleartext)
		// Fill remaining 306 bytes with random padding so unused bytes are
		// indistinguishable from encrypted data (spec requirement).
		if _, err := rand.Read(data[i*528+222 : (i+1)*528]); err != nil {
			log.WithFields(logger.Fields{
				"at":     "newTunnelBuildMessage",
				"record": i,
			}).Warn("Failed to generate random padding for record")
		}
	}
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":        "newTunnelBuildMessage",
		"data_size": len(data),
	}).Debug("TunnelBuild message created successfully (cleartext, requires encryption)")

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

// MarshalBinary serializes the TunnelBuild message using BaseI2NPMessage.
// Logs a warning if the records have not been encrypted, as cleartext
// build records are not specification-compliant for network transmission.
func (msg *TunnelBuildMessage) MarshalBinary() ([]byte, error) {
	if !msg.encrypted {
		log.WithFields(logger.Fields{
			"at": "TunnelBuildMessage.MarshalBinary",
		}).Warn("Serializing cleartext TunnelBuild records — not safe for network transmission")
	}
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

// validateTunnelBuildDataSize checks if the data size matches expected 8*528 bytes.
func validateTunnelBuildDataSize(recordData []byte) error {
	expected := 8 * 528
	if len(recordData) == expected {
		return nil
	}
	log.WithFields(logger.Fields{
		"at":            "UnmarshalBinary",
		"expected_size": expected,
		"actual_size":   len(recordData),
	}).Error("Invalid TunnelBuild data size")
	return oops.Errorf("invalid TunnelBuild data size: expected %d bytes, got %d", expected, len(recordData))
}

// parseBuildRequestRecords parses cleartext BuildRequestRecords from record data.
func parseBuildRequestRecords(recordData []byte) ([8]BuildRequestRecord, error) {
	var records [8]BuildRequestRecord
	log.WithFields(logger.Fields{
		"at": "UnmarshalBinary",
	}).Debug("Parsing build request records (cleartext)")

	for i := 0; i < 8; i++ {
		record, err := ReadBuildRequestRecord(recordData[i*528 : (i+1)*528])
		if err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"at":           "UnmarshalBinary",
				"record_index": i,
			}).Error("Failed to parse build request record")
			return records, oops.Wrapf(err, "failed to parse build request record %d", i)
		}
		records[i] = record
	}
	return records, nil
}

// UnmarshalBinary parses a TunnelBuildMessage from the provided byte slice, populating the base I2NP header and the fixed set of 8 build request records.
func (msg *TunnelBuildMessage) UnmarshalBinary(data []byte) error {
	log.WithFields(logger.Fields{
		"at":        "UnmarshalBinary",
		"data_size": len(data),
	}).Debug("Unmarshaling TunnelBuild message")

	if err := msg.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		log.WithError(err).Error("Failed to unmarshal base I2NP message")
		return oops.Wrapf(err, "failed to unmarshal base I2NP message")
	}

	recordData := msg.GetData()
	if err := validateTunnelBuildDataSize(recordData); err != nil {
		return err
	}

	records, err := parseBuildRequestRecords(recordData)
	if err != nil {
		return err
	}
	msg.Records = records

	log.WithFields(logger.Fields{
		"at":           "UnmarshalBinary",
		"record_count": 8,
	}).Debug("TunnelBuild message unmarshaled successfully")

	return nil
}

// NewEncryptedTunnelBuildMessage creates a new TunnelBuild I2NP message with encrypted records.
//
// Each BuildRequestRecord is encrypted using ECIES-X25519-AEAD encryption against
// the corresponding hop's RouterInfo. This produces specification-compliant 528-byte
// encrypted records suitable for network transmission.
//
// Parameters:
//   - records: The 8 cleartext BuildRequestRecords
//   - recipientRouterInfos: The RouterInfo for each hop (one per record)
//
// Returns the encrypted TunnelBuildMessage or an error if encryption fails.
func NewEncryptedTunnelBuildMessage(records [8]BuildRequestRecord, recipientRouterInfos [8]router_info.RouterInfo) (*TunnelBuildMessage, error) {
	log.WithFields(logger.Fields{
		"at":           "NewEncryptedTunnelBuildMessage",
		"record_count": 8,
	}).Debug("Creating encrypted TunnelBuild message")

	msg := &TunnelBuildMessage{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
		Records:         TunnelBuild(records),
		encrypted:       true,
	}

	data := make([]byte, 8*528)
	for i := 0; i < 8; i++ {
		encrypted, err := EncryptBuildRequestRecord(records[i], recipientRouterInfos[i])
		if err != nil {
			return nil, oops.Wrapf(err, "failed to encrypt build request record %d", i)
		}
		copy(data[i*528:(i+1)*528], encrypted[:])
	}
	msg.SetData(data)

	log.WithFields(logger.Fields{
		"at":        "NewEncryptedTunnelBuildMessage",
		"data_size": len(data),
	}).Debug("Encrypted TunnelBuild message created successfully")

	return msg, nil
}

// UnmarshalEncryptedBinary deserializes and decrypts a TunnelBuild message.
//
// Each 528-byte record is decrypted using ECIES-X25519-AEAD decryption with
// the local router's private key. Only the record addressed to us (identified
// by matching identity hash prefix) will decrypt successfully; other records
// will fail decryption and are left as zero-value records.
//
// Parameters:
//   - data: The raw I2NP message bytes
//   - privateKey: Our router's 32-byte X25519 private encryption key
//
// Returns an error if the base message or the targeted record cannot be parsed.
func (msg *TunnelBuildMessage) UnmarshalEncryptedBinary(data, privateKey []byte) error {
	log.WithFields(logger.Fields{
		"at":        "UnmarshalEncryptedBinary",
		"data_size": len(data),
	}).Debug("Unmarshaling encrypted TunnelBuild message")

	if err := msg.BaseI2NPMessage.UnmarshalBinary(data); err != nil {
		return oops.Wrapf(err, "failed to unmarshal base I2NP message")
	}

	recordData := msg.GetData()
	if len(recordData) != 8*528 {
		return oops.Errorf("invalid TunnelBuild data size: expected %d bytes, got %d", 8*528, len(recordData))
	}

	decryptedCount := 0
	for i := 0; i < 8; i++ {
		var encryptedRecord [528]byte
		copy(encryptedRecord[:], recordData[i*528:(i+1)*528])

		record, err := DecryptBuildRequestRecord(encryptedRecord, privateKey)
		if err != nil {
			// This record is not addressed to us or failed decryption — skip it
			log.WithFields(logger.Fields{
				"at":           "UnmarshalEncryptedBinary",
				"record_index": i,
			}).Debug("Record decryption failed (not addressed to us or invalid)")
			continue
		}
		msg.Records[i] = record
		decryptedCount++
	}

	log.WithFields(logger.Fields{
		"at":              "UnmarshalEncryptedBinary",
		"decrypted_count": decryptedCount,
		"total_records":   8,
	}).Debug("Encrypted TunnelBuild message unmarshaled")

	return nil
}

// Compile-time interface satisfaction checks
var (
	_ TunnelBuilder = (*TunnelBuild)(nil)
	_ TunnelBuilder = (*TunnelBuildMessage)(nil)
	_ I2NPMessage   = (*TunnelBuildMessage)(nil)
)
