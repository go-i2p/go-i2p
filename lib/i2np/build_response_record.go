package i2np

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
I2P I2NP BuildResponseRecord
https://geti2p.net/spec/i2np#buildresponserecord
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

type (
	BuildResponseRecordELGamalAES [528]byte
	BuildResponseRecordELGamal    [528]byte
)

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

// responseFieldParser pairs a field name with a closure that reads and assigns
// a single BuildResponseRecord field from raw data.
type responseFieldParser struct {
	name  string
	parse func([]byte, *BuildResponseRecord) error
}

// applyResponseParsers runs each parser in order, logging and returning
// on the first error. Mirrors applyFieldParsers for BuildRequestRecord.
func applyResponseParsers(data []byte, record *BuildResponseRecord, parsers []responseFieldParser) error {
	for _, p := range parsers {
		if err := p.parse(data, record); err != nil {
			log.WithError(err).Error("Failed to read " + p.name)
			return err
		}
	}
	return nil
}

// ReadBuildResponseRecord parses a BuildResponseRecord from the provided byte slice.
func ReadBuildResponseRecord(data []byte) (BuildResponseRecord, error) {
	log.WithFields(logger.Fields{"at": "ReadBuildResponseRecord"}).Debug("Reading BuildResponseRecord")
	record := BuildResponseRecord{}

	if err := applyResponseParsers(data, &record, []responseFieldParser{
		{"Hash", func(d []byte, r *BuildResponseRecord) error {
			v, err := readBuildResponseRecordHash(d)
			r.Hash = v
			return err
		}},
		{"Random Data", func(d []byte, r *BuildResponseRecord) error {
			v, err := readBuildResponseRecordRandomData(d)
			r.RandomData = v
			return err
		}},
		{"Reply", func(d []byte, r *BuildResponseRecord) error {
			v, err := readBuildResponseRecordReply(d)
			r.Reply = v
			return err
		}},
	}); err != nil {
		return record, err
	}

	log.WithFields(logger.Fields{"at": "ReadBuildResponseRecord"}).Debug("BuildResponseRecord read successfully")
	return record, nil
}

func readBuildResponseRecordHash(data []byte) (common.Hash, error) {
	hash, _, err := common.ReadHash(data)
	if err != nil {
		return common.Hash{}, ErrBuildResponseRecordNotEnoughData
	}

	log.WithFields(logger.Fields{
		"at":   "i2np.readBuildResponseRecordHash",
		"hash": hash,
	}).Debug("parsed_build_response_record_hash")
	return hash, nil
}

func readBuildResponseRecordRandomData(data []byte) ([495]byte, error) {
	if len(data) < 527 {
		return [495]byte{}, ErrBuildResponseRecordNotEnoughData
	}

	random_data := [495]byte{}
	copy(random_data[:], data[32:527])

	log.WithFields(logger.Fields{
		"at":          "i2np.readBuildResponseRandomData",
		"random_data": random_data,
	}).Debug("parsed_build_response_record_random_data")
	return random_data, nil
}

func readBuildResponseRecordReply(data []byte) (byte, error) {
	if len(data) < 528 {
		return byte(0), ErrBuildResponseRecordNotEnoughData
	}

	reply := data[527]

	log.WithFields(logger.Fields{
		"at":    "i2np.readBuildResponseReply",
		"reply": reply,
	}).Debug("parsed_build_response_record_reply")
	return reply, nil
}

// validateBuildResponseRecord performs basic validation of a build response record.
// It checks that the hash is non-zero and that SHA-256(random_data || reply_byte)
// matches the embedded hash. This is a standalone helper shared by all tunnel
// build reply types.
func validateBuildResponseRecord(record BuildResponseRecord) error {
	allZeros := true
	for _, b := range record.Hash {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return oops.Errorf("response record has empty hash")
	}

	// Verify SHA-256 hash: hash should be SHA256(random_data + reply_byte)
	data := make([]byte, 496)
	copy(data[0:495], record.RandomData[:])
	data[495] = record.Reply

	computedHash := types.SHA256(data)
	if computedHash != record.Hash {
		log.WithFields(logger.Fields{
			"expected": record.Hash,
			"computed": computedHash,
		}).Warn("Response record hash mismatch")
		return oops.Errorf("response record hash verification failed")
	}

	log.WithFields(logger.Fields{"at": "validateBuildResponseRecord"}).Debug("Response record validation passed")
	return nil
}
