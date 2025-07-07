package i2np

import (
	"errors"

	"github.com/sirupsen/logrus"

	common "github.com/go-i2p/common/data"
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
type BuildResponseRecord struct {
	Hash       common.Hash
	RandomData [495]byte
	Reply      byte
}

var ERR_BUILD_RESPONSE_RECORD_NOT_ENOUGH_DATA = errors.New("not enough i2np build request record data")

func ReadBuildResponseRecord(data []byte) (BuildResponseRecord, error) {
	log.Debug("Reading BuildResponseRecord")
	build_response_record := BuildResponseRecord{}

	hash, err := readBuildResponseRecordHash(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Hash")
		return build_response_record, err
	}
	build_response_record.Hash = hash

	random_data, err := readBuildResponseRecordRandomData(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Random Data")
		return build_response_record, err
	}
	build_response_record.RandomData = random_data

	reply, err := readBuildResponseRecordReply(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Reply")
		return build_response_record, err
	}
	build_response_record.Reply = reply

	log.Debug("BuildResponseRecord read successfully")
	return build_response_record, nil
}

func readBuildResponseRecordHash(data []byte) (common.Hash, error) {
	if len(data) < 32 {
		return common.Hash{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	hash := common.Hash(data[0:32])

	log.WithFields(logrus.Fields{
		"at":   "i2np.readBuildResponseRecordHash",
		"hash": hash,
	}).Debug("parsed_build_response_record_hash")
	return hash, nil
}

func readBuildResponseRecordRandomData(data []byte) ([495]byte, error) {
	if len(data) < 527 {
		return [495]byte{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	random_data := [495]byte{}
	copy(random_data[:], data[32:527])

	log.WithFields(logrus.Fields{
		"at":          "i2np.readBuildResponseRandomData",
		"random_data": random_data,
	}).Debug("parsed_build_response_record_random_data")
	return random_data, nil
}

func readBuildResponseRecordReply(data []byte) (byte, error) {
	if len(data) < 528 {
		return byte(0), ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	reply := data[527]

	log.WithFields(logrus.Fields{
		"at":    "i2np.readBuildResponseReply",
		"reply": reply,
	}).Debug("parsed_build_response_record_reply")
	return reply, nil
}
