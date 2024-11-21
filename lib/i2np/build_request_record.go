package i2np

import (
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

/*
I2P I2NP BuildRequestRecord
https://geti2p.net/spec/i2np
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
| receive_tunnel    | our_ident         |
+----+----+----+----+                   +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                   +----+----+----+----+
|                   | next_tunnel       |
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

receive_tunnel :: TunnelId
                  length -> 4 bytes

our_ident :: Hash
             length -> 32 bytes

next_tunnel :: TunnelId
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

send_message_id :: Integer
                   length -> 4 bytes

padding :: Data
           length -> 29 bytes
           source -> random

total length: 222
*/

type (
	BuildRequestRecordElGamalAES [528]byte
	BuildRequestRecordElGamal    [528]byte
)

type BuildRequestRecord struct {
	ReceiveTunnel tunnel.TunnelID
	OurIdent      common.Hash
	NextTunnel    tunnel.TunnelID
	NextIdent     common.Hash
	LayerKey      session_key.SessionKey
	IVKey         session_key.SessionKey
	ReplyKey      session_key.SessionKey
	ReplyIV       [16]byte
	Flag          int
	RequestTime   time.Time
	SendMessageID int
	Padding       [29]byte
}

var ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA = errors.New("not enough i2np build request record data")

func ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error) {
	log.Debug("Reading BuildRequestRecord")
	build_request_record := BuildRequestRecord{}

	receive_tunnel, err := readBuildRequestRecordReceiveTunnel(data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReceiveTunnel")
		return build_request_record, err
	}
	build_request_record.ReceiveTunnel = receive_tunnel

	our_ident, err := readBuildRequestRecordOurIdent(data)
	if err != nil {
		log.WithError(err).Error("Failed to read OurIdent")
		return build_request_record, err
	}
	build_request_record.OurIdent = our_ident

	next_tunnel, err := readBuildRequestRecordNextTunnel(data)
	if err != nil {
		log.WithError(err).Error("Failed to read NextTunnel")
		return build_request_record, err
	}
	build_request_record.NextTunnel = next_tunnel

	next_ident, err := readBuildRequestRecordNextIdent(data)
	if err != nil {
		log.WithError(err).Error("Failed to read NextIdent")
		return build_request_record, err
	}
	build_request_record.NextIdent = next_ident

	layer_key, err := readBuildRequestRecordLayerKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to read LayerKey")
		return build_request_record, err
	}
	build_request_record.LayerKey = layer_key

	iv_key, err := readBuildRequestRecordIVKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to read IVKey")
		return build_request_record, err
	}
	build_request_record.IVKey = iv_key

	reply_key, err := readBuildRequestRecordReplyKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyKey")
		return build_request_record, err
	}
	build_request_record.ReplyKey = reply_key

	reply_iv, err := readBuildRequestRecordReplyIV(data)
	if err != nil {
		log.WithError(err).Error("Failed to read ReplyIV")
		return build_request_record, err
	}
	build_request_record.ReplyIV = reply_iv

	flag, err := readBuildRequestRecordFlag(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Flag")
		return build_request_record, err
	}
	build_request_record.Flag = flag

	request_time, err := readBuildRequestRecordRequestTime(data)
	if err != nil {
		log.WithError(err).Error("Failed to read RequestTime")
		return build_request_record, err
	}
	build_request_record.RequestTime = request_time

	send_message_id, err := readBuildRequestRecordSendMessageID(data)
	if err != nil {
		log.WithError(err).Error("Failed to read SendMessageID")
		return build_request_record, err
	}
	build_request_record.SendMessageID = send_message_id

	padding, err := readBuildRequestRecordPadding(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Padding")
		return build_request_record, err
	}
	build_request_record.Padding = padding

	log.Debug("BuildRequestRecord read successfully")
	return build_request_record, nil
}

func readBuildRequestRecordReceiveTunnel(data []byte) (tunnel.TunnelID, error) {
	if len(data) < 4 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	receive_tunnel := tunnel.TunnelID(
		common.Integer(data[0:4]).Int(),
	)

	log.WithFields(logrus.Fields{
		"at":              "i2np.readBuildRequestRecordReceiveTunnel",
		"receieve_tunnel": receive_tunnel,
	}).Debug("parsed_build_request_record_receive_tunnel")
	return receive_tunnel, nil
}

func readBuildRequestRecordOurIdent(data []byte) (common.Hash, error) {
	if len(data) < 36 {
		return common.Hash{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	hash := common.Hash{}
	copy(hash[:], data[4:36])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordOurIdent",
	}).Debug("parsed_build_request_record_our_ident")
	return hash, nil
}

func readBuildRequestRecordNextTunnel(data []byte) (tunnel.TunnelID, error) {
	if len(data) < 40 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	next_tunnel := tunnel.TunnelID(
		common.Integer(data[36:40]).Int(),
	)

	log.WithFields(logrus.Fields{
		"at":          "i2np.readBuildRequestRecordNextTunnel",
		"next_tunnel": next_tunnel,
	}).Debug("parsed_build_request_record_next_tunnel")
	return next_tunnel, nil
}

func readBuildRequestRecordNextIdent(data []byte) (common.Hash, error) {
	if len(data) < 72 {
		return common.Hash{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	hash := common.Hash{}
	copy(hash[:], data[40:72])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordNextIdent",
	}).Debug("parsed_build_request_record_next_ident")
	return hash, nil
}

func readBuildRequestRecordLayerKey(data []byte) (session_key.SessionKey, error) {
	if len(data) < 104 {
		return session_key.SessionKey{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	session_key := session_key.SessionKey{}
	copy(session_key[:], data[72:104])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordLayerKey",
	}).Debug("parsed_build_request_record_layer_key")
	return session_key, nil
}

func readBuildRequestRecordIVKey(data []byte) (session_key.SessionKey, error) {
	if len(data) < 136 {
		return session_key.SessionKey{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	session_key := session_key.SessionKey{}
	copy(session_key[:], data[104:136])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordIVKey",
	}).Debug("parsed_build_request_record_iv_key")
	return session_key, nil
}

func readBuildRequestRecordReplyKey(data []byte) (session_key.SessionKey, error) {
	if len(data) < 168 {
		return session_key.SessionKey{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	session_key := session_key.SessionKey{}
	copy(session_key[:], data[136:168])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordReplyKey",
	}).Debug("parsed_build_request_record_reply_key")
	return session_key, nil
}

func readBuildRequestRecordReplyIV(data []byte) ([16]byte, error) {
	if len(data) < 184 {
		return [16]byte{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	iv := [16]byte{}
	copy(iv[:], data[168:184])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordReplyIV",
	}).Debug("parsed_build_request_record_reply_iv")
	return iv, nil
}

func readBuildRequestRecordFlag(data []byte) (int, error) {
	if len(data) < 185 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	flag := common.Integer([]byte{data[185]}).Int()

	log.WithFields(logrus.Fields{
		"at":   "i2np.readBuildRequestRecordFlag",
		"flag": flag,
	}).Debug("parsed_build_request_record_flag")
	return flag, nil
}

func readBuildRequestRecordRequestTime(data []byte) (time.Time, error) {
	if len(data) < 189 {
		return time.Time{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	count := common.Integer(data[185:189]).Int()
	rtime := time.Unix(0, 0).Add(time.Duration(count) * time.Hour)

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordRequestTime",
	}).Debug("parsed_build_request_record_request_time")
	return rtime, nil
}

func readBuildRequestRecordSendMessageID(data []byte) (int, error) {
	if len(data) < 193 {
		return 0, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	send_message_id := common.Integer(data[189:193]).Int()

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordSendMessageID",
	}).Debug("parsed_build_request_record_send_message_id")
	return send_message_id, nil
}

func readBuildRequestRecordPadding(data []byte) ([29]byte, error) {
	if len(data) < 222 {
		return [29]byte{}, ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA
	}

	padding := [29]byte{}
	copy(padding[:], data[193:222])

	log.WithFields(logrus.Fields{
		"at": "i2np.readBuildRequestRecordPadding",
	}).Debug("parsed_build_request_record_padding")
	return padding, nil
}
