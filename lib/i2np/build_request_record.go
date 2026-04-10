package i2np

import (
	"time"

	"github.com/go-i2p/logger"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

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

// BuildRequestRecord represents a single record in a tunnel build request, containing the cryptographic keys and routing information needed to construct one hop in a tunnel.
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

// ReadBuildRequestRecord parses a BuildRequestRecord from the provided byte slice.
func ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error) {
	log.WithFields(logger.Fields{"at": "ReadBuildRequestRecord"}).Debug("Reading BuildRequestRecord")

	record := BuildRequestRecord{}

	if err := parseTunnelIdentifiers(data, &record); err != nil {
		return record, err
	}

	if err := parseSessionKeys(data, &record); err != nil {
		return record, err
	}

	if err := parseMetadata(data, &record); err != nil {
		return record, err
	}

	log.WithFields(logger.Fields{"at": "ReadBuildRequestRecord"}).Debug("BuildRequestRecord read successfully")
	return record, nil
}

// fieldParser pairs a field name with a closure that reads and assigns a single
// BuildRequestRecord field from raw data.
type fieldParser struct {
	name  string
	parse func([]byte, *BuildRequestRecord) error
}

// applyFieldParsers runs each parser in order, logging and returning on the first error.
func applyFieldParsers(data []byte, record *BuildRequestRecord, parsers []fieldParser) error {
	for _, p := range parsers {
		if err := p.parse(data, record); err != nil {
			log.WithError(err).Error("Failed to read " + p.name)
			return err
		}
	}
	return nil
}

// parseTunnelIdentifiers extracts tunnel and identity information from the record data.
func parseTunnelIdentifiers(data []byte, record *BuildRequestRecord) error {
	return applyFieldParsers(data, record, []fieldParser{
		{"ReceiveTunnel", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordReceiveTunnel(d)
			r.ReceiveTunnel = v
			return err
		}},
		{"OurIdent", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordOurIdent(d)
			r.OurIdent = v
			return err
		}},
		{"NextTunnel", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordNextTunnel(d)
			r.NextTunnel = v
			return err
		}},
		{"NextIdent", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordNextIdent(d)
			r.NextIdent = v
			return err
		}},
	})
}

// parseSessionKeys extracts all cryptographic keys from the record data.
func parseSessionKeys(data []byte, record *BuildRequestRecord) error {
	return applyFieldParsers(data, record, []fieldParser{
		{"LayerKey", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordLayerKey(d)
			r.LayerKey = v
			return err
		}},
		{"IVKey", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordIVKey(d)
			r.IVKey = v
			return err
		}},
		{"ReplyKey", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordReplyKey(d)
			r.ReplyKey = v
			return err
		}},
		{"ReplyIV", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordReplyIV(d)
			r.ReplyIV = v
			return err
		}},
	})
}

// parseMetadata extracts flags, timestamps, and padding from the record data.
func parseMetadata(data []byte, record *BuildRequestRecord) error {
	return applyFieldParsers(data, record, []fieldParser{
		{"Flag", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordFlag(d)
			r.Flag = v
			return err
		}},
		{"RequestTime", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordRequestTime(d)
			r.RequestTime = v
			return err
		}},
		{"SendMessageID", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordSendMessageID(d)
			r.SendMessageID = v
			return err
		}},
		{"Padding", func(d []byte, r *BuildRequestRecord) error {
			v, err := readBuildRequestRecordPadding(d)
			r.Padding = v
			return err
		}},
	})
}

func readBuildRequestRecordReceiveTunnel(data []byte) (tunnel.TunnelID, error) {
	if len(data) < 4 {
		return 0, ErrBuildRequestRecordNotEnoughData
	}

	receive_tunnel := tunnel.TunnelID(
		common.Integer(data[0:4]).Int(),
	)

	log.WithFields(logger.Fields{
		"at":             "i2np.readBuildRequestRecordReceiveTunnel",
		"receive_tunnel": receive_tunnel,
	}).Debug("parsed_build_request_record_receive_tunnel")
	return receive_tunnel, nil
}

func readBuildRequestRecordOurIdent(data []byte) (common.Hash, error) {
	if len(data) < 36 {
		return common.Hash{}, ErrBuildRequestRecordNotEnoughData
	}

	hash, _, err := common.ReadHash(data[4:])
	if err != nil {
		return common.Hash{}, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordOurIdent",
	}).Debug("parsed_build_request_record_our_ident")
	return hash, nil
}

func readBuildRequestRecordNextTunnel(data []byte) (tunnel.TunnelID, error) {
	if len(data) < 40 {
		return 0, ErrBuildRequestRecordNotEnoughData
	}

	next_tunnel := tunnel.TunnelID(
		common.Integer(data[36:40]).Int(),
	)

	log.WithFields(logger.Fields{
		"at":          "i2np.readBuildRequestRecordNextTunnel",
		"next_tunnel": next_tunnel,
	}).Debug("parsed_build_request_record_next_tunnel")
	return next_tunnel, nil
}

func readBuildRequestRecordNextIdent(data []byte) (common.Hash, error) {
	if len(data) < 72 {
		return common.Hash{}, ErrBuildRequestRecordNotEnoughData
	}

	hash, _, err := common.ReadHash(data[40:])
	if err != nil {
		return common.Hash{}, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordNextIdent",
	}).Debug("parsed_build_request_record_next_ident")
	return hash, nil
}

func readBuildRequestRecordLayerKey(data []byte) (session_key.SessionKey, error) {
	if len(data) < 104 {
		return session_key.SessionKey{}, ErrBuildRequestRecordNotEnoughData
	}

	session_key, _, err := session_key.ReadSessionKey(data[72:])
	if err != nil {
		return session_key, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordLayerKey",
	}).Debug("parsed_build_request_record_layer_key")
	return session_key, nil
}

func readBuildRequestRecordIVKey(data []byte) (session_key.SessionKey, error) {
	if len(data) < 136 {
		return session_key.SessionKey{}, ErrBuildRequestRecordNotEnoughData
	}

	session_key, _, err := session_key.ReadSessionKey(data[104:])
	if err != nil {
		return session_key, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordIVKey",
	}).Debug("parsed_build_request_record_iv_key")
	return session_key, nil
}

func readBuildRequestRecordReplyKey(data []byte) (session_key.SessionKey, error) {
	if len(data) < 168 {
		return session_key.SessionKey{}, ErrBuildRequestRecordNotEnoughData
	}

	session_key, _, err := session_key.ReadSessionKey(data[136:])
	if err != nil {
		return session_key, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordReplyKey",
	}).Debug("parsed_build_request_record_reply_key")
	return session_key, nil
}

func readBuildRequestRecordReplyIV(data []byte) ([16]byte, error) {
	if len(data) < 184 {
		return [16]byte{}, ErrBuildRequestRecordNotEnoughData
	}

	iv := [16]byte{}
	copy(iv[:], data[168:184])

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordReplyIV",
	}).Debug("parsed_build_request_record_reply_iv")
	return iv, nil
}

func readBuildRequestRecordFlag(data []byte) (int, error) {
	if len(data) < 185 {
		return 0, ErrBuildRequestRecordNotEnoughData
	}

	flag := common.Integer([]byte{data[184]}).Int()

	log.WithFields(logger.Fields{
		"at":   "i2np.readBuildRequestRecordFlag",
		"flag": flag,
	}).Debug("parsed_build_request_record_flag")
	return flag, nil
}

func readBuildRequestRecordRequestTime(data []byte) (time.Time, error) {
	if len(data) < 189 {
		return time.Time{}, ErrBuildRequestRecordNotEnoughData
	}

	count := common.Integer(data[185:189]).Int()
	rtime := time.Unix(0, 0).Add(time.Duration(count) * time.Hour)

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordRequestTime",
	}).Debug("parsed_build_request_record_request_time")
	return rtime, nil
}

func readBuildRequestRecordSendMessageID(data []byte) (int, error) {
	if len(data) < 193 {
		return 0, ErrBuildRequestRecordNotEnoughData
	}

	send_message_id := common.Integer(data[189:193]).Int()

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordSendMessageID",
	}).Debug("parsed_build_request_record_send_message_id")
	return send_message_id, nil
}

func readBuildRequestRecordPadding(data []byte) ([29]byte, error) {
	if len(data) < 222 {
		return [29]byte{}, ErrBuildRequestRecordNotEnoughData
	}

	padding := [29]byte{}
	copy(padding[:], data[193:222])

	log.WithFields(logger.Fields{
		"at": "i2np.readBuildRequestRecordPadding",
	}).Debug("parsed_build_request_record_padding")
	return padding, nil
}

// GetReceiveTunnel returns the receive tunnel ID
func (b *BuildRequestRecord) GetReceiveTunnel() tunnel.TunnelID {
	return b.ReceiveTunnel
}

// GetNextTunnel returns the next tunnel ID
func (b *BuildRequestRecord) GetNextTunnel() tunnel.TunnelID {
	return b.NextTunnel
}

// GetOurIdent returns our identity hash
func (b *BuildRequestRecord) GetOurIdent() common.Hash {
	return b.OurIdent
}

// GetNextIdent returns the next identity hash
func (b *BuildRequestRecord) GetNextIdent() common.Hash {
	return b.NextIdent
}

// GetReplyKey returns the reply session key
func (b *BuildRequestRecord) GetReplyKey() session_key.SessionKey {
	return b.ReplyKey
}

// GetLayerKey returns the layer session key
func (b *BuildRequestRecord) GetLayerKey() session_key.SessionKey {
	return b.LayerKey
}

// GetIVKey returns the IV session key
func (b *BuildRequestRecord) GetIVKey() session_key.SessionKey {
	return b.IVKey
}

// Bytes serializes the BuildRequestRecord to its cleartext 222-byte representation.
// The caller is responsible for encrypting this data.
func (b *BuildRequestRecord) Bytes() []byte {
	data := make([]byte, 222)

	// ReceiveTunnel (4 bytes)
	if tunnelInt, err := common.NewIntegerFromInt(int(b.ReceiveTunnel), 4); err == nil {
		copy(data[0:4], tunnelInt.Bytes())
	}

	// OurIdent (32 bytes)
	copy(data[4:36], b.OurIdent[:])

	// NextTunnel (4 bytes)
	if tunnelInt, err := common.NewIntegerFromInt(int(b.NextTunnel), 4); err == nil {
		copy(data[36:40], tunnelInt.Bytes())
	}

	// NextIdent (32 bytes)
	copy(data[40:72], b.NextIdent[:])

	// LayerKey (32 bytes)
	copy(data[72:104], b.LayerKey[:])

	// IVKey (32 bytes)
	copy(data[104:136], b.IVKey[:])

	// ReplyKey (32 bytes)
	copy(data[136:168], b.ReplyKey[:])

	// ReplyIV (16 bytes)
	copy(data[168:184], b.ReplyIV[:])

	// Flag (1 byte)
	data[184] = byte(b.Flag)

	// RequestTime (4 bytes) - hours since epoch
	hours := int(b.RequestTime.Unix() / 3600)
	if timeInt, err := common.NewIntegerFromInt(hours, 4); err == nil {
		copy(data[185:189], timeInt.Bytes())
	}

	// SendMessageID (4 bytes)
	if msgInt, err := common.NewIntegerFromInt(b.SendMessageID, 4); err == nil {
		copy(data[189:193], msgInt.Bytes())
	}

	// Padding (29 bytes)
	copy(data[193:222], b.Padding[:])

	log.WithFields(logger.Fields{"at": "Bytes"}).Debug("BuildRequestRecord serialized to 222 bytes")
	return data
}

// ShortBytes serializes the BuildRequestRecord to the 218-byte ECIES short record
// wire format as defined in the I2P specification (proposal 157, since 0.9.49).
//
// Short build records use a more compact layout than the standard 222-byte
// ElGamal cleartext. Keys (LayerKey, IVKey, ReplyKey) are derived via HKDF
// rather than transmitted explicitly, saving significant space.
//
// On-wire format (218 bytes total):
//
//	toPeer:         16 bytes - truncated SHA-256 of peer's RouterIdentity
//	ephemeral key:  32 bytes - X25519 public key (placeholder pre-encryption)
//	encrypted data: 170 bytes - AEAD(cleartext 154 bytes) + 16-byte MAC
//
// Cleartext payload layout (154 bytes):
//
//	receive_tunnel:  4 bytes [0:4]
//	next_tunnel:     4 bytes [4:8]
//	next_ident:     32 bytes [8:40]
//	flag:            1 byte  [40] + 2 unused bytes [41:43]
//	layer_enc_type:  1 byte  [43]
//	request_time:    4 bytes [44:48] (minutes since epoch)
//	expiration:      4 bytes [48:52] (seconds)
//	send_message_id: 4 bytes [52:56]
//	options/padding: 98 bytes [56:154]
//
// The caller is responsible for applying ECIES encryption.
func (b *BuildRequestRecord) ShortBytes() []byte {
	data := make([]byte, ShortBuildRecordSize)

	// toPeer: first 16 bytes of peer's identity hash
	copy(data[0:16], b.OurIdent[:16])

	// Ephemeral X25519 key placeholder (32 bytes at offset 16)
	// Filled in during ECIES encryption; zeroed for now.

	// Cleartext payload starts at offset 48 (after toPeer + ephemeral key)
	const payloadOff = 48

	// receive_tunnel (4 bytes)
	if tunnelInt, err := common.NewIntegerFromInt(int(b.ReceiveTunnel), 4); err == nil {
		copy(data[payloadOff:payloadOff+4], tunnelInt.Bytes())
	}

	// next_tunnel (4 bytes)
	if tunnelInt, err := common.NewIntegerFromInt(int(b.NextTunnel), 4); err == nil {
		copy(data[payloadOff+4:payloadOff+8], tunnelInt.Bytes())
	}

	// next_ident (32 bytes)
	copy(data[payloadOff+8:payloadOff+40], b.NextIdent[:])

	// flag (1 byte) + 2 unused bytes
	data[payloadOff+40] = byte(b.Flag)

	// layer_enc_type (1 byte) - 0 = default (AES256/CBC+HMAC)
	data[payloadOff+43] = 0

	// request_time (4 bytes) - minutes since epoch (not hours like standard)
	minutes := int(b.RequestTime.Unix() / 60)
	if timeInt, err := common.NewIntegerFromInt(minutes, 4); err == nil {
		copy(data[payloadOff+44:payloadOff+48], timeInt.Bytes())
	}

	// expiration (4 bytes) - default 480 seconds (8 minutes)
	if expInt, err := common.NewIntegerFromInt(DefaultExpirationSeconds, 4); err == nil {
		copy(data[payloadOff+48:payloadOff+52], expInt.Bytes())
	}

	// send_message_id (4 bytes)
	if msgInt, err := common.NewIntegerFromInt(b.SendMessageID, 4); err == nil {
		copy(data[payloadOff+52:payloadOff+56], msgInt.Bytes())
	}

	// options/padding: remaining bytes [56:154] already zeroed
	// MAC space: [154:170] already zeroed (filled by AEAD encryption)

	log.WithFields(logger.Fields{"at": "ShortBytes"}).Debug("BuildRequestRecord serialized to 218-byte short ECIES format")
	return data
}

// ReadShortBuildRequestRecord parses the 154-byte STBM cleartext payload into a BuildRequestRecord.
// The STBM cleartext uses a compact layout: cryptographic keys (LayerKey, IVKey, ReplyKey)
// are absent and must be derived via HKDF by the caller.
//
// Cleartext layout (154 bytes):
//
//	[0:4]    receive_tunnel (4 bytes)
//	[4:8]    next_tunnel    (4 bytes)
//	[8:40]   next_ident     (32 bytes)
//	[40]     flag           (1 byte)
//	[44:48]  request_time   (4 bytes, minutes since epoch)
//	[52:56]  send_message_id (4 bytes)
func ReadShortBuildRequestRecord(data []byte) (BuildRequestRecord, error) {
	if len(data) < ShortBuildRecordCleartextLen {
		return BuildRequestRecord{}, ErrBuildRequestRecordNotEnoughData
	}

	record := BuildRequestRecord{}
	record.ReceiveTunnel = tunnel.TunnelID(common.Integer(data[0:4]).Int())
	record.NextTunnel = tunnel.TunnelID(common.Integer(data[4:8]).Int())
	nextIdent, _, err := common.ReadHash(data[8:])
	if err != nil {
		return BuildRequestRecord{}, ErrBuildRequestRecordNotEnoughData
	}
	record.NextIdent = nextIdent
	record.Flag = int(data[40])
	minutesSinceEpoch := common.Integer(data[44:48]).Int()
	record.RequestTime = time.Unix(int64(minutesSinceEpoch)*60, 0)
	record.SendMessageID = common.Integer(data[52:56]).Int()

	log.WithFields(logger.Fields{"at": "ReadShortBuildRequestRecord"}).Debug("ReadShortBuildRequestRecord: parsed 154-byte STBM cleartext")
	return record, nil
}

// Compile-time interface satisfaction checks
var (
	_ TunnelIdentifier   = (*BuildRequestRecord)(nil)
	_ HashProvider       = (*BuildRequestRecord)(nil)
	_ SessionKeyProvider = (*BuildRequestRecord)(nil)
)
