package i2np

import (
	"encoding/binary"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// I2NP Header Reading Utilities
// Moved from: header.go

// ReadI2NPNTCPHeader reads an entire I2NP message and returns the parsed header
// with embedded encrypted data
func ReadI2NPNTCPHeader(data []byte) (I2NPNTCPHeader, error) {
	log.WithFields(logger.Fields{"at": "ReadI2NPNTCPHeader"}).Debug("Reading I2NP NTCP Header")
	header := I2NPNTCPHeader{}

	if err := executeHeaderParsers(data, &header); err != nil {
		return header, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.ReadI2NPNTCPHeader",
	}).Debug("parsed_i2np_ntcp_header")
	return header, nil
}

// namedHeaderParser pairs a field name with a parser closure for I2NP NTCP headers.
type namedHeaderParser struct {
	name  string
	parse func([]byte, *I2NPNTCPHeader) error
}

// executeHeaderParsers sequentially executes named header field parsers,
// logging and returning on the first error encountered.
func executeHeaderParsers(data []byte, header *I2NPNTCPHeader) error {
	parsers := []namedHeaderParser{
		{"I2NP type", func(d []byte, h *I2NPNTCPHeader) error {
			v, err := ReadI2NPType(d)
			h.Type = v
			return err
		}},
		{"I2NP NTCP message ID", func(d []byte, h *I2NPNTCPHeader) error {
			v, err := ReadI2NPNTCPMessageID(d)
			h.MessageID = v
			return err
		}},
		{"I2NP NTCP message expiration", func(d []byte, h *I2NPNTCPHeader) error {
			v, err := ReadI2NPNTCPMessageExpiration(d)
			h.Expiration = v.Time()
			return err
		}},
		{"I2NP NTCP message size", func(d []byte, h *I2NPNTCPHeader) error {
			v, err := ReadI2NPNTCPMessageSize(d)
			h.Size = v
			return err
		}},
		{"I2NP NTCP message checksum", func(d []byte, h *I2NPNTCPHeader) error {
			v, err := ReadI2NPNTCPMessageChecksum(d)
			h.Checksum = v
			return err
		}},
		{"I2NP NTCP message data", func(d []byte, h *I2NPNTCPHeader) error {
			v, err := ReadI2NPNTCPData(d, h.Size)
			h.Data = v
			return err
		}},
	}

	for _, p := range parsers {
		if err := p.parse(data, header); err != nil {
			log.WithError(err).WithField("field", p.name).Error("failed to read field")
			return err
		}
	}
	return nil
}

// MarshalSecondGenTransportHeader serializes an I2NP NTCP2/SSU2 header into
// a 9-byte buffer: type (1 byte) + msg_id (4 bytes, big-endian) +
// short_expiration (4 bytes, seconds since epoch, big-endian).
// This is the inverse of ReadI2NPSecondGenTransportHeader.
func MarshalSecondGenTransportHeader(header I2NPSecondGenTransportHeader) ([]byte, error) {
	data := make([]byte, 9)
	data[0] = byte(header.Type)
	binary.BigEndian.PutUint32(data[1:5], uint32(header.MessageID))
	binary.BigEndian.PutUint32(data[5:9], uint32(header.Expiration.Unix()))
	return data, nil
}

// ReadI2NPSecondGenTransportHeader reads an I2NP NTCP2 or SSU2 header
// When transmitted over [NTCP2] or [SSU2], the 16-byte standard header is not used.
// Only a 1-byte type, 4-byte message id, and a 4-byte expiration in seconds are included.
// The size is incorporated in the NTCP2 and SSU2 data packet formats.
// The checksum is not required since errors are caught in decryption.
func ReadI2NPSecondGenTransportHeader(dat []byte) (I2NPSecondGenTransportHeader, error) {
	header := I2NPSecondGenTransportHeader{}

	if len(dat) < 9 {
		return header, ErrI2NPNotEnoughData
	}

	messageType, err := ReadI2NPType(dat)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP type")
		return header, err
	}
	header.Type = messageType

	messageID := common.Integer(dat[1:5])
	header.MessageID = messageID.Int()

	// NTCP2/SSU2 uses a 4-byte expiration in seconds since epoch (not the
	// 8-byte millisecond Date used in standard I2NP headers). Read as uint32
	// and convert to time.Time directly.
	expirationSeconds := binary.BigEndian.Uint32(dat[5:9])
	header.Expiration = time.Unix(int64(expirationSeconds), 0)

	log.WithFields(logger.Fields{
		"at":         "i2np.ReadI2NPSecondGenTransportHeader",
		"type":       header.Type,
		"messageID":  header.MessageID,
		"expiration": header.Expiration,
	}).Debug("parsed_i2np_second_gen_transport_header")

	return header, nil
}

// ReadI2NPSSUHeader reads an I2NP SSU header
func ReadI2NPSSUHeader(data []byte) (I2NPSSUHeader, error) {
	header := I2NPSSUHeader{}

	messageType, err := ReadI2NPType(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP type")
		return header, err
	} else {
		header.Type = messageType
	}

	messageDate, err := ReadI2NPSSUMessageExpiration(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP SSU message expiration")
		return header, err
	} else {
		header.Expiration = messageDate.Time()
	}
	log.WithFields(logger.Fields{
		"type": header.Type,
	}).Debug("Parsed I2NP SSU header")
	return header, nil
}

// ReadI2NPType reads the I2NP message type from data
// L-2 Consolidation: Unified logging logic into single computed log call
func ReadI2NPType(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, ErrI2NPNotEnoughData
	}

	messageType := common.Integer([]byte{data[0]})
	typeValue := messageType.Int()
	logLevel, logMessage := getI2NPTypeLogLevel(typeValue)

	// Single log call with computed level and message
	fields := logger.Fields{
		"at":   "i2np.ReadI2NPType",
		"type": messageType,
	}
	switch logLevel {
	case i2npLogLevelWarn:
		log.WithFields(fields).Warn(logMessage)
	default:
		log.WithFields(fields).Debug(logMessage)
	}

	return typeValue, nil
}

// i2npLogLevel is a tiny enum for the logging branch used by ReadI2NPType.
type i2npLogLevel int

const (
	i2npLogLevelDebug i2npLogLevel = iota
	i2npLogLevelWarn
)

// getI2NPTypeLogLevel returns the log level and message for a parsed I2NP type.
func getI2NPTypeLogLevel(typeValue int) (i2npLogLevel, string) {
	logLevel := i2npLogLevelDebug
	logMessage := "parsed_i2np_type"

	// Types 4-9 and 12-17 are currently unassigned in the I2NP spec.
	// Log at Debug level instead of Warn to avoid spurious warnings for
	// types that may be assigned in future spec revisions.
	if (typeValue >= 4 && typeValue <= 9) || (typeValue >= 12 && typeValue <= 17) {
		logMessage = "unassigned_i2np_type"
	} else if typeValue >= 224 && typeValue <= 254 {
		logLevel = i2npLogLevelWarn
		logMessage = "experimental_i2np_type"
	} else if typeValue == 255 {
		logLevel = i2npLogLevelWarn
		logMessage = "reserved_i2np_type"
	}

	return logLevel, logMessage
}

// ReadI2NPNTCPMessageID reads the message ID from NTCP data
func ReadI2NPNTCPMessageID(data []byte) (int, error) {
	if len(data) < 5 {
		return 0, ErrI2NPNotEnoughData
	}

	messageID := common.Integer(data[1:5])

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageID",
		"type": messageID,
	}).Debug("parsed_i2np_message_id")
	return messageID.Int(), nil
}

// ReadI2NPNTCPMessageExpiration reads the expiration from NTCP data
func ReadI2NPNTCPMessageExpiration(data []byte) (common.Date, error) {
	if len(data) < 13 {
		return common.Date{}, ErrI2NPNotEnoughData
	}

	date, _, err := common.ReadDate(data[5:])
	if err != nil {
		return common.Date{}, err
	}

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageExpiration",
		"date": date,
	}).Debug("parsed_i2np_message_date")
	return date, nil
}

// ReadI2NPSSUMessageExpiration reads the expiration from SSU data
// Note: Short expiration is a 4-byte unsigned integer that will wrap around
// on February 7, 2106. As of that date, an offset must be added to get the
// correct time. See I2NP specification for details.
func ReadI2NPSSUMessageExpiration(data []byte) (common.Date, error) {
	if len(data) < 5 {
		return common.Date{}, ErrI2NPNotEnoughData
	}

	// SSU short expiration is a 4-byte unsigned integer in seconds since epoch.
	// Date stores milliseconds since epoch as an 8-byte big-endian integer,
	// so we must convert seconds to milliseconds before encoding.
	seconds := binary.BigEndian.Uint32(data[1:5])
	milliseconds := uint64(seconds) * 1000

	date := common.Date{}
	binary.BigEndian.PutUint64(date[:], milliseconds)

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPSSUMessageExpiration",
		"date": date,
	}).Debug("parsed_i2np_message_date")
	return date, nil
}

// ReadI2NPNTCPMessageSize reads the message size from NTCP data
func ReadI2NPNTCPMessageSize(data []byte) (int, error) {
	if len(data) < 15 {
		return 0, ErrI2NPNotEnoughData
	}

	size := common.Integer(data[13:15])

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageSize",
		"size": size,
	}).Debug("parsed_i2np_message_size")
	return size.Int(), nil
}

// ReadI2NPNTCPMessageChecksum reads the message checksum from NTCP data
func ReadI2NPNTCPMessageChecksum(data []byte) (int, error) {
	if len(data) < 16 {
		return 0, ErrI2NPNotEnoughData
	}

	checksum := common.Integer(data[15:16])

	log.WithFields(logger.Fields{
		"at":       "i2np.ReadI2NPNTCPMessageCHecksum",
		"checksum": checksum,
	}).Debug("parsed_i2np_message_checksum")
	return checksum.Int(), nil
}

// ReadI2NPNTCPData reads the message data from NTCP payload
func ReadI2NPNTCPData(data []byte, size int) ([]byte, error) {
	if len(data) < 16+size {
		return []byte{}, ErrI2NPNotEnoughData
	}
	log.WithField("data_size", size).Debug("Read I2NP NTCP message data")
	return data[16 : 16+size], nil
}

// Helper Functions for Creating Interface Implementations
// Moved from: processor.go

// CreateTunnelRecord creates a build request record with interface methods
func CreateTunnelRecord(receiveTunnel, nextTunnel buildrecord.TunnelID,
	ourIdent, nextIdent common.Hash,
) TunnelIdentifier {
	return &BuildRequestRecord{
		ReceiveTunnel: receiveTunnel,
		NextTunnel:    nextTunnel,
		OurIdent:      ourIdent,
		NextIdent:     nextIdent,
	}
}

// CreateDatabaseQuery creates a database lookup with interface methods
func CreateDatabaseQuery(key, from common.Hash, flags byte) DatabaseReader {
	return &DatabaseLookup{
		Key:   key,
		From:  from,
		Flags: flags,
	}
}

// CreateDatabaseEntry creates a database store with interface methods
func CreateDatabaseEntry(key common.Hash, data []byte, dataType byte) DatabaseWriter {
	return &DatabaseStore{
		BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeDatabaseStore),
		Key:             key,
		Data:            data,
		StoreType:       dataType,
	}
}

// ByteReader provides a cursor-style interface for sequential byte reading,
// similar to bytes.Reader in the Go standard library. Each read operation
// advances the offset, eliminating the need for callers to track positions
// manually. This prevents off-by-one errors and simplifies parsing logic.
//
// Error handling follows Go's io.Reader pattern: on error, the reader is not
// advanced, allowing callers to inspect the failed position.
type ByteReader struct {
	data   []byte
	offset int
}

// NewByteReader creates a new ByteReader positioned at offset 0.
func NewByteReader(data []byte) *ByteReader {
	return &ByteReader{
		data:   data,
		offset: 0,
	}
}

// Offset returns the current read position.
func (br *ByteReader) Offset() int {
	return br.offset
}

// Remaining returns the number of bytes left to read.
func (br *ByteReader) Remaining() int {
	if br.offset > len(br.data) {
		return 0
	}
	return len(br.data) - br.offset
}

// ReadByte reads a single byte and advances the offset. Returns ErrI2NPNotEnoughData
// if there are no bytes remaining.
func (br *ByteReader) ReadByte() (byte, error) {
	if br.offset >= len(br.data) {
		return 0, ErrI2NPNotEnoughData
	}
	b := br.data[br.offset]
	br.offset++
	return b, nil
}

// ReadInt reads a 4-byte big-endian integer and advances the offset.
// Returns ErrI2NPNotEnoughData if fewer than 4 bytes remain.
func (br *ByteReader) ReadInt() (int, error) {
	if br.offset+4 > len(br.data) {
		return 0, ErrI2NPNotEnoughData
	}
	v := binary.BigEndian.Uint32(br.data[br.offset : br.offset+4])
	br.offset += 4
	return int(v), nil
}

// ReadInt64 reads an 8-byte big-endian integer and advances the offset.
// Returns ErrI2NPNotEnoughData if fewer than 8 bytes remain.
func (br *ByteReader) ReadInt64() (int64, error) {
	if br.offset+8 > len(br.data) {
		return 0, ErrI2NPNotEnoughData
	}
	v := binary.BigEndian.Uint64(br.data[br.offset : br.offset+8])
	br.offset += 8
	return int64(v), nil
}

// ReadDate reads an 8-byte I2P Date (millisecond timestamp) and advances
// the offset. Returns ErrI2NPNotEnoughData if fewer than 8 bytes remain.
func (br *ByteReader) ReadDate() (common.Date, error) {
	data, err := br.ReadBytes(8)
	if err != nil {
		return common.Date{}, err
	}
	date, _, err := common.ReadDate(data)
	return date, err
}

// ReadBytes reads n bytes and advances the offset. Returns ErrI2NPNotEnoughData
// if fewer than n bytes remain. The returned slice is a view into the
// underlying data; modifications affect the original buffer.
func (br *ByteReader) ReadBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrI2NPNotEnoughData
	}
	if br.offset+n > len(br.data) {
		return nil, ErrI2NPNotEnoughData
	}
	result := br.data[br.offset : br.offset+n]
	br.offset += n
	return result, nil
}

// ReadHash reads a 32-byte router hash and advances the offset.
// Returns ErrI2NPNotEnoughData if fewer than 32 bytes remain.
func (br *ByteReader) ReadHash() (common.Hash, error) {
	data, err := br.ReadBytes(32)
	if err != nil {
		return common.Hash{}, err
	}
	var h common.Hash
	copy(h[:], data)
	return h, nil
}

// Peek returns the next n bytes without advancing the offset.
// Returns ErrI2NPNotEnoughData if fewer than n bytes remain.
func (br *ByteReader) Peek(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrI2NPNotEnoughData
	}
	if br.offset+n > len(br.data) {
		return nil, ErrI2NPNotEnoughData
	}
	return br.data[br.offset : br.offset+n], nil
}

// Reset resets the reader to the beginning.
func (br *ByteReader) Reset() {
	br.offset = 0
}

// processHopReplyCode handles the reply code from a single hop in a tunnel build reply.
// It returns (success, error) where success indicates if the hop accepted the tunnel.
// The logPrefix is prepended to log messages for context (e.g., "Variable tunnel " or "").
func processHopReplyCode(hopIndex int, replyCode byte, logPrefix string) (bool, error) {
	log.WithFields(logger.Fields{
		"hop_index":  hopIndex,
		"reply_code": replyCode,
	}).Debug(logPrefix + "Processing hop response")

	switch replyCode {
	case TunnelBuildReplySuccess:
		log.WithField("hop_index", hopIndex).Debug(logPrefix + "Hop accepted tunnel build request")
		return true, nil

	case TunnelBuildReplyReject:
		log.WithField("hop_index", hopIndex).Warn(logPrefix + "Hop rejected tunnel build request")
		return false, oops.Errorf("hop %d: rejected request", hopIndex)

	case TunnelBuildReplyOverload:
		log.WithField("hop_index", hopIndex).Warn(logPrefix + "Hop is overloaded")
		return false, oops.Errorf("hop %d: router overloaded", hopIndex)

	case TunnelBuildReplyBandwidth:
		log.WithField("hop_index", hopIndex).Warn(logPrefix + "Hop has insufficient bandwidth")
		return false, oops.Errorf("hop %d: insufficient bandwidth", hopIndex)

	case TunnelBuildReplyInvalid:
		log.WithField("hop_index", hopIndex).Warn(logPrefix + "Hop received invalid request data")
		return false, oops.Errorf("hop %d: invalid request data", hopIndex)

	case TunnelBuildReplyExpired:
		log.WithField("hop_index", hopIndex).Warn(logPrefix + "Hop request has expired")
		return false, oops.Errorf("hop %d: request expired", hopIndex)

	default:
		log.WithFields(logger.Fields{
			"hop_index":  hopIndex,
			"reply_code": replyCode,
		}).Warn(logPrefix + "Hop returned unknown reply code")
		return false, oops.Errorf("hop %d: unknown reply code %d", hopIndex, replyCode)
	}
}

// DetermineBuildResult evaluates tunnel build outcome based on success counts and first encountered error.
// L-1 Consolidation: Shared by tunnel_build_reply.go and variable_tunnel_build_reply.go.
// tunnelType should be lowercase (e.g., "tunnel", "variable tunnel") for error messages.
func DetermineBuildResult(successCount, recordCount int, firstError error, tunnelType string) error {
	if successCount == recordCount {
		log.WithFields(logger.Fields{
			"at":   "DetermineBuildResult",
			"type": tunnelType,
		}).Debug(tunnelType + " build successful - all hops accepted")
		return nil
	}

	if firstError != nil {
		return oops.Wrapf(firstError, "%s build failed", tunnelType)
	}

	return oops.Errorf("%s build failed: only %d of %d hops accepted", tunnelType, successCount, recordCount)
}

// ValidateRecordCount validates that Count field matches actual record count.
// L-4 Consolidation: Shared by variable_tunnel_build_reply.go and short_tunnel_build_reply.go.
// tunnelTypeName is used in log messages (e.g., "VariableTunnelBuildReply", "ShortTunnelBuildReply")
func ValidateRecordCount(countField, recordCount int, tunnelTypeName string) error {
	if countField != recordCount {
		return oops.Errorf("count mismatch: Count field is %d but have %d records", countField, recordCount)
	}

	if recordCount == 0 {
		log.WithFields(logger.Fields{"at": "ValidateRecordCount"}).Warn(tunnelTypeName + " has no response records")
		return oops.Errorf("tunnel build failed: no response records")
	}

	return nil
}
