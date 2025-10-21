package i2np

import (
	common "github.com/go-i2p/common/data"
	datalib "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// I2NP Header Reading Utilities
// Moved from: header.go

// ReadI2NPNTCPHeader reads an entire I2NP message and returns the parsed header
// with embedded encrypted data
func ReadI2NPNTCPHeader(data []byte) (I2NPNTCPHeader, error) {
	log.Debug("Reading I2NP NTCP Header")
	header := I2NPNTCPHeader{}

	if err := readHeaderType(data, &header); err != nil {
		return header, err
	}

	if err := readHeaderMessageID(data, &header); err != nil {
		return header, err
	}

	if err := readHeaderExpiration(data, &header); err != nil {
		return header, err
	}

	if err := readHeaderSize(data, &header); err != nil {
		return header, err
	}

	if err := readHeaderChecksum(data, &header); err != nil {
		return header, err
	}

	if err := readHeaderData(data, &header); err != nil {
		return header, err
	}

	log.WithFields(logger.Fields{
		"at": "i2np.ReadI2NPNTCPHeader",
	}).Debug("parsed_i2np_ntcp_header")
	return header, nil
}

// readHeaderType reads and validates the I2NP message type field.
func readHeaderType(data []byte, header *I2NPNTCPHeader) error {
	messageType, err := ReadI2NPType(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP type")
		return err
	}
	header.Type = messageType
	return nil
}

// readHeaderMessageID reads and validates the NTCP message ID field.
func readHeaderMessageID(data []byte, header *I2NPNTCPHeader) error {
	messageID, err := ReadI2NPNTCPMessageID(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP NTCP message ID")
		return err
	}
	header.MessageID = messageID
	return nil
}

// readHeaderExpiration reads and validates the message expiration timestamp.
func readHeaderExpiration(data []byte, header *I2NPNTCPHeader) error {
	messageDate, err := ReadI2NPNTCPMessageExpiration(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP NTCP message expiration")
		return err
	}
	header.Expiration = messageDate.Time()
	return nil
}

// readHeaderSize reads and validates the message size field.
func readHeaderSize(data []byte, header *I2NPNTCPHeader) error {
	messageSize, err := ReadI2NPNTCPMessageSize(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP NTCP message size")
		return err
	}
	header.Size = messageSize
	return nil
}

// readHeaderChecksum reads and validates the message checksum field.
func readHeaderChecksum(data []byte, header *I2NPNTCPHeader) error {
	messageChecksum, err := ReadI2NPNTCPMessageChecksum(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP NTCP message checksum")
		return err
	}
	header.Checksum = messageChecksum
	return nil
}

// readHeaderData reads and validates the message data payload.
func readHeaderData(data []byte, header *I2NPNTCPHeader) error {
	messageData, err := ReadI2NPNTCPData(data, header.Size)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP NTCP message data")
		return err
	}
	header.Data = messageData
	return nil
}

// ReadI2NPSecondGenTransportHeader reads an I2NP NTCP2 or SSU2 header
// When transmitted over [NTCP2] or [SSU2], the 16-byte standard header is not used.
// Only a 1-byte type, 4-byte message id, and a 4-byte expiration in seconds are included.
// The size is incorporated in the NTCP2 and SSU2 data packet formats.
// The checksum is not required since errors are caught in decryption.
func ReadI2NPSecondGenTransportHeader(dat []byte) (I2NPSecondGenTransportHeader, error) {
	header := I2NPSecondGenTransportHeader{}

	if len(dat) < 9 {
		return header, ERR_I2NP_NOT_ENOUGH_DATA
	}

	messageType, err := ReadI2NPType(dat)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP type")
		return header, err
	}
	header.Type = messageType

	messageID := datalib.Integer(dat[1:5])
	header.MessageID = messageID.Int()

	expiration := datalib.Date(dat[5:9])
	header.Expiration = expiration.Time()

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

	message_type, err := ReadI2NPType(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP type")
		return header, err
	} else {
		header.Type = message_type
	}

	message_date, err := ReadI2NPSSUMessageExpiration(data)
	if err != nil {
		log.WithError(err).Error("Failed to read I2NP SSU message expiration")
		return header, err
	} else {
		header.Expiration = message_date.Time()
	}
	log.WithFields(logger.Fields{
		"type": header.Type,
	}).Debug("Parsed I2NP SSU header")
	return header, nil
}

// ReadI2NPType reads the I2NP message type from data
func ReadI2NPType(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	message_type := datalib.Integer([]byte{data[0]})

	if (message_type.Int() >= 4 && message_type.Int() <= 9) ||
		(message_type.Int() >= 12 && message_type.Int() <= 17) {
		log.WithFields(logger.Fields{
			"at":   "i2np.ReadI2NPType",
			"type": message_type,
		}).Warn("unknown_i2np_type")
	}

	if message_type.Int() >= 224 && message_type.Int() <= 254 {
		log.WithFields(logger.Fields{
			"at":   "i2np.ReadI2NPType",
			"type": message_type,
		}).Warn("experimental_i2np_type")
	}

	if message_type.Int() == 255 {
		log.WithFields(logger.Fields{
			"at":   "i2np.ReadI2NPType",
			"type": message_type,
		}).Warn("reserved_i2np_type")
	}

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPType",
		"type": message_type,
	}).Debug("parsed_i2np_type")
	return message_type.Int(), nil
}

// ReadI2NPNTCPMessageID reads the message ID from NTCP data
func ReadI2NPNTCPMessageID(data []byte) (int, error) {
	if len(data) < 5 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	message_id := datalib.Integer(data[1:5])

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageID",
		"type": message_id,
	}).Debug("parsed_i2np_message_id")
	return message_id.Int(), nil
}

// ReadI2NPNTCPMessageExpiration reads the expiration from NTCP data
func ReadI2NPNTCPMessageExpiration(data []byte) (datalib.Date, error) {
	if len(data) < 13 {
		return datalib.Date{}, ERR_I2NP_NOT_ENOUGH_DATA
	}

	date := datalib.Date{}
	copy(date[:], data[5:13])

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageExpiration",
		"date": date,
	}).Debug("parsed_i2np_message_date")
	return date, nil
}

// ReadI2NPSSUMessageExpiration reads the expiration from SSU data
func ReadI2NPSSUMessageExpiration(data []byte) (datalib.Date, error) {
	if len(data) < 5 {
		return datalib.Date{}, ERR_I2NP_NOT_ENOUGH_DATA
	}

	date := datalib.Date{}
	copy(date[4:], data[1:5])

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPSSUMessageExpiration",
		"date": date,
	}).Debug("parsed_i2np_message_date")
	return date, nil
}

// ReadI2NPNTCPMessageSize reads the message size from NTCP data
func ReadI2NPNTCPMessageSize(data []byte) (int, error) {
	if len(data) < 15 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	size := datalib.Integer(data[13:15])

	log.WithFields(logger.Fields{
		"at":   "i2np.ReadI2NPNTCPMessageSize",
		"size": size,
	}).Debug("parsed_i2np_message_size")
	return size.Int(), nil
}

// ReadI2NPNTCPMessageChecksum reads the message checksum from NTCP data
func ReadI2NPNTCPMessageChecksum(data []byte) (int, error) {
	if len(data) < 16 {
		return 0, ERR_I2NP_NOT_ENOUGH_DATA
	}

	checksum := datalib.Integer(data[15:16])

	log.WithFields(logger.Fields{
		"at":       "i2np.ReadI2NPNTCPMessageCHecksum",
		"checksum": checksum,
	}).Debug("parsed_i2np_message_checksum")
	return checksum.Int(), nil
}

// ReadI2NPNTCPData reads the message data from NTCP payload
func ReadI2NPNTCPData(data []byte, size int) ([]byte, error) {
	if len(data) < 16+size {
		return []byte{}, ERR_I2NP_NOT_ENOUGH_DATA
	}
	log.WithField("data_size", size).Debug("Read I2NP NTCP message data")
	return data[16 : 16+size], nil
}

// Helper Functions for Creating Interface Implementations
// Moved from: processor.go

// CreateTunnelRecord creates a build request record with interface methods
func CreateTunnelRecord(receiveTunnel, nextTunnel tunnel.TunnelID,
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
		Key:  key,
		Data: data,
		Type: dataType,
	}
}
