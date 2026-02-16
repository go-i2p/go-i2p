package i2np

import (
	"errors"
)

// I2NP Message Type Constants
// Moved from: header.go
const (
	I2NP_MESSAGE_TYPE_DATABASE_STORE              = 1
	I2NP_MESSAGE_TYPE_DATABASE_LOOKUP             = 2
	I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY       = 3
	I2NP_MESSAGE_TYPE_DELIVERY_STATUS             = 10
	I2NP_MESSAGE_TYPE_GARLIC                      = 11
	I2NP_MESSAGE_TYPE_TUNNEL_DATA                 = 18
	I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY              = 19
	I2NP_MESSAGE_TYPE_DATA                        = 20
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD                = 21
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY          = 22
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD       = 23
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY = 24
	I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD          = 25
	I2NP_MESSAGE_TYPE_SHORT_TUNNEL_BUILD_REPLY    = 26
)

// I2NP Error Constants
// These use errors.New (not oops.Errorf) so callers can match them with errors.Is().
// Moved from: header.go, build_request_record.go, build_response_record.go, database_lookup.go
var (
	ERR_I2NP_NOT_ENOUGH_DATA                  = errors.New("not enough i2np header data")
	ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA  = errors.New("not enough i2np build request record data")
	ERR_BUILD_RESPONSE_RECORD_NOT_ENOUGH_DATA = errors.New("not enough i2np build response record data")
	ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA       = errors.New("not enough i2np database lookup data")
	ERR_DATABASE_SEARCH_REPLY_NOT_ENOUGH_DATA = errors.New("not enough i2np database search reply data")
	ERR_DATABASE_LOOKUP_INVALID_SIZE          = errors.New("database lookup excluded peers size exceeds protocol limit")
	ERR_I2NP_MESSAGE_EXPIRED                  = errors.New("i2np message has expired")
)

// Build record size constants per the I2P specification.
// Standard (ElGamal/ECIES long) records are 528 bytes on the wire.
// Short (ECIES) records are 218 bytes on the wire (added in 0.9.49).
// Standard cleartext (before encryption) is 222 bytes.
// Short cleartext (ECIES short) is 154 bytes (218 - 16 toPeer - 32 ephKey - 16 MAC).
const (
	StandardBuildRecordSize         = 528 // Encrypted on-wire size for standard/variable tunnel build records
	ShortBuildRecordSize            = 218 // Encrypted on-wire size for short tunnel build records (ECIES)
	StandardBuildRecordCleartextLen = 222 // Cleartext length for standard ElGamal build request records
	ShortBuildRecordCleartextLen    = 154 // Cleartext length for short ECIES build request records (218 - 64)
	ShortRecordHeaderSize           = 64  // toPeer(16) + ephemeralKey(32) + MAC(16)
	DefaultExpirationSeconds        = 480 // Default tunnel expiration: 8 minutes
)

// Default expiration tolerance for clock skew (5 minutes into the past)
// This allows for reasonable clock differences between I2P routers while
// still rejecting clearly expired messages.
const DefaultExpirationTolerance = 5 * 60 // 5 minutes in seconds
