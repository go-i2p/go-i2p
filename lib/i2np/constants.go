package i2np

import "errors"

// I2NP Message Type Constants
// Moved from: header.go
const (
	I2NPMessageTypeDatabaseStore            = 1
	I2NPMessageTypeDatabaseLookup           = 2
	I2NPMessageTypeDatabaseSearchReply      = 3
	I2NPMessageTypeDeliveryStatus           = 10
	I2NPMessageTypeGarlic                   = 11
	I2NPMessageTypeTunnelData               = 18
	I2NPMessageTypeTunnelGateway            = 19
	I2NPMessageTypeData                     = 20
	I2NPMessageTypeTunnelBuild              = 21
	I2NPMessageTypeTunnelBuildReply         = 22
	I2NPMessageTypeVariableTunnelBuild      = 23
	I2NPMessageTypeVariableTunnelBuildReply = 24
	I2NPMessageTypeShortTunnelBuild         = 25
	I2NPMessageTypeShortTunnelBuildReply    = 26
)

// I2NP Error Constants
// These use errors.New (not oops.Errorf) so callers can match them with errors.Is().
// Moved from: header.go, build_request_record.go, build_response_record.go, database_lookup.go
var (
	ErrI2NPNotEnoughData                = errors.New("not enough i2np header data")
	ErrBuildRequestRecordNotEnoughData  = errors.New("not enough i2np build request record data")
	ErrBuildResponseRecordNotEnoughData = errors.New("not enough i2np build response record data")
	ErrDatabaseLookupNotEnoughData      = errors.New("not enough i2np database lookup data")
	ErrDatabaseSearchReplyNotEnoughData = errors.New("not enough i2np database search reply data")
	ErrDatabaseLookupInvalidSize        = errors.New("database lookup excluded peers size exceeds protocol limit")
	ErrI2NPMessageExpired               = errors.New("i2np message has expired")
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
