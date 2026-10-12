package i2np

import (
	"errors"

	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// I2NP Message Type Constants
// These are the type bytes in the I2NP message header that identify the
// message kind. See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the full list.
// Moved from: header.go
const (
	// I2NPMessageTypeDatabaseStore is the type for DatabaseStore messages.
	I2NPMessageTypeDatabaseStore = 1
	// I2NPMessageTypeDatabaseLookup is the type for DatabaseLookup messages.
	I2NPMessageTypeDatabaseLookup = 2
	// I2NPMessageTypeDatabaseSearchReply is the type for DatabaseSearchReply messages.
	I2NPMessageTypeDatabaseSearchReply = 3
	// I2NPMessageTypeDeliveryStatus is the type for DeliveryStatus messages.
	I2NPMessageTypeDeliveryStatus = 10
	// I2NPMessageTypeGarlic is the type for Garlic messages.
	I2NPMessageTypeGarlic = 11
	// I2NPMessageTypeTunnelData is the type for TunnelData messages.
	I2NPMessageTypeTunnelData = 18
	// I2NPMessageTypeTunnelGateway is the type for TunnelGateway messages.
	I2NPMessageTypeTunnelGateway = 19
	// I2NPMessageTypeData is the type for Data messages.
	I2NPMessageTypeData = 20
	// I2NPMessageTypeTunnelBuild is the type for TunnelBuild messages.
	I2NPMessageTypeTunnelBuild = 21
	// I2NPMessageTypeTunnelBuildReply is the type for TunnelBuildReply messages.
	I2NPMessageTypeTunnelBuildReply = 22
	// I2NPMessageTypeVariableTunnelBuild is the type for VariableTunnelBuild messages.
	I2NPMessageTypeVariableTunnelBuild = 23
	// I2NPMessageTypeVariableTunnelBuildReply is the type for VariableTunnelBuildReply messages.
	I2NPMessageTypeVariableTunnelBuildReply = 24
	// I2NPMessageTypeShortTunnelBuild is the type for ShortTunnelBuild messages.
	I2NPMessageTypeShortTunnelBuild = 25
	// I2NPMessageTypeShortTunnelBuildReply is the type for ShortTunnelBuildReply messages.
	I2NPMessageTypeShortTunnelBuildReply = 26
)

// I2NP Error Constants
// These use errors.New (not oops.Errorf) so callers can match them with errors.Is().
// Moved from: header.go, build_request_record.go, build_response_record.go, database_lookup.go
var (
	// ErrI2NPNotEnoughData is returned when a message buffer is too short to
	// contain a valid I2NP header.
	ErrI2NPNotEnoughData = errors.New("not enough i2np header data")
	// ErrBuildRequestRecordNotEnoughData is returned when a build request
	// record buffer is too short to parse.
	ErrBuildRequestRecordNotEnoughData = buildrecord.ErrNotEnoughData
	// ErrBuildResponseRecordNotEnoughData is returned when a build response
	// record buffer is too short to parse.
	ErrBuildResponseRecordNotEnoughData = buildrecord.ErrBuildResponseRecordNotEnoughData
	// ErrDatabaseLookupNotEnoughData is returned when a DatabaseLookup payload
	// is too short to parse.
	ErrDatabaseLookupNotEnoughData = errors.New("not enough i2np database lookup data")
	// ErrDatabaseSearchReplyNotEnoughData is returned when a DatabaseSearchReply
	// payload is too short to parse.
	ErrDatabaseSearchReplyNotEnoughData = errors.New("not enough i2np database search reply data")
	// ErrDatabaseLookupInvalidSize is returned when a DatabaseLookup's excluded
	// peers list exceeds the protocol limit.
	ErrDatabaseLookupInvalidSize = errors.New("database lookup excluded peers size exceeds protocol limit")
	// ErrI2NPMessageExpired is returned when a message's expiration is in the
	// past.
	ErrI2NPMessageExpired = errors.New("i2np message has expired")
)

// Build record size constants per the I2P specification.
// Standard (ElGamal) records are 528 bytes on the wire; cleartext is 222 bytes.
// ECIES-X25519 long-form records are also 528 bytes on the wire; cleartext is 464 bytes.
// Short (ECIES) records are 218 bytes on the wire (added in 0.9.49).
// Standard cleartext (before encryption) is 222 bytes.
// Short cleartext (ECIES short) is 154 bytes (218 - 16 toPeer - 32 ephKey - 16 MAC).
const (
	StandardBuildRecordSize         = 528                                  // Encrypted on-wire size for standard/variable tunnel build records
	ShortBuildRecordSize            = buildrecord.ShortRecordSize          // 218
	StandardBuildRecordCleartextLen = buildrecord.StandardCleartextLen     // 222
	ShortBuildRecordCleartextLen    = buildrecord.ShortCleartextLen        // 154
	ShortRecordHeaderSize           = 64                                   // toPeer(16) + ephemeralKey(32) + MAC(16)
	DefaultExpirationSeconds        = buildrecord.DefaultExpirationSeconds // 480
)

// DefaultExpirationTolerance is the default expiration tolerance for clock skew (5 minutes into the past).
// This allows for reasonable clock differences between I2P routers while
// still rejecting clearly expired messages.
const DefaultExpirationTolerance = 5 * 60 // 5 minutes in seconds
