package i2np

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel/build"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
)

// I2NP Header Types
// Moved from: header.go

// I2NPNTCPHeader represents a parsed I2NP message header for NTCP
// transport. It holds the standard 16-byte header fields (type, message
// ID, expiration, size, checksum) plus the message data, so the router
// can validate and dispatch messages received over NTCP.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [I2NPSecondGenTransportHeader] and [ReadI2NPNTCPHeader].
type I2NPNTCPHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
	Size       int
	Checksum   int
	Data       []byte
}

// I2NPSecondGenTransportHeader represents the compact 9-byte I2NP header
// used over NTCP2 and SSU2 transports, replacing the standard 16-byte
// header. The size and checksum fields are dropped because the transport
// layer already provides framing and integrity.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [I2NPNTCPHeader] and [ReadI2NPSecondGenTransportHeader].
type I2NPSecondGenTransportHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
}

// Interface Definitions

// MessageSerializer represents types that can be marshaled and
// unmarshaled. All I2NP message types satisfy this interface, which lets
// the message processor serialize and deserialize messages generically.
// See also [Message].
type MessageSerializer interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
}

// MessageIdentifier represents types that have message identification.
// The message ID is used to correlate replies with their original
// requests, and the type selects the message handler.
// See also [Message].
type MessageIdentifier interface {
	Type() int
	MessageID() int
	SetMessageID(id int)
}

// MessageExpiration represents types that have expiration management.
// Expired messages are dropped before processing to prevent replay of
// stale data, so every I2NP message carries an expiration timestamp.
// See also [Message] and [CheckMessageExpiration].
type MessageExpiration interface {
	Expiration() time.Time
	SetExpiration(exp time.Time)
}

// DataCarrier represents messages that expose raw message data via GetData().
// All typed I2NP messages embed BaseI2NPMessage and satisfy this interface.
// Use this for type-safe data extraction instead of asserting *BaseI2NPMessage
// directly, which fails for typed message structs.
type DataCarrier interface {
	GetData() []byte
}

// PayloadCarrier represents messages that carry payload data. It lets
// the router extract the application payload from a Data message without
// depending on the concrete message type.
// See also [DataMessage] and [DataCarrier].
type PayloadCarrier interface {
	GetPayload() []byte
}

// TunnelCarrier represents messages that carry tunnel-related data.
// Per I2P spec (tunnel-message.rst), TunnelData messages contain TunnelID(4) + IV(16) + EncryptedData(1008) = 1028 bytes.
type TunnelCarrier interface {
	GetTunnelData() []byte
	GetTunnelID() buildrecord.TunnelID
}

// DatabaseReader represents types that can perform database lookups.
// It exposes the key, source, and flags of a lookup so the database
// manager can route it to the correct store.
// See also [DatabaseLookup] and [DatabaseManager].
type DatabaseReader interface {
	GetKey() common.Hash
	GetFrom() common.Hash
	GetFlags() byte
}

// DatabaseWriter represents types that can store database entries. It
// exposes the key, data, and type of a store so the database manager can
// persist it in the correct table.
// See also [DatabaseStore] and [DatabaseManager].
type DatabaseWriter interface {
	GetStoreKey() common.Hash
	GetStoreData() []byte
	GetStoreType() byte
}

// TunnelBuilder represents types that can build tunnels - re-exported from lib/tunnel/build
type TunnelBuilder = build.TunnelBuilder

// TunnelReplyHandler represents types that handle tunnel build replies - re-exported from lib/tunnel/build
type TunnelReplyHandler = build.TunnelReplyHandler

// repliedHopCounter is implemented by reply handlers that can be told how many
// of their records are real hop replies. A short build reply relays every slot
// of the build request it answered, fake records included, so the handler needs
// the hop count to avoid scoring padding as a rejected hop
// (tunnel-creation-ecies.rst "Build Records"). Handlers that do not implement it
// evaluate every record they hold, which is correct for reply sets that carry one
// record per hop.
type repliedHopCounter interface {
	SetRepliedHopCount(count int)
}

// replyStepProcessor defines the internal operations for processing tunnel
// build replies. Used by processReplySteps to eliminate duplication across
// ShortTunnelBuildReply.
type replyStepProcessor interface {
	logReplyStart(recordCount int)
	validateRecordCount(recordCount int) error
	processAllHops() (int, error)
	logReplyCompletion(successCount, recordCount int)
	determineBuildResult(successCount, recordCount int, firstError error) error
}

// processReplySteps executes the common tunnel build reply pipeline:
// log start → validate count → process hops → log completion → determine result.
func processReplySteps(p replyStepProcessor, records []BuildResponseRecord) error {
	recordCount := len(records)
	p.logReplyStart(recordCount)
	if err := p.validateRecordCount(recordCount); err != nil {
		return err
	}
	successCount, firstError := p.processAllHops()
	p.logReplyCompletion(successCount, recordCount)
	return p.determineBuildResult(successCount, recordCount, firstError)
}

// SessionKeyProvider represents types that provide session keys. Build
// request records carry the reply and layer keys needed to decrypt
// tunnel build replies and tunnel data for each hop.
// See also [BuildRequestRecord].
type SessionKeyProvider interface {
	GetReplyKey() session_key.SessionKey
	GetLayerKey() session_key.SessionKey
	GetIVKey() session_key.SessionKey
}

// TunnelIdentifier represents types that identify tunnel endpoints.
// Build request records use it to specify which tunnel to receive on and
// which tunnel the next hop should be.
// See also [BuildRequestRecord].
type TunnelIdentifier interface {
	GetReceiveTunnel() buildrecord.TunnelID
	GetNextTunnel() buildrecord.TunnelID
}

// HashProvider represents types that provide hash identification. Build
// request records use it to identify the requesting router and the next
// hop's router identity for reply routing.
// See also [BuildRequestRecord].
type HashProvider interface {
	GetOurIdent() common.Hash
	GetNextIdent() common.Hash
}

// StatusReporter represents types that report delivery status. It lets
// the delivery status reporter correlate a status message with the
// original message it refers to.
// See also [DeliveryStatusMessage].
type StatusReporter interface {
	GetStatusMessageID() int
	GetTimestamp() time.Time
}

// GarlicProcessor represents types that process garlic messages. It
// exposes the cloves of a Garlic message so the router can unwrap and
// dispatch each clove's payload.
// See also [Garlic] and [GarlicClove].
type GarlicProcessor interface {
	GetCloves() []GarlicClove
	GetCloveCount() int
}

// Compile-time interface satisfaction checks for message types
var (
	// Core message interfaces
	_ MessageSerializer = (*BaseI2NPMessage)(nil)
	_ MessageIdentifier = (*BaseI2NPMessage)(nil)
	_ MessageExpiration = (*BaseI2NPMessage)(nil)
	_ Message           = (*BaseI2NPMessage)(nil)
	_ Message           = (*DataMessage)(nil)
	_ Message           = (*DeliveryStatusMessage)(nil)
	_ Message           = (*TunnelDataMessage)(nil)

	// Specialized behavior interfaces
	_ PayloadCarrier  = (*DataMessage)(nil)
	_ TunnelCarrier   = (*TunnelDataMessage)(nil)
	_ StatusReporter  = (*DeliveryStatusMessage)(nil)
	_ GarlicProcessor = (*Garlic)(nil)

	// Database interfaces
	_ DatabaseReader = (*DatabaseLookup)(nil)
	_ DatabaseWriter = (*DatabaseStore)(nil)

	// Tunnel interfaces
	_ TunnelBuilder      = (*ShortTunnelBuild)(nil)
	_ TunnelReplyHandler = (*ShortTunnelBuildReply)(nil)

	// Build record interfaces
	_ TunnelIdentifier   = (*BuildRequestRecord)(nil)
	_ SessionKeyProvider = (*BuildRequestRecord)(nil)
	_ HashProvider       = (*BuildRequestRecord)(nil)
)
