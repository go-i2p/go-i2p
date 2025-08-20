package i2np

import (
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/common/session_tag"
	"github.com/go-i2p/go-i2p/lib/tunnel"
)

// I2NP Header Types
// Moved from: header.go

// I2NPNTCPHeader represents a parsed I2NP message header for NTCP transport
type I2NPNTCPHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
	Size       int
	Checksum   int
	Data       []byte
}

// I2NPSSUHeader represents a parsed I2NP message header for SSU transport
type I2NPSSUHeader struct {
	Type       int
	Expiration time.Time
}

/*
When transmitted over [NTCP2] or [SSU2], the 16-byte standard header is not used. Only a 1-byte type, 4-byte message id, and a 4-byte expiration in seconds are included. The size is incorporated in the NTCP2 and SSU2 data packet formats. The checksum is not required since errors are caught in decryption.
*/
type I2NPSecondGenTransportHeader struct {
	Type       int
	MessageID  int
	Expiration time.Time
}

// Interface Definitions

// MessageSerializer represents types that can be marshaled and unmarshaled
type MessageSerializer interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
}

// MessageIdentifier represents types that have message identification
type MessageIdentifier interface {
	Type() int
	MessageID() int
	SetMessageID(id int)
}

// MessageExpiration represents types that have expiration management
type MessageExpiration interface {
	Expiration() time.Time
	SetExpiration(exp time.Time)
}

// PayloadCarrier represents messages that carry payload data
type PayloadCarrier interface {
	GetPayload() []byte
}

// TunnelCarrier represents messages that carry tunnel-related data
type TunnelCarrier interface {
	GetTunnelData() []byte
}

// BuildRecordReader represents types that can parse build request records
type BuildRecordReader interface {
	ReadBuildRequestRecord(data []byte) (BuildRequestRecord, error)
}

// BuildRecordWriter represents types that can write build response records
type BuildRecordWriter interface {
	WriteBuildResponseRecord() ([]byte, error)
}

// DatabaseReader represents types that can perform database lookups
type DatabaseReader interface {
	GetKey() common.Hash
	GetFrom() common.Hash
	GetFlags() byte
}

// DatabaseWriter represents types that can store database entries
type DatabaseWriter interface {
	GetStoreKey() common.Hash
	GetStoreData() []byte
	GetStoreType() byte
}

// TunnelBuilder represents types that can build tunnels
type TunnelBuilder interface {
	GetBuildRecords() []BuildRequestRecord
	GetRecordCount() int
}

// TunnelReplyHandler represents types that handle tunnel build replies
type TunnelReplyHandler interface {
	GetReplyRecords() []BuildResponseRecord
	ProcessReply() error
}

// SessionKeyProvider represents types that provide session keys
type SessionKeyProvider interface {
	GetReplyKey() session_key.SessionKey
	GetLayerKey() session_key.SessionKey
	GetIVKey() session_key.SessionKey
}

// SessionTagProvider represents types that provide session tags
type SessionTagProvider interface {
	GetReplyTags() []session_tag.SessionTag
	GetTagCount() int
}

// TunnelIdentifier represents types that identify tunnel endpoints
type TunnelIdentifier interface {
	GetReceiveTunnel() tunnel.TunnelID
	GetNextTunnel() tunnel.TunnelID
}

// HashProvider represents types that provide hash identification
type HashProvider interface {
	GetOurIdent() common.Hash
	GetNextIdent() common.Hash
}

// StatusReporter represents types that report delivery status
type StatusReporter interface {
	GetStatusMessageID() int
	GetTimestamp() time.Time
}

// GarlicProcessor represents types that process garlic messages
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
	_ I2NPMessage       = (*BaseI2NPMessage)(nil)
	_ I2NPMessage       = (*DataMessage)(nil)
	_ I2NPMessage       = (*DeliveryStatusMessage)(nil)
	_ I2NPMessage       = (*TunnelDataMessage)(nil)

	// Specialized behavior interfaces
	_ PayloadCarrier  = (*DataMessage)(nil)
	_ TunnelCarrier   = (*TunnelDataMessage)(nil)
	_ StatusReporter  = (*DeliveryStatusMessage)(nil)
	_ GarlicProcessor = (*Garlic)(nil)

	// Database interfaces
	_ DatabaseReader     = (*DatabaseLookup)(nil)
	_ DatabaseWriter     = (*DatabaseStore)(nil)
	_ SessionTagProvider = (*DatabaseLookup)(nil)

	// Tunnel interfaces
	_ TunnelBuilder      = (*TunnelBuild)(nil)
	_ TunnelBuilder      = (*VariableTunnelBuild)(nil)
	_ TunnelReplyHandler = (*TunnelBuildReply)(nil)
	_ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)

	// Build record interfaces
	_ TunnelIdentifier   = (*BuildRequestRecord)(nil)
	_ SessionKeyProvider = (*BuildRequestRecord)(nil)
	_ HashProvider       = (*BuildRequestRecord)(nil)
)
