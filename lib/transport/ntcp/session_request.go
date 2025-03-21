package ntcp

// SessionRequestMessage represents Message 1 of the NTCP2 handshake
type SessionRequestMessage struct {
	ObfuscatedKey []byte   // 32 bytes ephemeral key X
	Timestamp     uint32   // Current time
	Options       [16]byte // Options block
	Padding       []byte   // Random padding
}

// SessionRequestBuilder handles creation of NTCP2 Message 1
type SessionRequestBuilder interface {
	// CreateSessionRequest builds Message 1 of handshake
	CreateSessionRequest() (*SessionRequestMessage, error)

	// ObfuscateEphemeral obfuscates ephemeral key using AES
	ObfuscateEphemeral(key []byte) ([]byte, error)
}
