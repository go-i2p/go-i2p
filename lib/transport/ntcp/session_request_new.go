package ntcp

import (
	"crypto/rand"
	"math/big"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
)

type SessionRequestProcessor struct {
	*NTCP2Session
}

// CreateMessage implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) CreateMessage(hs *handshake.HandshakeState) (messages.Message, error) {
	// Get our ephemeral key pair
	ephemeralKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, err
	}

	// Add random padding (implementation specific)
	randomInt, err := rand.Int(rand.Reader, big.NewInt(16))
	if err != nil {
		return nil, err
	}

	padding := make([]byte, randomInt.Int64()) // Up to 16 bytes of padding
	if err != nil {
		return nil, err
	}

	netId, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, err
	}
	version, err := data.NewIntegerFromInt(2, 1)
	if err != nil {
		return nil, err
	}
	paddingLen, _, err := data.NewInteger([]byte{byte(len(padding))}, 1)
	if err != nil {
		return nil, err
	}
	//message3Part2Len, err := data.NewInteger()
	//if err != nil {
	//	return nil, err
	//}
	timestamp, err := data.DateFromTime(s.GetCurrentTime())
	if err != nil {
		return nil, err
	}
	requestOptions := &messages.RequestOptions{
		NetworkID:       netId,
		ProtocolVersion: version,
		PaddingLength:   paddingLen,
		// Message3Part2Length: ,
		Timestamp: timestamp,
	}

	return &messages.SessionRequest{
		XContent: [32]byte(ephemeralKey),
		Options:  *requestOptions,
		Padding:  padding,
	}, nil
}

// EncryptOptions implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) EncryptOptions(msg messages.Message, obfuscatedKey []byte, hs *handshake.HandshakeState) ([]byte, error) {
	panic("unimplemented")
}

// GetPadding implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) GetPadding(msg messages.Message) []byte {
	panic("unimplemented")
}

// ObfuscateKey implements HandshakeMessageProcessor.
func (s *SessionRequestProcessor) ObfuscateKey(msg messages.Message, hs *handshake.HandshakeState) ([]byte, error) {
	return s.ObfuscateEphemeral(msg.(*messages.SessionRequest).XContent[:])
}

var _ handshake.HandshakeMessageProcessor = (*SessionRequestProcessor)(nil)
