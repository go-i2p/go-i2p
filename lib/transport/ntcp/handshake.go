package ntcp

import (
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/messages"
	"github.com/samber/oops"
)

// CreateHandshakeProcessors initializes all the handshake message processors
func (s *NTCP2Session) CreateHandshakeProcessors() {
	s.Processors = map[messages.MessageType]handshake.HandshakeMessageProcessor{
		messages.MessageTypeSessionRequest:   &SessionRequestProcessor{NTCP2Session: s},
		messages.MessageTypeSessionCreated:   &SessionCreatedProcessor{NTCP2Session: s},
		messages.MessageTypeSessionConfirmed: &SessionConfirmedProcessor{NTCP2Session: s},
	}
}

// GetProcessor returns the appropriate processor for a message type
func (s *NTCP2Session) GetProcessor(messageType messages.MessageType) (handshake.HandshakeMessageProcessor, error) {
	processor, exists := s.Processors[messageType]
	if !exists {
		return nil, oops.Errorf("no processor for message type: %v", messageType)
	}
	return processor, nil
}
