package ntcp

import (
	"crypto/rand"
	"math/big"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/messages"
	"github.com/samber/oops"
)

// CreateSessionCreated builds the SessionCreated message (Message 2 in NTCP2 handshake)
// This is sent by Bob to Alice after receiving SessionRequest
func (s *NTCP2Session) CreateSessionCreated(
	handshakeState *noise.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionCreated, error) {
	// 1. Generate ephemeral key (handshakeState has already done this, we just need to extract it)
	ephemeralKey := handshakeState.LocalEphemeral().Public

	// 2. Create padding according to NTCP2 spec
	// NTCP2 spec recommends 0-31 bytes of random padding
	paddingSize, err := rand.Int(rand.Reader, big.NewInt(32))
	if err != nil {
		return nil, oops.Errorf("failed to generate random padding size: %w", err)
	}

	padding := make([]byte, paddingSize.Int64())
	if _, err := rand.Read(padding); err != nil {
		return nil, oops.Errorf("failed to generate padding: %w", err)
	}

	// 3. Create response options
	timestamp, err := data.DateFromTime(s.GetCurrentTime())
	if err != nil {
		return nil, oops.Errorf("failed to create timestamp: %w", err)
	}
	paddingLen, err := data.NewIntegerFromInt(len(padding), 1)
	if err != nil {
		return nil, oops.Errorf("failed to create padding length: %w", err)
	}

	// Create response options with appropriate fields
	responseOptions := &messages.CreatedOptions{
		PaddingLength: paddingLen,
		Timestamp:     timestamp,
	}

	// 4. Return the complete SessionCreated message
	return &messages.SessionCreated{
		YContent: [32]byte(ephemeralKey), // Y is the obfuscated ephemeral key
		Options:  responseOptions,
		Padding:  padding,
	}, nil
}
