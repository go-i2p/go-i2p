package ntcp

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/messages"
)

// CreateSessionConfirmed builds the SessionConfirmed message (Message 3 in NTCP2 handshake)
// This is sent by Alice to Bob after receiving SessionCreated
func (c *NTCP2Session) CreateSessionConfirmed(
	handshakeState *noise.HandshakeState,
	localRouterInfo *router_info.RouterInfo,
) (*messages.SessionConfirmed, error) {
	// Create the SessionConfirmed message
	sc := &messages.SessionConfirmed{}

	// Step 1: Get our static key from the handshake state
	// Note: The static key must be encrypted using the handshakeState's WriteMessage
	// but we need to extract it first to store in the result structure
	localKeyPair, err := c.localStaticKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get local static keypair: %w", err)
	}

	// Copy the 32-byte static key
	copy(sc.StaticKey[:], localKeyPair[:])

	// Step 2: Set the RouterInfo
	sc.RouterInfo = localRouterInfo

	// Step 3: Create options with padding settings
	// Use default padding for now - we should make this something we can configure
	paddingLength, err := data.NewIntegerFromInt(calculatePaddingLength(localRouterInfo), 1)
	if err != nil {
		return nil, fmt.Errorf("failed to create padding length: %w", err)
	}

	sc.Options = &messages.ConfirmedOptions{
		PaddingLength: paddingLength,
	}

	// Step 4: Generate padding data according to the specified length
	// In a real implementation, this should be cryptographically secure random data
	if paddingLength.Int() > 0 {
		sc.Padding = make([]byte, paddingLength.Int())
		if _, err := rand.Read(sc.Padding); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}

	// The actual encryption of the message will happen in the calling function
	// using the handshakeState.WriteMessage() method, as it needs to maintain the
	// proper noise protocol state
	return sc, nil
}

// calculatePaddingLength determines an appropriate padding length based on the RouterInfo
func calculatePaddingLength(ri *router_info.RouterInfo) int {
	rib, _ := ri.Bytes()
	// Base size of the RouterInfo
	riSize := len(rib)

	// For this implementation, we'll use a simple padding scheme:
	// - Add enough padding to make the total size at least 128 bytes
	// - Add random padding between 16 and 64 bytes

	minSize := 128
	minPadding := 1
	maxExtraPadding := 30 // Total max padding: 1+30=31

	padding := 0
	if riSize < minSize {
		padding = minSize - riSize
	}

	// Add random additional padding between minPadding and minPadding+maxExtraPadding
	padding += mrand.Intn(maxExtraPadding) + minPadding

	return padding
}
