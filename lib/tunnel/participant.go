package tunnel

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/tunnel"
	"github.com/go-i2p/logger"
)

// Participant represents an intermediate hop in an I2P tunnel.
// It receives encrypted tunnel messages, decrypts one layer,
// and forwards them to the next hop.
//
// Design decisions:
// - Simple relay logic: decrypt and forward
// - Uses crypto/tunnel with ECIES-X25519-AEAD (ChaCha20/Poly1305) by default
// - Supports both modern ECIES and legacy AES-256-CBC for compatibility
// - No message inspection (maintains tunnel privacy)
// - Stateless processing for better performance
// - Tracks creation time and expiration (tunnels typically last 10 minutes)
// - Tracks last activity to detect idle tunnels (protection against resource exhaustion attacks)
// - Thread-safe: lastActivity uses atomic operations with 5-second granularity
// - Stores next hop routing info (router identity and tunnel ID) for forwarding
type Participant struct {
	// tunnelID is this participant's tunnel ID (not used for processing,
	// but kept for logging and debugging)
	tunnelID TunnelID

	// decryption handles removing one layer of encryption
	decryption tunnel.TunnelEncryptor

	// createdAt tracks when this participant tunnel was created
	createdAt time.Time

	// lifetime is how long this participant tunnel is valid (nanoseconds)
	// Typically 10 minutes for I2P tunnels
	// Uses atomic operations for thread-safe access
	lifetime atomic.Int64

	// lastActivity tracks when data was last processed through this tunnel (UnixNano)
	// Used to detect idle tunnels that may be part of a resource exhaustion attack
	// Uses atomic operations with 5-second granularity to reduce syscall overhead
	lastActivity atomic.Int64

	// idleTimeout is how long a tunnel can be idle before being dropped (nanoseconds)
	// Default is 2 minutes to mitigate attackers requesting excessive tunnels
	// Uses atomic operations for thread-safe access
	idleTimeout atomic.Int64

	// nextHopIdent is the router identity (hash) of the next hop for routing
	// May be nil if forwarding to an endpoint (tunnel ID 0)
	nextHopIdent common.Hash

	// nextHopTunnel is the tunnel ID at the next hop for routing (0 = direct to router)
	nextHopTunnel TunnelID
}

var (
	// ErrNilParticipantDecryption is returned when participant decryption is nil.
	ErrNilParticipantDecryption = errors.New("participant decryption cannot be nil")

	// ErrInvalidParticipantData is returned when tunnel data is malformed
	ErrInvalidParticipantData = errors.New("invalid participant tunnel data")
)

// DefaultIdleTimeout is the default duration after which an idle tunnel is dropped.
// This helps mitigate resource exhaustion attacks where attackers request
// excessive tunnels but send no data through them.
const DefaultIdleTimeout = 2 * time.Minute

// activityTimestampGranularitySec is the granularity for lastActivity timestamp updates (in seconds).
// Timestamps are only updated if at least this many seconds have passed since the last update.
// This reduces time.Now() syscall overhead from 50+/sec to <1/sec per tunnel.
// Can be overridden in tests to 0 for immediate updates.
var activityTimestampGranularitySec int64 = 5

// NewParticipant creates a new tunnel participant.
//
// Parameters:
// - tunnelID: the tunnel ID for this participant hop
// - decryption: the tunnel decryption object for removing one encryption layer
//
// Returns an error if decryption is nil.
//
// Design note: We use TunnelEncryptor interface even though it's called
// "decryption" because the interface supports both encrypt and decrypt operations.
// The crypto/tunnel package uses the same interface for both directions.
// The participant is created with a default lifetime of 10 minutes (standard I2P tunnel lifetime)
// and an idle timeout of 2 minutes to protect against resource exhaustion attacks.
func NewParticipant(tunnelID TunnelID, decryption tunnel.TunnelEncryptor) (*Participant, error) {
	if decryption == nil {
		return nil, ErrNilParticipantDecryption
	}

	now := time.Now()
	p := &Participant{
		tunnelID:   tunnelID,
		decryption: decryption,
		createdAt:  now,
	}
	// Initialize atomic fields
	p.lifetime.Store(int64(10 * time.Minute)) // Standard I2P tunnel lifetime
	// Initialize lastActivity atomically to creation time (UnixNano)
	p.lastActivity.Store(now.UnixNano())
	// Initialize idleTimeout atomically (nanoseconds)
	p.idleTimeout.Store(int64(DefaultIdleTimeout))

	log.WithFields(logger.Fields{
		"at":           "NewParticipant",
		"reason":       "relay_tunnel_created",
		"tunnel_id":    tunnelID,
		"idle_timeout": DefaultIdleTimeout,
	}).Debug("created tunnel participant")
	return p, nil
}

// NewParticipantWithNextHop creates a new tunnel participant with next hop routing information.
// This is used during tunnel build when we accept a transit tunnel and need to store
// where to forward decrypted messages to.
//
// Parameters:
// - tunnelID: the tunnel ID for this participant hop
// - decryption: the tunnel decryption object for removing one encryption layer
// - nextHopIdent: the router hash of the next hop (may be empty if endpoint)
// - nextHopTunnel: the tunnel ID at the next hop (0 if direct to router)
//
// Returns an error if decryption is nil.
func NewParticipantWithNextHop(tunnelID TunnelID, decryption tunnel.TunnelEncryptor, nextHopIdent common.Hash, nextHopTunnel TunnelID) (*Participant, error) {
	p, err := NewParticipant(tunnelID, decryption)
	if err != nil {
		return nil, err
	}
	p.nextHopIdent = nextHopIdent
	p.nextHopTunnel = nextHopTunnel
	return p, nil
}

// NextHopIdent returns the router identity of the next hop for routing.
func (p *Participant) NextHopIdent() common.Hash {
	return p.nextHopIdent
}

// NextHopTunnel returns the tunnel ID at the next hop for routing.
func (p *Participant) NextHopTunnel() TunnelID {
	return p.nextHopTunnel
}

// Process handles an incoming encrypted tunnel message.
//
// This function implements the core participant functionality:
// 1. Validate the tunnel message format
// 2. Decrypt one layer of encryption
// 3. Extract the next hop tunnel ID
// 4. Return the partially-decrypted message ready for forwarding
//
// Parameters:
// - encryptedData: the 1028-byte encrypted tunnel message
//
// Returns:
// - nextHopID: the tunnel ID for the next hop
// - decryptedData: the message with one layer removed (still encrypted for next hops)
// - error: any processing error
//
// Design notes:
// - This is a stateless operation - no state is maintained between messages
// - The participant doesn't inspect message contents (privacy by design)
// - The tunnel ID in the message header specifies the next hop, not this hop
// - All 1028 bytes are returned; the next hop will decrypt further
func (p *Participant) Process(encryptedData []byte) (nextHopID TunnelID, decryptedData []byte, err error) {
	// Update last activity timestamp to track tunnel usage (configurable granularity)
	// This helps detect idle tunnels that may be part of a resource exhaustion attack
	// Only update if >= activityTimestampGranularitySec seconds have passed to reduce time.Now() syscall overhead
	now := time.Now()
	nowNano := now.UnixNano()
	lastNano := p.lastActivity.Load()
	// Check if enough seconds have passed (convert nanoseconds to seconds for comparison)
	if (nowNano-lastNano)/1e9 >= activityTimestampGranularitySec {
		// Use CompareAndSwap to handle concurrent updates without mutex
		p.lastActivity.CompareAndSwap(lastNano, nowNano)
	}

	// Validate input size
	if len(encryptedData) != 1028 {
		log.WithFields(logger.Fields{
			"at":           "(Participant) Process",
			"reason":       "invalid_message_size",
			"size":         len(encryptedData),
			"expected_min": 1028,
		}).Error("invalid tunnel message size")
		return 0, nil, ErrInvalidParticipantData
	}

	// Decrypt one layer of encryption
	// Modern ECIES-X25519 uses ChaCha20/Poly1305 AEAD for authenticated decryption
	// Legacy AES uses AES-256-CBC with dual-layer decryption and IV handling
	decrypted, err := p.decryption.Decrypt(encryptedData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(Participant) Process",
			"reason": "decryption_failed",
			"error":  err.Error(),
		}).Error("failed to decrypt tunnel layer")
		return 0, nil, err
	}

	// Validate decrypted size
	if len(decrypted) < 4 {
		log.WithFields(logger.Fields{
			"at":           "(Participant) Process",
			"reason":       "truncated_data",
			"size":         len(decrypted),
			"expected_min": 4,
		}).Error("decrypted data too small for tunnel ID")
		return 0, nil, ErrInvalidParticipantData
	}

	// Extract next hop tunnel ID from decrypted header
	// After decryption, bytes 0-3 contain the tunnel ID for the next hop
	nextHopID = TunnelID(binary.BigEndian.Uint32(decrypted[:4]))

	log.WithFields(map[string]interface{}{
		"tunnel_id":   p.tunnelID,
		"next_hop_id": nextHopID,
	}).Debug("Participant processed tunnel message")

	// Return the decrypted data (which still contains inner encryption layers)
	// and the next hop ID for routing
	return nextHopID, decrypted, nil
}

// TunnelID returns this participant's tunnel ID
func (p *Participant) TunnelID() TunnelID {
	return p.tunnelID
}

// IsExpired checks if this participant tunnel has expired.
// Returns true if the current time is past createdAt + lifetime.
//
// Parameters:
// - now: the current time to check against
// Returns true if the current time is past createdAt + lifetime.
//
// This is used by the tunnel manager to clean up expired participants.
// Thread-safe: uses atomic load for lifetime.
func (p *Participant) IsExpired(now time.Time) bool {
	lifetime := time.Duration(p.lifetime.Load())
	expirationTime := p.createdAt.Add(lifetime)
	return now.After(expirationTime)
}

// SetLifetime updates the lifetime for this participant tunnel.
// This allows customization beyond the default 10 minutes if needed.
// Thread-safe: uses atomic store.
func (p *Participant) SetLifetime(lifetime time.Duration) {
	p.lifetime.Store(int64(lifetime))
}

// CreatedAt returns when this participant tunnel was created.
func (p *Participant) CreatedAt() time.Time {
	return p.createdAt
}

// LastActivity returns when data was last processed through this tunnel.
// Thread-safe: uses atomic load with 5-second granularity.
func (p *Participant) LastActivity() time.Time {
	return time.Unix(0, p.lastActivity.Load())
}

// IsIdle checks if this participant tunnel has been idle for too long.
// Returns true if no data has been processed within the idle timeout period.
// This helps detect tunnels that may be part of a resource exhaustion attack
// where attackers request excessive tunnels but send no data through them.
// Thread-safe: uses atomic load with 5-second granularity.
//
// Parameters:
// - now: the current time to check against
//
// This is used by the tunnel manager to clean up idle participants.
func (p *Participant) IsIdle(now time.Time) bool {
	lastActivity := time.Unix(0, p.lastActivity.Load())
	idleTimeout := time.Duration(p.idleTimeout.Load())
	return now.Sub(lastActivity) > idleTimeout
}

// SetIdleTimeout updates the idle timeout for this participant tunnel.
// This allows customization beyond the default 2 minutes if needed.
// Thread-safe: uses atomic store.
func (p *Participant) SetIdleTimeout(timeout time.Duration) {
	p.idleTimeout.Store(int64(timeout))
}
