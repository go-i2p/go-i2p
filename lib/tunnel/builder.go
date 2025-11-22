package tunnel

import (
	"crypto/rand"
	"fmt"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
)

// TunnelBuilder handles the creation of tunnel build request messages.
// It generates encrypted build records for each hop in a tunnel and constructs
// VariableTunnelBuild messages for transmission over the I2P network.
type TunnelBuilder struct {
	peerSelector PeerSelector
}

// NewTunnelBuilder creates a new TunnelBuilder with the given peer selector.
// The peer selector is used to choose routers for tunnel hops.
//
// Returns an error if the peer selector is nil.
func NewTunnelBuilder(selector PeerSelector) (*TunnelBuilder, error) {
	if selector == nil {
		return nil, fmt.Errorf("peer selector cannot be nil")
	}
	return &TunnelBuilder{peerSelector: selector}, nil
}

// BuildTunnelRequest contains the parameters needed to build a tunnel.
type BuildTunnelRequest struct {
	HopCount      int           // Number of hops in the tunnel (1-8)
	IsInbound     bool          // True for inbound tunnel, false for outbound
	OurIdentity   common.Hash   // Our router identity hash
	ExcludePeers  []common.Hash // Peers to exclude from selection
	ReplyTunnelID TunnelID      // Tunnel ID for receiving build replies (0 for outbound)
	ReplyGateway  common.Hash   // Gateway hash for build replies (empty for outbound)
	UseShortBuild bool          // Use Short Tunnel Build (STBM - modern, default true)
}

// BuildRequestRecord contains all the data for a single tunnel hop build request.
// This is the cleartext version before encryption. It maps to the I2NP
// BuildRequestRecord structure but is defined here to avoid import cycles.
type BuildRequestRecord struct {
	ReceiveTunnel TunnelID
	OurIdent      common.Hash
	NextTunnel    TunnelID
	NextIdent     common.Hash
	LayerKey      session_key.SessionKey
	IVKey         session_key.SessionKey
	ReplyKey      session_key.SessionKey
	ReplyIV       [16]byte
	Flag          int
	RequestTime   time.Time
	SendMessageID int
	Padding       [29]byte
}

// TunnelBuildResult contains the result of building a tunnel request.
type TunnelBuildResult struct {
	TunnelID      TunnelID                 // The generated tunnel ID
	Hops          []router_info.RouterInfo // Selected router hops
	Records       []BuildRequestRecord     // Build records for each hop
	ReplyKeys     []session_key.SessionKey // Reply decryption keys for each hop
	ReplyIVs      [][16]byte               // Reply IVs for each hop
	UseShortBuild bool                     // True if using Short Tunnel Build (STBM), false for Variable Tunnel Build
}

// CreateBuildRequest generates a complete tunnel build request with encrypted records.
//
// The process:
// 1. Select peers for tunnel hops using the peer selector
// 2. Generate a unique tunnel ID for this tunnel
// 3. Create build request records for each hop with cryptographic keys
// 4. Prepare reply decryption keys for processing build replies
//
// Returns TunnelBuildResult with all necessary information, or an error if:
// - HopCount is invalid (must be 1-8)
// - Peer selection fails
// - Cryptographic key generation fails
func (tb *TunnelBuilder) CreateBuildRequest(req BuildTunnelRequest) (*TunnelBuildResult, error) {
	if err := tb.validateHopCount(req.HopCount); err != nil {
		return nil, err
	}

	peers, err := tb.selectTunnelPeers(req)
	if err != nil {
		return nil, err
	}

	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate tunnel ID: %w", err)
	}

	records, replyKeys, replyIVs, err := tb.createAllHopRecords(req, tunnelID, peers)
	if err != nil {
		return nil, err
	}

	return &TunnelBuildResult{
		TunnelID:      tunnelID,
		Hops:          peers,
		Records:       records,
		ReplyKeys:     replyKeys,
		ReplyIVs:      replyIVs,
		UseShortBuild: req.UseShortBuild,
	}, nil
}

// validateHopCount validates that the hop count is within I2P spec limits (1-8).
func (tb *TunnelBuilder) validateHopCount(hopCount int) error {
	if hopCount < 1 || hopCount > 8 {
		return fmt.Errorf("hop count must be between 1 and 8, got %d", hopCount)
	}
	return nil
}

// selectTunnelPeers selects and validates peers for tunnel hops.
func (tb *TunnelBuilder) selectTunnelPeers(req BuildTunnelRequest) ([]router_info.RouterInfo, error) {
	peers, err := tb.peerSelector.SelectPeers(req.HopCount, req.ExcludePeers)
	if err != nil {
		return nil, fmt.Errorf("failed to select peers: %w", err)
	}

	if len(peers) < req.HopCount {
		return nil, fmt.Errorf("insufficient peers: need %d, got %d", req.HopCount, len(peers))
	}

	return peers, nil
}

// createAllHopRecords creates build request records for all tunnel hops.
// Returns the records, reply keys, and reply IVs for each hop.
func (tb *TunnelBuilder) createAllHopRecords(
	req BuildTunnelRequest,
	tunnelID TunnelID,
	peers []router_info.RouterInfo,
) ([]BuildRequestRecord, []session_key.SessionKey, [][16]byte, error) {
	records := make([]BuildRequestRecord, req.HopCount)
	replyKeys := make([]session_key.SessionKey, req.HopCount)
	replyIVs := make([][16]byte, req.HopCount)

	for i := 0; i < req.HopCount; i++ {
		record, replyKey, replyIV, err := tb.createHopRecord(i, req, tunnelID, peers)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create record for hop %d: %w", i, err)
		}

		records[i] = record
		replyKeys[i] = replyKey
		replyIVs[i] = replyIV
	}

	return records, replyKeys, replyIVs, nil
}

// createHopRecord creates a build request record for a single tunnel hop.
//
// The record contains:
// - Tunnel IDs for routing (receive and next hop)
// - Router identity hashes (this hop and next hop)
// - Cryptographic keys for tunnel message encryption (layer key, IV key)
// - Reply encryption keys for build response
// - Timestamp and message ID
func (tb *TunnelBuilder) createHopRecord(
	hopIndex int,
	req BuildTunnelRequest,
	tunnelID TunnelID,
	peers []router_info.RouterInfo,
) (BuildRequestRecord, session_key.SessionKey, [16]byte, error) {
	// Generate cryptographic keys for this hop
	layerKey, err := generateSessionKey()
	if err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{},
			fmt.Errorf("failed to generate layer key: %w", err)
	}

	ivKey, err := generateSessionKey()
	if err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{},
			fmt.Errorf("failed to generate IV key: %w", err)
	}

	replyKey, err := generateSessionKey()
	if err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{},
			fmt.Errorf("failed to generate reply key: %w", err)
	}

	var replyIV [16]byte
	if _, err := rand.Read(replyIV[:]); err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{},
			fmt.Errorf("failed to generate reply IV: %w", err)
	}

	// Determine tunnel routing parameters based on position in chain
	receiveTunnel, nextTunnel, ourIdent, nextIdent := tb.determineRoutingParams(
		hopIndex, req, tunnelID, peers,
	)

	// Generate random padding
	var padding [29]byte
	if _, err := rand.Read(padding[:]); err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{},
			fmt.Errorf("failed to generate padding: %w", err)
	}

	// Create the build request record
	record := BuildRequestRecord{
		ReceiveTunnel: receiveTunnel,
		OurIdent:      ourIdent,
		NextTunnel:    nextTunnel,
		NextIdent:     nextIdent,
		LayerKey:      layerKey,
		IVKey:         ivKey,
		ReplyKey:      replyKey,
		ReplyIV:       replyIV,
		Flag:          0, // Standard flag (no special behavior)
		RequestTime:   time.Now(),
		SendMessageID: generateMessageID(),
		Padding:       padding,
	}

	return record, replyKey, replyIV, nil
}

// determineRoutingParams calculates the tunnel routing parameters for a specific hop.
//
// For outbound tunnels:
// - First hop (gateway): receives from us (0), sends to next hop
// - Middle hops: receive from previous, send to next
// - Last hop (endpoint): receives from previous, sends to destination (0)
//
// For inbound tunnels:
// - First hop (endpoint): receives from sender, sends to next hop
// - Middle hops: receive from previous, send to next
// - Last hop (gateway): receives from previous, sends to us (specified tunnel ID)
func (tb *TunnelBuilder) determineRoutingParams(
	hopIndex int,
	req BuildTunnelRequest,
	tunnelID TunnelID,
	peers []router_info.RouterInfo,
) (receiveTunnel, nextTunnel TunnelID, ourIdent, nextIdent common.Hash) {
	isLastHop := hopIndex == len(peers)-1
	isFirstHop := hopIndex == 0

	// Get this hop's router identity using the IdentHash() method
	ourIdent = peers[hopIndex].IdentHash()

	if req.IsInbound {
		// Inbound tunnel: messages flow from network toward us
		if isFirstHop {
			// Endpoint receives from sender (unknown tunnel ID, use 0)
			receiveTunnel = 0
		} else {
			// Middle/gateway receives from previous hop
			receiveTunnel = tunnelID
		}

		if isLastHop {
			// Gateway sends to our specified tunnel
			nextTunnel = req.ReplyTunnelID
			nextIdent = req.ReplyGateway
		} else {
			// Endpoint/middle sends to next hop
			nextTunnel = tunnelID
			nextIdent = peers[hopIndex+1].IdentHash()
		}
	} else {
		// Outbound tunnel: messages flow from us toward network
		if isFirstHop {
			// Gateway receives from our tunnel
			receiveTunnel = tunnelID
		} else {
			// Middle/endpoint receives from previous hop
			receiveTunnel = tunnelID
		}

		if isLastHop {
			// Endpoint sends to destination (tunnel ID set per message)
			nextTunnel = 0
			nextIdent = common.Hash{} // Empty hash, set per message
		} else {
			// Gateway/middle sends to next hop
			nextTunnel = tunnelID
			nextIdent = peers[hopIndex+1].IdentHash()
		}
	}

	return
}

// generateTunnelID creates a cryptographically random tunnel ID.
// Tunnel IDs are 32-bit unsigned integers used to route messages through tunnels.
func generateTunnelID() (TunnelID, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("failed to read random data: %w", err)
	}

	// Convert to TunnelID, ensuring it's non-zero
	id := TunnelID(uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3]))
	if id == 0 {
		// Retry if we got zero (extremely unlikely)
		return generateTunnelID()
	}

	return id, nil
}

// generateSessionKey creates a cryptographically random 32-byte session key.
// Session keys are used for AES-256 encryption in tunnel messages.
func generateSessionKey() (session_key.SessionKey, error) {
	var key session_key.SessionKey
	if _, err := rand.Read(key[:]); err != nil {
		return session_key.SessionKey{}, fmt.Errorf("failed to read random data: %w", err)
	}
	return key, nil
}

// generateMessageID creates a random message ID for tracking build requests.
// Message IDs are 32-bit unsigned integers.
func generateMessageID() int {
	var buf [4]byte
	rand.Read(buf[:]) // Ignore error, best effort for message ID

	return int(uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3]))
}
