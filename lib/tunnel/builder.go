package tunnel

import (
	"fmt"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/logger"
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
	log.WithFields(logger.Fields{
		"at":     "(TunnelBuilder) NewTunnelBuilder",
		"phase":  "tunnel_build",
		"step":   1,
		"reason": "initializing tunnel builder",
	}).Debug("creating new tunnel builder")
	if selector == nil {
		log.WithFields(logger.Fields{
			"at":     "(TunnelBuilder) NewTunnelBuilder",
			"phase":  "tunnel_build",
			"reason": "peer selector is nil",
		}).Error("peer selector is nil")
		return nil, fmt.Errorf("peer selector cannot be nil")
	}
	log.WithFields(logger.Fields{
		"at":     "(TunnelBuilder) NewTunnelBuilder",
		"phase":  "tunnel_build",
		"reason": "tunnel builder initialized successfully",
	}).Debug("tunnel builder created successfully")
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
	log.WithFields(logger.Fields{
		"at":              "(TunnelBuilder) CreateBuildRequest",
		"phase":           "tunnel_build",
		"step":            "start",
		"reason":          "initiating tunnel build request creation",
		"hop_count":       req.HopCount,
		"is_inbound":      req.IsInbound,
		"use_short_build": req.UseShortBuild,
		"exclude_count":   len(req.ExcludePeers),
	}).Debug("creating tunnel build request")

	if err := tb.validateHopCount(req.HopCount); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":        "(TunnelBuilder) CreateBuildRequest",
			"phase":     "tunnel_build",
			"reason":    "hop count validation failed",
			"hop_count": req.HopCount,
			"min_hops":  1,
			"max_hops":  8,
		}).Error("invalid hop count")
		return nil, err
	}

	peers, err := tb.selectTunnelPeers(req)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":            "(TunnelBuilder) CreateBuildRequest",
			"phase":         "tunnel_build",
			"reason":        "peer selection failed",
			"hop_count":     req.HopCount,
			"exclude_count": len(req.ExcludePeers),
		}).Error("failed to select tunnel peers")
		return nil, err
	}

	tunnelID, err := generateTunnelID()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(TunnelBuilder) CreateBuildRequest",
			"phase":  "tunnel_build",
			"reason": "tunnel ID generation failed",
		}).Error("failed to generate tunnel ID")
		return nil, fmt.Errorf("failed to generate tunnel ID: %w", err)
	}
	log.WithFields(logger.Fields{
		"at":        "(TunnelBuilder) CreateBuildRequest",
		"phase":     "tunnel_build",
		"step":      "id_generated",
		"reason":    "generated unique tunnel identifier",
		"tunnel_id": tunnelID,
	}).Debug("generated tunnel ID")

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
	log.WithFields(logger.Fields{
		"at":        "validateHopCount",
		"hop_count": hopCount,
	}).Debug("Validating hop count")

	if hopCount < 1 || hopCount > 8 {
		log.WithFields(logger.Fields{
			"at":        "validateHopCount",
			"hop_count": hopCount,
			"reason":    "hop count out of range (1-8)",
		}).Error("Invalid hop count")
		return fmt.Errorf("hop count must be between 1 and 8, got %d", hopCount)
	}
	return nil
}

// selectTunnelPeers selects and validates peers for tunnel hops.
func (tb *TunnelBuilder) selectTunnelPeers(req BuildTunnelRequest) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":            "(TunnelBuilder) selectTunnelPeers",
		"phase":         "tunnel_build",
		"step":          "peer_selection",
		"reason":        "selecting routers for tunnel hops",
		"hop_count":     req.HopCount,
		"exclude_count": len(req.ExcludePeers),
	}).Debug("selecting tunnel peers")

	peers, err := tb.peerSelector.SelectPeers(req.HopCount, req.ExcludePeers)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":            "(TunnelBuilder) selectTunnelPeers",
			"phase":         "tunnel_build",
			"reason":        "peer selector returned error",
			"hop_count":     req.HopCount,
			"exclude_count": len(req.ExcludePeers),
		}).Error("peer selection failed")
		return nil, fmt.Errorf("failed to select peers: %w", err)
	}

	if len(peers) < req.HopCount {
		log.WithFields(logger.Fields{
			"at":        "(TunnelBuilder) selectTunnelPeers",
			"phase":     "tunnel_build",
			"reason":    "insufficient peers returned by selector",
			"needed":    req.HopCount,
			"got":       len(peers),
			"shortfall": req.HopCount - len(peers),
		}).Error("not enough peers")
		return nil, fmt.Errorf("insufficient peers: need %d, got %d", req.HopCount, len(peers))
	}

	log.WithFields(logger.Fields{
		"at":         "(TunnelBuilder) selectTunnelPeers",
		"phase":      "tunnel_build",
		"step":       "peer_selection",
		"reason":     "peer selection completed successfully",
		"peer_count": len(peers),
	}).Debug("successfully selected tunnel peers")
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
	layerKey, ivKey, replyKey, replyIV, err := generateHopCryptoKeys()
	if err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{}, err
	}

	receiveTunnel, nextTunnel, ourIdent, nextIdent, err := tb.determineRoutingParams(
		hopIndex, req, tunnelID, peers,
	)
	if err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{}, fmt.Errorf("failed to determine routing params: %w", err)
	}

	padding, err := generateRecordPadding()
	if err != nil {
		return BuildRequestRecord{}, session_key.SessionKey{}, [16]byte{}, err
	}

	record := assembleBuildRecord(
		receiveTunnel, nextTunnel, ourIdent, nextIdent,
		layerKey, ivKey, replyKey, replyIV, padding,
	)

	return record, replyKey, replyIV, nil
}

// generateHopCryptoKeys generates all cryptographic keys needed for a tunnel hop.
func generateHopCryptoKeys() (layerKey, ivKey, replyKey session_key.SessionKey, replyIV [16]byte, err error) {
	layerKey, err = generateSessionKey()
	if err != nil {
		err = fmt.Errorf("failed to generate layer key: %w", err)
		return
	}

	ivKey, err = generateSessionKey()
	if err != nil {
		err = fmt.Errorf("failed to generate IV key: %w", err)
		return
	}

	replyKey, err = generateSessionKey()
	if err != nil {
		err = fmt.Errorf("failed to generate reply key: %w", err)
		return
	}

	if _, err = rand.Read(replyIV[:]); err != nil {
		err = fmt.Errorf("failed to generate reply IV: %w", err)
		return
	}

	return
}

// generateRecordPadding generates random padding for a build request record.
func generateRecordPadding() ([29]byte, error) {
	var padding [29]byte
	if _, err := rand.Read(padding[:]); err != nil {
		return [29]byte{}, fmt.Errorf("failed to generate padding: %w", err)
	}
	return padding, nil
}

// assembleBuildRecord creates a BuildRequestRecord from its components.
func assembleBuildRecord(
	receiveTunnel, nextTunnel TunnelID,
	ourIdent, nextIdent common.Hash,
	layerKey, ivKey, replyKey session_key.SessionKey,
	replyIV [16]byte,
	padding [29]byte,
) BuildRequestRecord {
	return BuildRequestRecord{
		ReceiveTunnel: receiveTunnel,
		OurIdent:      ourIdent,
		NextTunnel:    nextTunnel,
		NextIdent:     nextIdent,
		LayerKey:      layerKey,
		IVKey:         ivKey,
		ReplyKey:      replyKey,
		ReplyIV:       replyIV,
		Flag:          0,
		RequestTime:   time.Now(),
		SendMessageID: generateMessageID(),
		Padding:       padding,
	}
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
) (receiveTunnel, nextTunnel TunnelID, ourIdent, nextIdent common.Hash, err error) {
	ourIdent, err = peers[hopIndex].IdentHash()
	if err != nil {
		return 0, 0, common.Hash{}, common.Hash{}, fmt.Errorf("failed to get hop %d identity: %w", hopIndex, err)
	}

	if req.IsInbound {
		receiveTunnel, nextTunnel, nextIdent, err = tb.determineInboundRouting(hopIndex, req, tunnelID, peers)
		if err != nil {
			return 0, 0, common.Hash{}, common.Hash{}, err
		}
	} else {
		receiveTunnel, nextTunnel, nextIdent, err = tb.determineOutboundRouting(hopIndex, tunnelID, peers)
		if err != nil {
			return 0, 0, common.Hash{}, common.Hash{}, err
		}
	}

	return
}

func (tb *TunnelBuilder) determineInboundRouting(
	hopIndex int,
	req BuildTunnelRequest,
	tunnelID TunnelID,
	peers []router_info.RouterInfo,
) (receiveTunnel, nextTunnel TunnelID, nextIdent common.Hash, err error) {
	isFirstHop := hopIndex == 0
	isLastHop := hopIndex == len(peers)-1

	// Inbound tunnel: messages flow from network toward us
	if isFirstHop {
		receiveTunnel = 0 // Endpoint receives from sender (unknown tunnel ID)
	} else {
		receiveTunnel = tunnelID // Middle/gateway receives from previous hop
	}

	if isLastHop {
		// Gateway sends to our specified tunnel
		nextTunnel = req.ReplyTunnelID
		nextIdent = req.ReplyGateway
	} else {
		// Endpoint/middle sends to next hop
		nextTunnel = tunnelID
		nextIdent, err = peers[hopIndex+1].IdentHash()
		if err != nil {
			return 0, 0, common.Hash{}, fmt.Errorf("failed to get next hop identity at index %d: %w", hopIndex+1, err)
		}
	}

	return
}

func (tb *TunnelBuilder) determineOutboundRouting(
	hopIndex int,
	tunnelID TunnelID,
	peers []router_info.RouterInfo,
) (receiveTunnel, nextTunnel TunnelID, nextIdent common.Hash, err error) {
	isLastHop := hopIndex == len(peers)-1

	// Outbound tunnel: messages flow from us toward network
	receiveTunnel = tunnelID // All hops receive with the tunnel ID

	if isLastHop {
		// Endpoint sends to destination (tunnel ID set per message)
		nextTunnel = 0
		nextIdent = common.Hash{} // Empty hash, set per message
	} else {
		// Gateway/middle sends to next hop
		nextTunnel = tunnelID
		nextIdent, err = peers[hopIndex+1].IdentHash()
		if err != nil {
			return 0, 0, common.Hash{}, fmt.Errorf("failed to get next hop identity at index %d: %w", hopIndex+1, err)
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
	// rand.Read from crypto/rand only errors if the system's secure random
	// number generator fails. This is extremely rare and if it happens, the
	// system has bigger problems. Using a zero ID is safe as message IDs
	// are used for correlation, not security.
	_, _ = rand.Read(buf[:])

	return int(uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3]))
}
