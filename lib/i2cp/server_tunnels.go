package i2cp

import (
	"encoding/binary"
	"net"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// backupQuantityOrDefault returns the backup quantity, defaulting to 2 if not explicitly set.
func backupQuantityOrDefault(backup int) int {
	if backup > 0 {
		return backup
	}
	return 2
}

// applyLengthVariance adjusts hop count by the configured length variance.
// Positive variance adds hops; negative variance subtracts (minimum 0 hops).
func applyLengthVariance(baseLength, variance int) int {
	adjusted := baseLength + variance
	if adjusted < 0 {
		return 0
	}
	return adjusted
}

// initializeSessionTunnelPools creates and configures tunnel pools for a session.
// This requires both tunnelBuilder and peerSelector to be set via SetTunnelBuilder
// and SetPeerSelector. If either is missing, pools are not initialized and an error
// is returned (but session creation can still proceed).
func (s *Server) initializeSessionTunnelPools(session *Session, config *SessionConfig) error {
	builder, selector, err := s.getTunnelInfrastructure()
	if err != nil {
		return err
	}

	return s.initializeSessionTunnelPoolsWithInfrastructure(session, config, builder, selector)
}

func (s *Server) initializeSessionTunnelPoolsWithInfrastructure(session *Session, config *SessionConfig, builder tunnel.BuilderInterface, selector tunnel.PeerSelector) error {
	inboundPool, err := s.createInboundPool(session, config, builder, selector)
	if err != nil {
		return err
	}

	if err := s.createOutboundPool(session, config, builder, selector, inboundPool); err != nil {
		return err
	}

	s.logPoolsInitialized(session, config)
	return nil
}

// getTunnelInfrastructure retrieves the tunnel builder and peer selector.
func (s *Server) getTunnelInfrastructure() (tunnel.BuilderInterface, tunnel.PeerSelector, error) {
	s.mu.RLock()
	builder := s.tunnelBuilder
	selector := s.peerSelector
	s.mu.RUnlock()

	if builder == nil || selector == nil {
		return nil, nil, oops.Errorf("tunnel infrastructure not configured (builder=%v, selector=%v)",
			builder != nil, selector != nil)
	}
	return builder, selector, nil
}

// createInboundPool creates and starts the inbound tunnel pool.
func (s *Server) createInboundPool(session *Session, config *SessionConfig, builder tunnel.BuilderInterface, selector tunnel.PeerSelector) (*tunnel.Pool, error) {
	return s.createInboundPoolWithConfig(session, config, builder, selector)
}

// createOutboundPool creates and starts the outbound tunnel pool.
func (s *Server) createOutboundPool(session *Session, config *SessionConfig, builder tunnel.BuilderInterface, selector tunnel.PeerSelector, inboundPool *tunnel.Pool) error {
	_, err := s.createOutboundPoolWithConfig(session, config, builder, selector, inboundPool)
	return err
}

// createInboundPoolWithConfig creates, configures, and starts an inbound pool.
func (s *Server) createInboundPoolWithConfig(session *Session, config *SessionConfig, builder tunnel.BuilderInterface, selector tunnel.PeerSelector) (*tunnel.Pool, error) {
	backup := backupQuantityOrDefault(config.InboundBackupQuantity)
	pool := s.newSessionPool(
		session,
		selector,
		builder,
		buildPoolConfig(
			config.InboundTunnelCount,
			backup,
			config.InboundTunnelLength,
			config.InboundLengthVariance,
			true,
		),
	)
	pool.SetReplyTunnelProvider(makeReplyTunnelProvider(pool))
	session.SetInboundPool(pool)

	if err := pool.StartMaintenance(); err != nil {
		return pool, oops.Errorf("failed to start inbound tunnel pool maintenance: %w", err)
	}

	return pool, nil
}

// createOutboundPoolWithConfig creates, configures, and starts an outbound pool.
func (s *Server) createOutboundPoolWithConfig(session *Session, config *SessionConfig, builder tunnel.BuilderInterface, selector tunnel.PeerSelector, inboundPool *tunnel.Pool) (*tunnel.Pool, error) {
	backup := backupQuantityOrDefault(config.OutboundBackupQuantity)
	pool := s.newSessionPool(
		session,
		selector,
		builder,
		buildPoolConfig(
			config.OutboundTunnelCount,
			backup,
			config.OutboundTunnelLength,
			config.OutboundLengthVariance,
			false,
		),
	)
	pool.SetReplyTunnelProvider(makeReplyTunnelProvider(inboundPool))
	session.SetOutboundPool(pool)

	if err := pool.StartMaintenance(); err != nil {
		if inboundPool != nil {
			inboundPool.Stop()
		}
		return pool, oops.Errorf("failed to start outbound tunnel pool maintenance: %w", err)
	}

	return pool, nil
}

// newSessionPool applies common session-pool setup independent of direction.
func (s *Server) newSessionPool(session *Session, selector tunnel.PeerSelector, builder tunnel.BuilderInterface, config tunnel.PoolConfig) *tunnel.Pool {
	pool := tunnel.NewTunnelPoolWithConfig(selector, config)
	pool.SetTunnelBuilder(builder)
	// Set the client session ID so that tunnel endpoint registration can identify the owning session.
	pool.SetClientSessionID(session.ID())
	s.applySessionPoolRoutingConfig(pool)
	return pool
}

// buildPoolConfig constructs a tunnel pool configuration with standard timeouts.
// All pools created here belong to I2CP client sessions and are marked IsClientPool=true
// so that successful builds are counted separately from the router's exploratory tunnels.
func buildPoolConfig(tunnelCount, backupQty, tunnelLength, lengthVariance int, isInbound bool) tunnel.PoolConfig {
	return tunnel.PoolConfig{
		MinTunnels:       tunnelCount,
		MaxTunnels:       tunnelCount + backupQty,
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  3,
		HopCount:         applyLengthVariance(tunnelLength, lengthVariance),
		IsInbound:        isInbound,
		IsClientPool:     true,
	}
}

// applySessionPoolRoutingConfig applies server-level routing identity settings
// to a newly-created session tunnel pool.
func (s *Server) applySessionPoolRoutingConfig(pool *tunnel.Pool) {
	s.mu.RLock()
	hash := s.routerHash
	hasHash := s.hasRouterHash
	s.mu.RUnlock()

	if hasHash {
		pool.SetRouterHash(hash)
		return
	}

	var zeroHash common.Hash
	pool.SetRouterHash(zeroHash)
	log.WithFields(logger.Fields{
		"at":     "i2cp.Server.applySessionPoolRoutingConfig",
		"reason": "router hash not yet configured for session pool",
	}).Warn("session pool router hash not configured")
}

// makeReplyTunnelProvider returns a provider that picks a stable active tunnel
// from the given pool for reply routing.
func makeReplyTunnelProvider(pool *tunnel.Pool) func() (tunnel.TunnelID, common.Hash, bool) {
	return func() (tunnel.TunnelID, common.Hash, bool) {
		if pool == nil {
			return 0, common.Hash{}, false
		}
		active := pool.GetActiveTunnels()
		if len(active) == 0 {
			return 0, common.Hash{}, false
		}
		if len(active[0].Hops) > 0 {
			return active[0].ID, active[0].Hops[0], true
		}
		return active[0].ID, common.Hash{}, true
	}
}

// logPoolsInitialized logs tunnel pool initialization details.
func (s *Server) logPoolsInitialized(session *Session, config *SessionConfig) {
	inboundBackup := backupQuantityOrDefault(config.InboundBackupQuantity)
	outboundBackup := backupQuantityOrDefault(config.OutboundBackupQuantity)
	log.WithFields(logger.Fields{
		"at":                       "i2cp.Server.initializeSessionTunnelPools",
		"sessionID":                session.ID(),
		"inbound_hop_count":        applyLengthVariance(config.InboundTunnelLength, config.InboundLengthVariance),
		"outbound_hop_count":       applyLengthVariance(config.OutboundTunnelLength, config.OutboundLengthVariance),
		"inbound_tunnel_count":     config.InboundTunnelCount,
		"outbound_tunnel_count":    config.OutboundTunnelCount,
		"inbound_backup_quantity":  inboundBackup,
		"outbound_backup_quantity": outboundBackup,
		"inbound_length_variance":  config.InboundLengthVariance,
		"outbound_length_variance": config.OutboundLengthVariance,
	}).Info("tunnel_pools_initialized")
}

// rebuildSessionTunnelPools stops existing tunnel pools and creates new ones
// using the session's current (reconfigured) settings.
// This is called after Reconfigure to apply tunnel parameter changes.
func (s *Server) rebuildSessionTunnelPools(session *Session) error {
	// Stop existing pools gracefully
	session.StopTunnelPools()

	// Rebuild with current config
	config := session.Config()
	return s.initializeSessionTunnelPools(session, config)
}

// monitorTunnelsAndRequestLeaseSet monitors a session's tunnel pools and sends
// RequestVariableLeaseSet (type 37) when tunnels are ready. This is required by
// I2CP protocol - the router must tell the client when to publish its LeaseSet.
//
// Per I2CP spec: After session creation, router waits for inbound+outbound tunnels,
// then sends type 37 with lease data. Client responds with CreateLeaseSet (type 5).
//
// Tunnel pools are initialized with TunnelBuilder and PeerSelector during session
// creation (initializeSessionTunnelPools), and their maintenance loops are started
// automatically. This monitor waits for the pools to report tunnel readiness.
func (s *Server) monitorTunnelsAndRequestLeaseSet(session *Session, conn net.Conn) {
	sessionID := session.ID()
	logMonitoringStart(sessionID)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(2 * time.Minute)
	s.waitForTunnelReadiness(session, conn, sessionID, ticker, timeout)
}

// waitForTunnelReadiness polls tunnel pools until tunnels are ready, context is cancelled, or timeout occurs.
func (s *Server) waitForTunnelReadiness(session *Session, conn net.Conn, sessionID uint16, ticker *time.Ticker, timeout <-chan time.Time) {
	for {
		if s.checkMonitoringEvent(session, conn, sessionID, ticker, timeout) {
			return
		}
	}
}

// checkMonitoringEvent processes a single monitoring event and returns true if monitoring should stop.
func (s *Server) checkMonitoringEvent(session *Session, conn net.Conn, sessionID uint16, ticker *time.Ticker, timeout <-chan time.Time) bool {
	select {
	case <-s.ctx.Done():
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
		}).Debug("context_cancelled_stopping_tunnel_monitoring")
		return true

	case <-timeout:
		logTimeoutWaitingForTunnels(sessionID)
		return true

	case <-ticker.C:
		if tunnels, ready := checkTunnelReadiness(session); ready {
			s.handleTunnelsReady(session, conn, sessionID, tunnels)
			return true
		}
		return false
	}
}

// logMonitoringStart logs the start of tunnel monitoring.
func logMonitoringStart(sessionID uint16) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID": sessionID,
	}).Debug("starting_tunnel_monitoring")
}

// logTimeoutWaitingForTunnels logs when tunnel monitoring times out.
func logTimeoutWaitingForTunnels(sessionID uint16) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID": sessionID,
	}).Warn("timeout_waiting_for_tunnels")
}

// tunnelReadinessResult holds tunnel readiness check results.
type tunnelReadinessResult struct {
	inboundTunnels  []*tunnel.TunnelState
	outboundTunnels []*tunnel.TunnelState
}

// checkTunnelReadiness verifies if both inbound and outbound tunnels are available and active.
func checkTunnelReadiness(session *Session) (tunnelReadinessResult, bool) {
	result := tunnelReadinessResult{}

	inboundPool := session.InboundPool()
	outboundPool := session.OutboundPool()

	if inboundPool == nil || outboundPool == nil {
		return result, false
	}

	result.inboundTunnels = inboundPool.GetActiveTunnels()
	result.outboundTunnels = outboundPool.GetActiveTunnels()

	if len(result.inboundTunnels) == 0 || len(result.outboundTunnels) == 0 {
		return result, false
	}

	return result, true
}

// handleTunnelsReady processes tunnel readiness by sending LeaseSet request and starting maintenance.
func (s *Server) handleTunnelsReady(session *Session, conn net.Conn, sessionID uint16, tunnels tunnelReadinessResult) {
	logTunnelsReady(sessionID, len(tunnels.inboundTunnels), len(tunnels.outboundTunnels))

	if err := s.sendLeaseSetRequest(session, conn, sessionID, tunnels.inboundTunnels); err != nil {
		return
	}

	startLeaseSetMaintenance(session, sessionID)
}

// logTunnelsReady logs when tunnels become ready.
func logTunnelsReady(sessionID uint16, inboundCount, outboundCount int) {
	log.WithFields(logger.Fields{
		"at":              "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID":       sessionID,
		"inboundTunnels":  inboundCount,
		"outboundTunnels": outboundCount,
	}).Info("tunnels_ready_sending_leaseset_request")
}

// sendLeaseSetRequest builds and sends the RequestVariableLeaseSet message to the client.
func (s *Server) sendLeaseSetRequest(session *Session, conn net.Conn, sessionID uint16, inTunnels []*tunnel.TunnelState) error {
	payload, err := s.buildRequestVariableLeaseSetPayload(sessionID, inTunnels)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_build_leaseset_request")
		return err
	}

	msg := &Message{
		Type:      MessageTypeRequestVariableLeaseSet,
		SessionID: sessionID,
		Payload:   payload,
	}

	s.mu.RLock()
	writeMu := s.connWriteMu[sessionID]
	s.mu.RUnlock()

	if writeMu != nil {
		writeMu.Lock()
	}
	err = WriteMessage(conn, msg)
	if writeMu != nil {
		writeMu.Unlock()
	}

	if err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_send_leaseset_request")
		return err
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
		"sessionID":   sessionID,
		"payloadSize": len(payload),
	}).Info("sent_request_variable_leaseset")

	return nil
}

// startLeaseSetMaintenance initiates automatic LeaseSet maintenance for the session.
func startLeaseSetMaintenance(session *Session, sessionID uint16) {
	if err := session.StartLeaseSetMaintenance(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
			"error":     err.Error(),
		}).Error("failed_to_start_leaseset_maintenance")
	} else {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Server.monitorTunnelsAndRequestLeaseSet",
			"sessionID": sessionID,
		}).Info("leaseset_maintenance_started")
	}
}

// buildRequestVariableLeaseSetPayload constructs the payload for RequestVariableLeaseSet (type 37).
// Payload format per I2CP spec:
//
//	SessionID: 2 bytes (big endian uint16) - session identifier
//	NumLeases: 1 byte - number of leases (N)
//	For each lease (N times):
//	  32 bytes: tunnel gateway router hash
//	  4 bytes:  tunnel ID (big endian uint32)
//	  8 bytes:  end date (milliseconds since epoch, big endian uint64)
func (s *Server) buildRequestVariableLeaseSetPayload(sessionID uint16, tunnels []*tunnel.TunnelState) ([]byte, error) {
	validTunnels, err := filterValidTunnels(tunnels)
	if err != nil {
		return nil, err
	}

	return encodeLeaseSetPayload(sessionID, validTunnels), nil
}

// filterValidTunnels removes nil and zero-hop tunnels and enforces a maximum
// of 16 leases to keep LeaseSet size reasonable. Returns an error if no valid
// tunnels remain after filtering.
func filterValidTunnels(tunnels []*tunnel.TunnelState) ([]*tunnel.TunnelState, error) {
	validTunnels := make([]*tunnel.TunnelState, 0, len(tunnels))
	for _, tun := range tunnels {
		if tun != nil && len(tun.Hops) > 0 {
			validTunnels = append(validTunnels, tun)
		}
	}
	if len(validTunnels) == 0 {
		return nil, oops.Errorf("no valid tunnels provided")
	}
	if len(validTunnels) > 16 {
		validTunnels = validTunnels[:16]
	}
	return validTunnels, nil
}

// encodeLeaseSetPayload serializes session ID and validated tunnels into the I2CP
// RequestVariableLeaseSet payload format: 2-byte session ID, 1-byte count, followed by
// N lease entries of 44 bytes each (32-byte hash + 4-byte ID + 8-byte end date).
func encodeLeaseSetPayload(sessionID uint16, tunnels []*tunnel.TunnelState) []byte {
	// Payload: SessionID(2 bytes) + NumLeases(1 byte) + 44*N bytes for lease entries
	payload := make([]byte, 2+1+len(tunnels)*44)
	
	// Write session ID (2 bytes, big endian)
	binary.BigEndian.PutUint16(payload[0:2], sessionID)
	
	// Write number of leases (1 byte) at offset 2
	payload[2] = byte(len(tunnels))

	// Write lease entries starting at offset 3
	offset := 3
	now := time.Now()
	for _, tun := range tunnels {
		offset = encodeLeaseEntry(payload, offset, tun, now)
	}
	return payload
}

// encodeLeaseEntry writes a single lease entry (gateway hash, tunnel ID, end date)
// into the payload at the given offset and returns the new offset.
func encodeLeaseEntry(payload []byte, offset int, tun *tunnel.TunnelState, now time.Time) int {
	copy(payload[offset:offset+32], tun.Hops[0][:])
	offset += 32

	binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(tun.ID))
	offset += 4

	endDate := calculateLeaseEndDate(tun.CreatedAt, now)
	binary.BigEndian.PutUint64(payload[offset:offset+8], uint64(endDate.UnixMilli()))
	offset += 8
	return offset
}

// calculateLeaseEndDate computes the lease expiration time. Standard leases
// expire 10 minutes after tunnel creation; stale tunnels receive a 5-minute
// extension from the current time.
func calculateLeaseEndDate(createdAt, now time.Time) time.Time {
	endDate := createdAt.Add(10 * time.Minute)
	if endDate.Before(now) {
		return now.Add(5 * time.Minute)
	}
	return endDate
}
