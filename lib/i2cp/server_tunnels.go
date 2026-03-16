package i2cp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// initializeSessionTunnelPools creates and configures tunnel pools for a session.
// This requires both tunnelBuilder and peerSelector to be set via SetTunnelBuilder
// and SetPeerSelector. If either is missing, pools are not initialized and an error
// is returned (but session creation can still proceed).
func (s *Server) initializeSessionTunnelPools(session *Session, config *SessionConfig) error {
	s.mu.RLock()
	builder := s.tunnelBuilder
	selector := s.peerSelector
	s.mu.RUnlock()

	// Check if tunnel infrastructure is available
	if builder == nil || selector == nil {
		return fmt.Errorf("tunnel infrastructure not configured (builder=%v, selector=%v)",
			builder != nil, selector != nil)
	}

	// Create inbound tunnel pool
	inboundConfig := tunnel.PoolConfig{
		MinTunnels:       config.InboundTunnelCount,
		MaxTunnels:       config.InboundTunnelCount + 2, // Allow some extra capacity
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  3,
		HopCount:         config.InboundTunnelLength,
		IsInbound:        true,
	}
	inboundPool := tunnel.NewTunnelPoolWithConfig(selector, inboundConfig)
	inboundPool.SetTunnelBuilder(builder)
	session.SetInboundPool(inboundPool)

	// Create outbound tunnel pool
	outboundConfig := tunnel.PoolConfig{
		MinTunnels:       config.OutboundTunnelCount,
		MaxTunnels:       config.OutboundTunnelCount + 2, // Allow some extra capacity
		TunnelLifetime:   10 * time.Minute,
		RebuildThreshold: 2 * time.Minute,
		BuildRetryDelay:  2 * time.Second,
		MaxBuildRetries:  3,
		HopCount:         config.OutboundTunnelLength,
		IsInbound:        false,
	}
	outboundPool := tunnel.NewTunnelPoolWithConfig(selector, outboundConfig)
	outboundPool.SetTunnelBuilder(builder)
	session.SetOutboundPool(outboundPool)

	log.WithFields(logger.Fields{
		"at":                    "i2cp.Server.initializeSessionTunnelPools",
		"sessionID":             session.ID(),
		"inbound_hop_count":     config.InboundTunnelLength,
		"outbound_hop_count":    config.OutboundTunnelLength,
		"inbound_tunnel_count":  config.InboundTunnelCount,
		"outbound_tunnel_count": config.OutboundTunnelCount,
	}).Info("tunnel_pools_initialized")

	return nil
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
// TODO: Full tunnel pool integration required. The router must:
// 1. Attach tunnel pools with proper TunnelBuilder during session creation
// 2. Provide peer selector for tunnel hop selection
// 3. Integrate with transport layer for tunnel establishment
// 4. Set up tunnel lifecycle management (expiry, rotation)
// Currently pools may not build tunnels automatically without this integration.
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
	payload, err := s.buildRequestVariableLeaseSetPayload(inTunnels)
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
//	1 byte: number of leases (N)
//	For each lease (N times):
//	  32 bytes: tunnel gateway router hash
//	  4 bytes:  tunnel ID (big endian uint32)
//	  8 bytes:  end date (milliseconds since epoch, big endian uint64)
func (s *Server) buildRequestVariableLeaseSetPayload(tunnels []*tunnel.TunnelState) ([]byte, error) {
	validTunnels, err := filterValidTunnels(tunnels)
	if err != nil {
		return nil, err
	}

	return encodeLeaseSetPayload(validTunnels), nil
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
		return nil, fmt.Errorf("no valid tunnels provided")
	}
	if len(validTunnels) > 16 {
		validTunnels = validTunnels[:16]
	}
	return validTunnels, nil
}

// encodeLeaseSetPayload serializes validated tunnels into the I2CP
// RequestVariableLeaseSet payload format: 1 byte count followed by
// N lease entries of 44 bytes each (32-byte hash + 4-byte ID + 8-byte end date).
func encodeLeaseSetPayload(tunnels []*tunnel.TunnelState) []byte {
	payload := make([]byte, 1+len(tunnels)*44)
	payload[0] = byte(len(tunnels))

	offset := 1
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
