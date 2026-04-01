package i2cp

import (
	"fmt"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// StartLeaseSetMaintenance begins automatic LeaseSet maintenance.
// This runs a background goroutine that:
// - Regenerates the LeaseSet before it expires
// - Publishes updated LeaseSets when tunnels change
// - Ensures the session remains reachable on the network
//
// The maintenance interval is calculated based on TunnelLifetime:
// - Check every TunnelLifetime/4 (e.g., every 2.5 minutes for 10-minute tunnels)
// - Regenerate when remaining lifetime < TunnelLifetime/2
//
// Must be called after tunnel pools are started.
func (s *Session) StartLeaseSetMaintenance() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return oops.Errorf("session %d is not active", s.id)
	}

	if s.inboundPool == nil {
		return oops.Errorf("session %d has no inbound tunnel pool", s.id)
	}

	// Calculate maintenance interval: check every 1/4 of tunnel lifetime
	// For default 10-minute tunnels, this means checking every 2.5 minutes.
	// Enforce a minimum of 1ms to prevent ticker panic on zero duration.
	maintenanceInterval := s.config.TunnelLifetime / 4
	if maintenanceInterval <= 0 {
		maintenanceInterval = 15 * time.Second
	}

	s.maintTicker = time.NewTicker(maintenanceInterval)

	s.maintWg.Add(1)
	go s.leaseSetMaintenanceLoop()

	log.WithFields(logger.Fields{
		"at":                  "i2cp.Session.StartLeaseSetMaintenance",
		"sessionID":           s.id,
		"maintenanceInterval": maintenanceInterval,
	}).Info("started_leaseset_maintenance")

	return nil
}

// leaseSetMaintenanceLoop runs in a background goroutine to maintain the LeaseSet.
// It periodically checks if the LeaseSet needs regeneration and publishes updates.
func (s *Session) leaseSetMaintenanceLoop() {
	defer s.maintWg.Done()
	defer s.cleanupMaintenanceTicker()

	s.generateInitialLeaseSet()
	s.runMaintenanceTickerLoop()
}

// cleanupMaintenanceTicker stops and clears the maintenance ticker during shutdown.
func (s *Session) cleanupMaintenanceTicker() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maintTicker != nil {
		s.maintTicker.Stop()
		s.maintTicker = nil
	}
}

// generateInitialLeaseSet creates the first LeaseSet immediately upon maintenance start.
func (s *Session) generateInitialLeaseSet() {
	if err := s.maintainLeaseSet(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.generateInitialLeaseSet",
			"sessionID": s.ID(),
			"error":     err,
		}).Error("failed_initial_leaseset_generation")
	}
}

// runMaintenanceTickerLoop executes the main maintenance event loop until stopped.
func (s *Session) runMaintenanceTickerLoop() {
	for {
		select {
		case <-s.stopCh:
			s.logMaintenanceStopped()
			return

		case <-s.maintTicker.C:
			s.handleMaintenanceTick()
		}
	}
}

// logMaintenanceStopped records debug information when maintenance is stopped.
func (s *Session) logMaintenanceStopped() {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.logMaintenanceStopped",
		"sessionID": s.ID(),
	}).Debug("leaseset_maintenance_stopped")
}

// handleMaintenanceTick processes periodic LeaseSet maintenance tasks.
func (s *Session) handleMaintenanceTick() {
	if err := s.maintainLeaseSet(); err != nil {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.handleMaintenanceTick",
			"sessionID": s.ID(),
			"error":     err,
		}).Warn("failed_to_maintain_leaseset")
	}
}

// maintainLeaseSet checks if LeaseSet needs regeneration and publishes if needed.
// Regeneration is triggered when:
// - No LeaseSet exists yet
// - Current LeaseSet is more than half its lifetime old
// - Tunnel pool has changed significantly
func (s *Session) maintainLeaseSet() error {
	needsRegeneration := s.checkLeaseSetRegeneration()

	if !needsRegeneration {
		return nil
	}

	return s.regenerateAndPublishLeaseSet()
}

// checkLeaseSetRegeneration evaluates whether the LeaseSet requires regeneration.
// Returns true if no LeaseSet exists or if the current LeaseSet exceeds half its lifetime.
func (s *Session) checkLeaseSetRegeneration() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentLeaseSet == nil {
		s.logLeaseSetMissing()
		return true
	}

	return s.evaluateLeaseSetAge()
}

// logLeaseSetMissing logs debug information when no LeaseSet exists.
func (s *Session) logLeaseSetMissing() {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.maintainLeaseSet",
		"sessionID": s.id,
	}).Debug("no_leaseset_exists_generating_new")
}

// evaluateLeaseSetAge determines if the current LeaseSet is too old and needs regeneration.
// Regeneration occurs when more than half the tunnel lifetime has elapsed.
func (s *Session) evaluateLeaseSetAge() bool {
	now := time.Now()
	age := now.Sub(s.leaseSetPublishedAt)
	regenerationThreshold := s.config.TunnelLifetime / 2

	if age > regenerationThreshold {
		s.logLeaseSetExpiration(age, regenerationThreshold)
		return true
	}

	return false
}

// logLeaseSetExpiration logs debug information when LeaseSet exceeds regeneration threshold.
func (s *Session) logLeaseSetExpiration(age, threshold time.Duration) {
	log.WithFields(logger.Fields{
		"at":                    "i2cp.Session.maintainLeaseSet",
		"sessionID":             s.id,
		"age":                   age,
		"regenerationThreshold": threshold,
	}).Debug("leaseset_exceeds_regeneration_threshold")
}

// regenerateAndPublishLeaseSet creates a new LeaseSet and publishes it to the network.
// This method:
// 1. Creates a fresh LeaseSet from current inbound tunnels (LeaseSet2 or EncryptedLeaseSet)
// 2. Publishes it to the local NetDB
// 3. Distributes it to floodfill routers (if publisher is configured)
//
// Returns an error if LeaseSet creation or publication fails.
func (s *Session) regenerateAndPublishLeaseSet() error {
	var leaseSetBytes []byte
	var err error

	// Read config under lock to avoid data race with Reconfigure
	s.mu.RLock()
	useEncrypted := s.config.UseEncryptedLeaseSet
	dontPublish := s.config.DontPublishLeaseSet
	s.mu.RUnlock()

	// Choose LeaseSet type based on configuration
	if useEncrypted {
		leaseSetBytes, err = s.CreateEncryptedLeaseSet()
		if err != nil {
			return oops.Errorf("failed to create EncryptedLeaseSet: %w", err)
		}
	} else {
		leaseSetBytes, err = s.CreateLeaseSet()
		if err != nil {
			return oops.Errorf("failed to create LeaseSet: %w", err)
		}
	}

	s.logLeaseSetRegenerated(leaseSetBytes)

	// Honor i2cp.dontPublishLeaseSet: create the LeaseSet but skip
	// network publication. This is used for services that want to
	// receive connections only from peers they've given the LeaseSet
	// directly (out-of-band), or for testing.
	if dontPublish {
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.regenerateAndPublishLeaseSet",
			"sessionID": s.ID(),
		}).Debug("skipping_leaseset_publication_dontPublishLeaseSet_is_set")
		return nil
	}

	// Publish to network database if publisher is configured
	if err := s.publishLeaseSetToNetwork(leaseSetBytes); err != nil {
		// Log the error but don't fail - LeaseSet is still cached locally
		log.WithFields(logger.Fields{
			"at":        "i2cp.Session.regenerateAndPublishLeaseSet",
			"sessionID": s.ID(),
			"error":     err,
		}).Warn("failed_to_publish_leaseset_to_network")
	}

	return nil
}

// publishLeaseSetToNetwork publishes the LeaseSet to the network database.
// Skips publication if no publisher is configured (allows sessions to work without network integration).
// For EncryptedLeaseSet, publishes using the blinded destination hash instead of the original.
func (s *Session) publishLeaseSetToNetwork(leaseSetBytes []byte) error {
	s.mu.RLock()
	publisher := s.publisher
	useEncrypted := s.config.UseEncryptedLeaseSet
	blindedDest := s.blindedDestination
	s.mu.RUnlock()

	if publisher == nil {
		// No publisher configured - this is acceptable for testing or standalone sessions
		return nil
	}

	// Calculate destination hash for publication
	destHash, err := s.calculatePublicationHash(useEncrypted, blindedDest)
	if err != nil {
		return err
	}

	// Publish to network
	if err := s.publishToPublisher(publisher, destHash, leaseSetBytes, useEncrypted); err != nil {
		return err
	}

	return nil
}

// calculatePublicationHash determines the correct hash for LeaseSet publication.
func (s *Session) calculatePublicationHash(useEncrypted bool, blindedDest *destination.Destination) (data.Hash, error) {
	if useEncrypted && blindedDest != nil {
		// For EncryptedLeaseSet, use blinded destination hash
		destBytes, err := blindedDest.Bytes()
		if err != nil {
			return data.Hash{}, oops.Errorf("failed to get blinded destination bytes: %w", err)
		}
		return data.HashData(destBytes), nil
	}

	// For normal LeaseSet2, use original destination hash
	destBytes, err := s.destination.Bytes()
	if err != nil {
		return data.Hash{}, oops.Errorf("failed to get destination bytes: %w", err)
	}
	return data.HashData(destBytes), nil
}

// publishToPublisher executes the publication and logs the result.
func (s *Session) publishToPublisher(publisher LeaseSetPublisher, destHash data.Hash, leaseSetBytes []byte, useEncrypted bool) error {
	if err := publisher.PublishLeaseSet(destHash, leaseSetBytes); err != nil {
		return oops.Errorf("publisher failed: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":          "i2cp.Session.publishLeaseSetToNetwork",
		"sessionID":   s.ID(),
		"destHash":    fmt.Sprintf("%x", destHash[:8]),
		"isEncrypted": useEncrypted,
	}).Debug("leaseset_published_to_network")

	return nil
}

// logLeaseSetRegenerated logs information about successful LeaseSet regeneration.
func (s *Session) logLeaseSetRegenerated(leaseSetBytes []byte) {
	log.WithFields(logger.Fields{
		"at":        "i2cp.Session.maintainLeaseSet",
		"sessionID": s.ID(),
		"size":      len(leaseSetBytes),
	}).Info("leaseset_regenerated")
}

// CurrentLeaseSet returns the currently cached LeaseSet, if any.
// Returns nil if no LeaseSet has been generated yet.
func (s *Session) CurrentLeaseSet() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentLeaseSet
}

// SetCurrentLeaseSet caches externally-provided LeaseSet bytes (e.g. from CreateLeaseSet2).
// Updates the currentLeaseSet and leaseSetPublishedAt timestamp.
func (s *Session) SetCurrentLeaseSet(leaseSetBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentLeaseSet = leaseSetBytes
	s.leaseSetPublishedAt = time.Now()
}

// ValidateLeaseSet2Data parses and validates client-provided LeaseSet2 bytes.
// Ensures the data is structurally valid and that the embedded destination
// matches the session's destination. Returns an error if validation fails.
//
// Checks performed:
//  1. Structural parsing via ReadLeaseSet2 (validates all fields and signature)
//  2. Destination match: the LeaseSet2's destination must match this session's destination
//  3. Expiration: the LeaseSet2 must not already be expired
func (s *Session) ValidateLeaseSet2Data(leaseSetBytes []byte) error {
	// Parse the LeaseSet2 to verify structural validity
	ls2, _, err := lease_set2.ReadLeaseSet2(leaseSetBytes)
	if err != nil {
		return oops.Errorf("invalid LeaseSet2 structure: %w", err)
	}

	// Verify the LeaseSet2's destination matches this session's destination
	s.mu.RLock()
	sessionDest := s.destination
	s.mu.RUnlock()

	if sessionDest == nil {
		return oops.Errorf("session has no destination configured")
	}

	if err := matchDestinations(sessionDest, ls2.Destination()); err != nil {
		return oops.Errorf("destination mismatch: %w", err)
	}

	// Verify the LeaseSet2 is not already expired
	if ls2.IsExpired() {
		return oops.Errorf("LeaseSet2 is already expired (published: %v, expires offset: %d)",
			ls2.PublishedTime(), ls2.Expires())
	}

	return nil
}

// matchDestinations compares two destinations by their signing public keys.
// The signing public key is the identity-critical component and is stable
// across serialization round-trips (construct → serialize → parse).
// Returns nil if they match, or an error describing the mismatch.
func matchDestinations(sessionDest *destination.Destination, lsDest destination.Destination) error {
	sessionSPK, err := sessionDest.SigningPublicKey()
	if err != nil {
		return oops.Errorf("failed to get session signing public key: %w", err)
	}

	lsSPK, err := lsDest.SigningPublicKey()
	if err != nil {
		return oops.Errorf("failed to get LeaseSet2 signing public key: %w", err)
	}

	sessionSPKBytes := sessionSPK.Bytes()
	lsSPKBytes := lsSPK.Bytes()

	if len(sessionSPKBytes) != len(lsSPKBytes) {
		return oops.Errorf("signing key length mismatch: session=%d, leaseset=%d",
			len(sessionSPKBytes), len(lsSPKBytes))
	}

	sessionHash := data.HashData(sessionSPKBytes)
	lsHash := data.HashData(lsSPKBytes)

	if sessionHash != lsHash {
		return oops.Errorf("LeaseSet2 destination hash %x does not match session destination hash %x",
			lsHash[:8], sessionHash[:8])
	}

	return nil
}

// LeaseSetAge returns how long ago the current LeaseSet was published.
// Returns 0 if no LeaseSet exists.
func (s *Session) LeaseSetAge() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentLeaseSet == nil {
		return 0
	}

	return time.Since(s.leaseSetPublishedAt)
}
