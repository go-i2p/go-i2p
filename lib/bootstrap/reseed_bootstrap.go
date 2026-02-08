package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/logger"

	"github.com/samber/oops"
)

// ReseedBootstrap implements the Bootstrap interface using HTTP reseeding
type ReseedBootstrap struct {
	// Configuration containing reseed servers
	config *config.BootstrapConfig
}

// NewReseedBootstrap creates a new reseeder with the provided configuration
func NewReseedBootstrap(config *config.BootstrapConfig) *ReseedBootstrap {
	log.WithFields(logger.Fields{
		"at":                  "(ReseedBootstrap) NewReseedBootstrap",
		"phase":               "bootstrap",
		"step":                1,
		"reason":              "initializing reseed bootstrap",
		"reseed_server_count": len(config.ReseedServers),
	}).Info("initializing reseed bootstrap")
	for i, server := range config.ReseedServers {
		log.WithFields(logger.Fields{
			"at":              "(ReseedBootstrap) NewReseedBootstrap",
			"phase":           "bootstrap",
			"step":            i + 2,
			"reason":          "registering reseed server configuration",
			"server_index":    i,
			"server_url":      server.Url,
			"has_fingerprint": server.SU3Fingerprint != "",
			"fingerprint_len": len(server.SU3Fingerprint),
		}).Debug("reseed server configured")
	}
	return &ReseedBootstrap{
		config: config,
	}
}

// GetPeers implements the Bootstrap interface by obtaining RouterInfos
// from configured reseed servers.
//
// When MinReseedServers > 1 and enough servers are configured, it uses
// MultiServerReseed for concurrent fetching with strategy-based result combination.
// This matches Java I2P's security model requiring multiple server confirmation.
//
// Falls back to sequential single-server mode if multi-server reseed fails
// or when MinReseedServers == 1.
func (rb *ReseedBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	rb.logReseedStart(n)

	// Try multi-server reseed first if configured (Java I2P parity)
	if rb.shouldUseMultiServerReseed() {
		peers, err := rb.MultiServerReseed(ctx, n)
		if err == nil && len(peers) > 0 {
			rb.logMultiServerSuccess(len(peers), n)
			return peers, nil
		}
		// Log failure and fall back to single-server mode
		log.WithError(err).WithFields(logger.Fields{
			"at":          "(ReseedBootstrap) GetPeers",
			"phase":       "bootstrap",
			"reason":      "multi-server reseed failed, falling back to single-server",
			"min_servers": rb.config.MinReseedServers,
			"peer_count":  len(peers),
			"fallback":    "single_server_sequential",
		}).Warn("multi-server reseed failed, attempting single-server fallback")
	}

	// Single-server sequential mode (original behavior)
	return rb.singleServerReseed(ctx, n)
}

// shouldUseMultiServerReseed returns true if multi-server mode should be attempted.
func (rb *ReseedBootstrap) shouldUseMultiServerReseed() bool {
	return rb.config.MinReseedServers > 1 &&
		len(rb.config.ReseedServers) >= rb.config.MinReseedServers
}

// logMultiServerSuccess logs successful completion of multi-server reseed.
func (rb *ReseedBootstrap) logMultiServerSuccess(peerCount, requested int) {
	log.WithFields(logger.Fields{
		"at":                "(ReseedBootstrap) GetPeers",
		"phase":             "bootstrap",
		"step":              "complete",
		"reason":            "multi-server reseed completed successfully",
		"routers_obtained":  peerCount,
		"routers_requested": requested,
		"mode":              "multi_server",
	}).Info("multi-server bootstrap peer acquisition completed")
}

// singleServerReseed performs sequential single-server reseed (original GetPeers logic).
// This is used as a fallback when multi-server reseed fails or when MinReseedServers == 1.
func (rb *ReseedBootstrap) singleServerReseed(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	state := &reseedState{
		allRouterInfos: make([]router_info.RouterInfo, 0),
	}

	for _, server := range rb.config.ReseedServers {
		if err := rb.processReseedServer(ctx, server, n, state); err != nil {
			return nil, err
		}

		if rb.hasEnoughPeers(n, len(state.allRouterInfos)) {
			break
		}
	}

	if err := rb.validateResults(state.allRouterInfos, state.lastErr, state.attemptedServers, state.successfulServers); err != nil {
		return nil, err
	}

	rb.logReseedComplete(len(state.allRouterInfos), state.attemptedServers, state.successfulServers, n)
	return state.allRouterInfos, nil
}

type reseedState struct {
	allRouterInfos    []router_info.RouterInfo
	lastErr           error
	attemptedServers  int
	successfulServers int
}

func (rb *ReseedBootstrap) processReseedServer(ctx context.Context, server *config.ReseedConfig, n int, state *reseedState) error {
	state.attemptedServers++

	if shouldStop, err := rb.checkContextCancellation(ctx, state.attemptedServers, state.successfulServers, len(state.allRouterInfos)); shouldStop {
		return err
	}

	serverRIs, err := rb.attemptReseedFromServer(server, state.attemptedServers)
	if err != nil {
		state.lastErr = err
		return nil
	}

	state.successfulServers++
	state.allRouterInfos = append(state.allRouterInfos, serverRIs...)
	rb.logServerSuccess(server, len(serverRIs), len(state.allRouterInfos), state.successfulServers)

	return nil
}

// logReseedStart logs the beginning of the bootstrap peer acquisition.
func (rb *ReseedBootstrap) logReseedStart(n int) {
	log.WithFields(logger.Fields{
		"at":              "(ReseedBootstrap) GetPeers",
		"phase":           "bootstrap",
		"step":            "start",
		"reason":          "initiating peer acquisition from reseed servers",
		"requested_peers": n,
		"server_count":    len(rb.config.ReseedServers),
		"strategy":        "sequential_until_satisfied",
	}).Info("starting bootstrap peer acquisition")
}

// checkContextCancellation checks if the context has been canceled.
func (rb *ReseedBootstrap) checkContextCancellation(ctx context.Context, attemptedServers, successfulServers, collectedPeers int) (bool, error) {
	if ctx.Err() != nil {
		log.WithError(ctx.Err()).WithFields(logger.Fields{
			"at":                 "(ReseedBootstrap) checkContextCancellation",
			"phase":              "bootstrap",
			"reason":             "context canceled during reseed operation",
			"attempted_servers":  attemptedServers,
			"successful_servers": successfulServers,
			"collected_peers":    collectedPeers,
			"context_error":      ctx.Err().Error(),
		}).Warn("bootstrap reseed canceled by context")
		return true, oops.Errorf("reseed canceled: %v", ctx.Err())
	}
	return false, nil
}

// attemptReseedFromServer attempts to reseed from a single server.
func (rb *ReseedBootstrap) attemptReseedFromServer(server *config.ReseedConfig, attemptNumber int) ([]router_info.RouterInfo, error) {
	startTime := time.Now()
	log.WithFields(logger.Fields{
		"at":            "(ReseedBootstrap) attemptReseedFromServer",
		"phase":         "bootstrap",
		"step":          attemptNumber,
		"reason":        "attempting HTTP reseed from server",
		"server_url":    server.Url,
		"attempt":       attemptNumber,
		"total_servers": len(rb.config.ReseedServers),
	}).Info("attempting reseed from server")

	reseeder := reseed.NewReseed()
	serverRIs, err := reseeder.SingleReseed(server.Url)
	elapsed := time.Since(startTime)

	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":          "(ReseedBootstrap) attemptReseedFromServer",
			"phase":       "bootstrap",
			"step":        attemptNumber,
			"reason":      "reseed attempt failed",
			"server_url":  server.Url,
			"attempt":     attemptNumber,
			"duration_ms": elapsed.Milliseconds(),
			"error_type":  fmt.Sprintf("%T", err),
		}).Warn("reseed attempt failed")
		return nil, oops.Errorf("reseed from %s failed: %v", server.Url, err)
	}

	log.WithFields(logger.Fields{
		"at":           "(ReseedBootstrap) attemptReseedFromServer",
		"phase":        "bootstrap",
		"step":         attemptNumber,
		"reason":       "reseed request completed successfully",
		"server_url":   server.Url,
		"duration_ms":  elapsed.Milliseconds(),
		"router_count": len(serverRIs),
	}).Debug("reseed HTTP request completed")

	// Validate RouterInfos and filter out invalid ones
	validServerRIs := rb.validateAndFilterRouterInfos(serverRIs, server.Url)

	log.WithFields(logger.Fields{
		"at":                 "(ReseedBootstrap) attemptReseedFromServer",
		"phase":              "validation",
		"reason":             "RouterInfo validation completed",
		"server_url":         server.Url,
		"total_received":     len(serverRIs),
		"valid_after_filter": len(validServerRIs),
	}).Debug("RouterInfo validation completed for reseed server")

	// Warn if reseed took longer than expected
	if elapsed.Seconds() > 30 {
		log.WithFields(logger.Fields{
			"at":          "(ReseedBootstrap) attemptReseedFromServer",
			"phase":       "bootstrap",
			"reason":      "slow reseed operation detected",
			"server_url":  server.Url,
			"duration_ms": elapsed.Milliseconds(),
			"threshold_s": 30,
			"impact":      "may indicate network issues or server load",
		}).Warn("reseed operation slower than expected")
	}

	// Warn if insufficient routers received
	if len(validServerRIs) < 50 {
		log.WithFields(logger.Fields{
			"at":           "(ReseedBootstrap) attemptReseedFromServer",
			"phase":        "bootstrap",
			"reason":       "insufficient valid routers from reseed server",
			"server_url":   server.Url,
			"router_count": len(validServerRIs),
			"minimum":      50,
			"shortfall":    50 - len(validServerRIs),
			"impact":       "may need additional reseed servers",
		}).Warn("reseed returned fewer valid routers than recommended")
	}

	return validServerRIs, nil
}

// validateAndFilterRouterInfos validates all RouterInfos and returns only valid ones
// It also collects and logs statistics about the validation process
func (rb *ReseedBootstrap) validateAndFilterRouterInfos(routerInfos []router_info.RouterInfo, serverUrl string) []router_info.RouterInfo {
	stats := NewValidationStats()
	validRouterInfos := make([]router_info.RouterInfo, 0, len(routerInfos))

	for _, ri := range routerInfos {
		// CRITICAL FIX #1: Pre-filter for direct NTCP2 connectivity BEFORE validation
		// This prevents ERROR logs from common package when checking introducer-only addresses
		if !HasDirectNTCP2Connectivity(ri) {
			stats.RecordInvalid("no direct NTCP2 connectivity (introducer-only or missing host/port)")
			log.WithFields(logger.Fields{
				"at":          "(ReseedBootstrap) validateAndFilterRouterInfos",
				"phase":       "pre-filter",
				"reason":      "no direct NTCP2 connectivity",
				"router_hash": GetRouterHashString(ri),
				"server_url":  serverUrl,
			}).Debug("skipping RouterInfo without direct NTCP2 connectivity")
			continue
		}

		if err := ValidateRouterInfo(ri); err != nil {
			stats.RecordInvalid(err.Error())
			log.WithFields(logger.Fields{
				"at":          "(ReseedBootstrap) validateAndFilterRouterInfos",
				"phase":       "validation",
				"reason":      "invalid RouterInfo from reseed server",
				"error":       err.Error(),
				"router_hash": GetRouterHashString(ri),
				"server_url":  serverUrl,
			}).Debug("skipping invalid RouterInfo from reseed server")
		} else {
			stats.RecordValid()
			validRouterInfos = append(validRouterInfos, ri)
		}
	}

	// Log validation statistics
	stats.LogSummary("reseed_bootstrap")

	if stats.InvalidRouterInfos > 0 {
		log.WithFields(logger.Fields{
			"at":              "(ReseedBootstrap) validateAndFilterRouterInfos",
			"phase":           "validation",
			"server_url":      serverUrl,
			"invalid_count":   stats.InvalidRouterInfos,
			"valid_count":     stats.ValidRouterInfos,
			"validity_rate":   fmt.Sprintf("%.1f%%", stats.ValidityRate()),
			"invalid_reasons": stats.InvalidReasons,
		}).Warn("some RouterInfos from reseed server failed validation")
	}

	return validRouterInfos
}

// logServerSuccess logs successful retrieval of router infos from a server.
func (rb *ReseedBootstrap) logServerSuccess(server *config.ReseedConfig, count, total, successfulServers int) {
	log.WithFields(logger.Fields{
		"at":                 "(ReseedBootstrap) processReseedServer",
		"phase":              "bootstrap",
		"reason":             "successfully obtained router infos from server",
		"server_url":         server.Url,
		"routers_from_this":  count,
		"routers_total":      total,
		"successful_servers": successfulServers,
		"total_servers":      len(rb.config.ReseedServers),
	}).Info("successfully obtained router infos from reseed server")
}

// hasEnoughPeers checks if we have collected enough peers.
func (rb *ReseedBootstrap) hasEnoughPeers(requested, obtained int) bool {
	if requested > 0 && obtained >= requested {
		log.WithFields(logger.Fields{
			"at":        "(ReseedBootstrap) hasEnoughPeers",
			"phase":     "bootstrap",
			"reason":    "reached requested peer threshold",
			"requested": requested,
			"obtained":  obtained,
			"surplus":   obtained - requested,
		}).Info("reached requested peer count, stopping reseed")
		return true
	}
	return false
}

// validateResults checks if we obtained any router infos and returns an error if not.
func (rb *ReseedBootstrap) validateResults(allRouterInfos []router_info.RouterInfo, lastErr error, attemptedServers, successfulServers int) error {
	if len(allRouterInfos) == 0 && lastErr != nil {
		log.WithFields(logger.Fields{
			"at":                 "(ReseedBootstrap) validateResults",
			"phase":              "bootstrap",
			"reason":             "all reseed attempts failed",
			"attempted_servers":  attemptedServers,
			"successful_servers": successfulServers,
			"failed_servers":     attemptedServers - successfulServers,
			"router_count":       0,
			"last_error":         lastErr.Error(),
			"error_type":         fmt.Sprintf("%T", lastErr),
			"recommendation":     "check network connectivity, firewall, and DNS resolution",
		}).Error("all reseed attempts failed, no peers obtained")
		return oops.Errorf("all reseed attempts failed: %w", lastErr)
	}
	return nil
}

// logReseedComplete logs the completion of bootstrap peer acquisition.
func (rb *ReseedBootstrap) logReseedComplete(totalPeers, attemptedServers, successfulServers, requestedPeers int) {
	log.WithFields(logger.Fields{
		"at":                 "(ReseedBootstrap) GetPeers",
		"phase":              "bootstrap",
		"step":               "complete",
		"reason":             "peer acquisition completed successfully",
		"routers_obtained":   totalPeers,
		"routers_requested":  requestedPeers,
		"attempted_servers":  attemptedServers,
		"successful_servers": successfulServers,
		"failed_servers":     attemptedServers - successfulServers,
		"success_rate":       fmt.Sprintf("%.1f%%", float64(successfulServers)/float64(attemptedServers)*100),
	}).Info("bootstrap peer acquisition completed")
}
