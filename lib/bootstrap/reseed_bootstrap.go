package bootstrap

import (
	"context"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/logger"

	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// ReseedBootstrap implements the Bootstrap interface using HTTP reseeding
type ReseedBootstrap struct {
	// Configuration containing reseed servers
	config *config.BootstrapConfig
}

// NewReseedBootstrap creates a new reseeder with the provided configuration
func NewReseedBootstrap(config *config.BootstrapConfig) *ReseedBootstrap {
	log.WithField("reseed_server_count", len(config.ReseedServers)).Info("Initializing reseed bootstrap")
	for i, server := range config.ReseedServers {
		log.WithFields(logger.Fields{
			"index": i,
			"url":   server.Url,
		}).Debug("Configured reseed server")
	}
	return &ReseedBootstrap{
		config: config,
	}
}

// GetPeers implements the Bootstrap interface by obtaining RouterInfos
// from configured reseed servers
func (rb *ReseedBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	rb.logReseedStart(n)

	var allRouterInfos []router_info.RouterInfo
	var lastErr error
	var attemptedServers int
	var successfulServers int

	for _, server := range rb.config.ReseedServers {
		attemptedServers++

		if shouldStop, err := rb.checkContextCancellation(ctx, attemptedServers, successfulServers, len(allRouterInfos)); shouldStop {
			return nil, err
		}

		serverRIs, err := rb.attemptReseedFromServer(server, attemptedServers)
		if err != nil {
			lastErr = err
			continue
		}

		successfulServers++
		allRouterInfos = append(allRouterInfos, serverRIs...)
		rb.logServerSuccess(server, len(serverRIs), len(allRouterInfos), successfulServers)

		if rb.hasEnoughPeers(n, len(allRouterInfos)) {
			break
		}
	}

	if err := rb.validateResults(allRouterInfos, lastErr, attemptedServers, successfulServers); err != nil {
		return nil, err
	}

	rb.logReseedComplete(len(allRouterInfos), attemptedServers, successfulServers, n)
	return allRouterInfos, nil
}

// logReseedStart logs the beginning of the bootstrap peer acquisition.
func (rb *ReseedBootstrap) logReseedStart(n int) {
	log.WithFields(logger.Fields{
		"requested_peers": n,
		"server_count":    len(rb.config.ReseedServers),
	}).Info("Starting bootstrap peer acquisition")
}

// checkContextCancellation checks if the context has been canceled.
func (rb *ReseedBootstrap) checkContextCancellation(ctx context.Context, attemptedServers, successfulServers, collectedPeers int) (bool, error) {
	if ctx.Err() != nil {
		log.WithError(ctx.Err()).WithFields(logger.Fields{
			"attempted_servers":  attemptedServers,
			"successful_servers": successfulServers,
			"collected_peers":    collectedPeers,
		}).Warn("Bootstrap reseed canceled by context")
		return true, oops.Errorf("reseed canceled: %v", ctx.Err())
	}
	return false, nil
}

// attemptReseedFromServer attempts to reseed from a single server.
func (rb *ReseedBootstrap) attemptReseedFromServer(server *config.ReseedConfig, attemptNumber int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"server":        server.Url,
		"attempt":       attemptNumber,
		"total_servers": len(rb.config.ReseedServers),
	}).Info("Attempting to reseed from server")

	reseeder := reseed.NewReseed()
	serverRIs, err := reseeder.SingleReseed(server.Url)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"server":  server.Url,
			"attempt": attemptNumber,
		}).Warn("Reseed attempt failed")
		return nil, oops.Errorf("reseed from %s failed: %v", server.Url, err)
	}

	return serverRIs, nil
}

// logServerSuccess logs successful retrieval of router infos from a server.
func (rb *ReseedBootstrap) logServerSuccess(server *config.ReseedConfig, count, total, successfulServers int) {
	log.WithFields(logger.Fields{
		"server":             server.Url,
		"count":              count,
		"total":              total,
		"successful_servers": successfulServers,
	}).Info("Successfully obtained router infos from reseed server")
}

// hasEnoughPeers checks if we have collected enough peers.
func (rb *ReseedBootstrap) hasEnoughPeers(requested, obtained int) bool {
	if requested > 0 && obtained >= requested {
		log.WithFields(logger.Fields{
			"requested": requested,
			"obtained":  obtained,
		}).Info("Reached requested peer count, stopping reseed")
		return true
	}
	return false
}

// validateResults checks if we obtained any router infos and returns an error if not.
func (rb *ReseedBootstrap) validateResults(allRouterInfos []router_info.RouterInfo, lastErr error, attemptedServers, successfulServers int) error {
	if len(allRouterInfos) == 0 && lastErr != nil {
		log.WithFields(logger.Fields{
			"attempted_servers":  attemptedServers,
			"successful_servers": successfulServers,
		}).Error("All reseed attempts failed, no peers obtained")
		return oops.Errorf("all reseed attempts failed: %w", lastErr)
	}
	return nil
}

// logReseedComplete logs the completion of bootstrap peer acquisition.
func (rb *ReseedBootstrap) logReseedComplete(totalPeers, attemptedServers, successfulServers, requestedPeers int) {
	log.WithFields(logger.Fields{
		"total_peers":        totalPeers,
		"attempted_servers":  attemptedServers,
		"successful_servers": successfulServers,
		"requested_peers":    requestedPeers,
	}).Info("Bootstrap peer acquisition completed")
}
