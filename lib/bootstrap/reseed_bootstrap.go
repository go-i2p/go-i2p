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
	log.WithFields(logger.Fields{
		"requested_peers": n,
		"server_count":    len(rb.config.ReseedServers),
	}).Info("Starting bootstrap peer acquisition")

	var allRouterInfos []router_info.RouterInfo
	var lastErr error
	var attemptedServers int
	var successfulServers int

	// Try each reseed server until we get enough routerInfos or exhaust all servers
	for _, server := range rb.config.ReseedServers {
		attemptedServers++
		// Check if context is canceled before making request
		if ctx.Err() != nil {
			log.WithError(ctx.Err()).WithFields(logger.Fields{
				"attempted_servers":  attemptedServers,
				"successful_servers": successfulServers,
				"collected_peers":    len(allRouterInfos),
			}).Warn("Bootstrap reseed canceled by context")
			return nil, oops.Errorf("reseed canceled: %v", ctx.Err())
		}

		log.WithFields(logger.Fields{
			"server":        server.Url,
			"attempt":       attemptedServers,
			"total_servers": len(rb.config.ReseedServers),
		}).Info("Attempting to reseed from server")

		// Use the existing Reseed implementation with a timeout context
		reseeder := reseed.NewReseed()

		// Perform the actual reseeding operation synchronously
		serverRIs, err := reseeder.SingleReseed(server.Url)
		if err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"server":  server.Url,
				"attempt": attemptedServers,
			}).Warn("Reseed attempt failed")
			lastErr = oops.Errorf("reseed from %s failed: %v", server.Url, err)
			continue
		}

		// Add the retrieved RouterInfos to our collection
		successfulServers++
		allRouterInfos = append(allRouterInfos, serverRIs...)
		log.WithFields(logger.Fields{
			"server":             server.Url,
			"count":              len(serverRIs),
			"total":              len(allRouterInfos),
			"successful_servers": successfulServers,
		}).Info("Successfully obtained router infos from reseed server")

		// Check if we have enough RouterInfos
		if n > 0 && len(allRouterInfos) >= n {
			log.WithFields(logger.Fields{
				"requested": n,
				"obtained":  len(allRouterInfos),
			}).Info("Reached requested peer count, stopping reseed")
			break
		}
	}

	// If we couldn't get any RouterInfos from any server, return the last error
	if len(allRouterInfos) == 0 && lastErr != nil {
		log.WithFields(logger.Fields{
			"attempted_servers":  attemptedServers,
			"successful_servers": successfulServers,
		}).Error("All reseed attempts failed, no peers obtained")
		return nil, oops.Errorf("all reseed attempts failed: %w", lastErr)
	}

	log.WithFields(logger.Fields{
		"total_peers":        len(allRouterInfos),
		"attempted_servers":  attemptedServers,
		"successful_servers": successfulServers,
		"requested_peers":    n,
	}).Info("Bootstrap peer acquisition completed")

	return allRouterInfos, nil
}
