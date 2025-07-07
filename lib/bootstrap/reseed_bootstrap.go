package bootstrap

import (
	"context"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

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
	return &ReseedBootstrap{
		config: config,
	}
}

// GetPeers implements the Bootstrap interface by obtaining RouterInfos
// from configured reseed servers
func (rb *ReseedBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	var allRouterInfos []router_info.RouterInfo
	var lastErr error

	// Try each reseed server until we get enough routerInfos or exhaust all servers
	for _, server := range rb.config.ReseedServers {
		// Check if context is canceled before making request
		if ctx.Err() != nil {
			return nil, oops.Errorf("reseed canceled: %v", ctx.Err())
		}

		log.WithField("server", server.Url).Debug("Attempting to reseed from server")

		// Use the existing Reseed implementation with a timeout context
		reseeder := reseed.NewReseed()

		// Perform the actual reseeding operation synchronously
		serverRIs, err := reseeder.SingleReseed(server.Url)

		if err != nil {
			log.WithError(err).WithField("server", server.Url).Warn("Reseed attempt failed")
			lastErr = oops.Errorf("reseed from %s failed: %v", server.Url, err)
			continue
		}

		// Add the retrieved RouterInfos to our collection
		allRouterInfos = append(allRouterInfos, serverRIs...)
		log.WithFields(logrus.Fields{
			"server": server.Url,
			"count":  len(serverRIs),
			"total":  len(allRouterInfos),
		}).Info("Successfully obtained router infos from reseed server")

		// Check if we have enough RouterInfos
		if n > 0 && len(allRouterInfos) >= n {
			break
		}
	}

	// If we couldn't get any RouterInfos from any server, return the last error
	if len(allRouterInfos) == 0 && lastErr != nil {
		return nil, oops.Errorf("all reseed attempts failed: %w", lastErr)
	}

	return allRouterInfos, nil
}
