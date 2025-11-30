package bootstrap

import (
	"context"
	"fmt"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
)

// CompositeBootstrap implements the Bootstrap interface by trying multiple
// bootstrap methods in sequence:
// 1. Local reseed file (if specified) - highest priority
// 2. Remote reseed servers
// 3. Local netDb directories - fallback
type CompositeBootstrap struct {
	fileBootstrap       *FileBootstrap
	reseedBootstrap     *ReseedBootstrap
	localNetDbBootstrap *LocalNetDbBootstrap
	config              *config.BootstrapConfig
}

// NewCompositeBootstrap creates a new composite bootstrap with file, reseed, and local netDb fallback
func NewCompositeBootstrap(cfg *config.BootstrapConfig) *CompositeBootstrap {
	log.Info("Initializing composite bootstrap (file + reseed + local netDb fallback)")

	cb := &CompositeBootstrap{
		reseedBootstrap:     NewReseedBootstrap(cfg),
		localNetDbBootstrap: NewLocalNetDbBootstrap(cfg),
		config:              cfg,
	}

	// Only create file bootstrap if a file path is specified
	if cfg.ReseedFilePath != "" {
		log.WithField("file_path", cfg.ReseedFilePath).Info("Local reseed file specified - will use as highest priority")
		cb.fileBootstrap = NewFileBootstrap(cfg.ReseedFilePath)
	}

	return cb
}

// GetPeers implements the Bootstrap interface by trying file first (if specified),
// then reseed, then falling back to local netDb if both fail
func (cb *CompositeBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.WithField("requested_peers", n).Info("Starting composite bootstrap")

	// First, try file bootstrap if configured
	if cb.fileBootstrap != nil {
		log.Info("Attempting file bootstrap from local reseed file")
		peers, err := cb.fileBootstrap.GetPeers(ctx, n)
		if err == nil && len(peers) > 0 {
			log.WithField("count", len(peers)).Info("Successfully obtained peers from local reseed file")
			return peers, nil
		}

		// Log file bootstrap failure
		if err != nil {
			log.WithError(err).Warn("File bootstrap failed, attempting remote reseed")
		} else {
			log.Warn("File bootstrap returned no peers, attempting remote reseed")
		}
	}

	// Second, try reseed
	log.Info("Attempting reseed bootstrap")
	peers, err := cb.reseedBootstrap.GetPeers(ctx, n)
	if err == nil && len(peers) > 0 {
		log.WithField("count", len(peers)).Info("Successfully obtained peers from reseed")
		return peers, nil
	}

	// Log reseed failure
	if err != nil {
		log.WithError(err).Warn("Reseed bootstrap failed, attempting local netDb fallback")
	} else {
		log.Warn("Reseed bootstrap returned no peers, attempting local netDb fallback")
	}

	// Fall back to local netDb
	log.Info("Attempting local netDb bootstrap")
	peers, err = cb.localNetDbBootstrap.GetPeers(ctx, n)
	if err != nil {
		log.WithError(err).Error("Local netDb bootstrap also failed")
		return nil, fmt.Errorf("all bootstrap methods failed - file, reseed, and local netDb: %w", err)
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("local netDb bootstrap returned no peers")
	}

	log.WithField("count", len(peers)).Info("Successfully obtained peers from local netDb")
	return peers, nil
}
