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

	// Collect errors from all methods for better debugging
	var fileErr, reseedErr, netDbErr error

	// Try file bootstrap first if configured
	if cb.fileBootstrap != nil {
		peers, err := tryFileBootstrap(cb.fileBootstrap, ctx, n)
		if err == nil {
			return peers, nil
		}
		fileErr = err
	}

	// Try reseed bootstrap
	peers, err := tryReseedBootstrap(cb.reseedBootstrap, ctx, n)
	if err == nil {
		return peers, nil
	}
	reseedErr = err

	// Fall back to local netDb
	peers, err = tryLocalNetDbBootstrap(cb.localNetDbBootstrap, ctx, n)
	if err == nil {
		return peers, nil
	}
	netDbErr = err

	// All methods failed - return aggregated error for debugging
	return nil, buildAggregatedError(fileErr, reseedErr, netDbErr)
}

// tryFileBootstrap attempts to obtain peers from the local reseed file.
func tryFileBootstrap(fb *FileBootstrap, ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.Info("Attempting file bootstrap from local reseed file")
	peers, err := fb.GetPeers(ctx, n)

	if err == nil && len(peers) > 0 {
		log.WithField("count", len(peers)).Info("Successfully obtained peers from local reseed file")
		return peers, nil
	}

	logFileBootstrapFailure(err)
	// Preserve actual error details for debugging
	if err != nil {
		return nil, fmt.Errorf("file bootstrap failed: %w", err)
	}
	return nil, fmt.Errorf("file bootstrap returned no peers")
}

// tryReseedBootstrap attempts to obtain peers from remote reseed servers.
func tryReseedBootstrap(rb *ReseedBootstrap, ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.Info("Attempting reseed bootstrap")
	peers, err := rb.GetPeers(ctx, n)

	if err == nil && len(peers) > 0 {
		log.WithField("count", len(peers)).Info("Successfully obtained peers from reseed")
		return peers, nil
	}

	logReseedFailure(err)
	// Preserve actual error details for debugging
	if err != nil {
		return nil, fmt.Errorf("reseed bootstrap failed: %w", err)
	}
	return nil, fmt.Errorf("reseed bootstrap returned no peers")
}

// tryLocalNetDbBootstrap attempts to obtain peers from local netDb directories.
func tryLocalNetDbBootstrap(lb *LocalNetDbBootstrap, ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.Info("Attempting local netDb bootstrap")
	peers, err := lb.GetPeers(ctx, n)
	if err != nil {
		log.WithError(err).Error("Local netDb bootstrap failed")
		// Preserve error details with consistent wrapping
		return nil, fmt.Errorf("local netDb bootstrap failed: %w", err)
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("local netDb bootstrap returned no peers")
	}

	log.WithField("count", len(peers)).Info("Successfully obtained peers from local netDb")
	return peers, nil
}

// logFileBootstrapFailure logs appropriate warnings for file bootstrap failures.
func logFileBootstrapFailure(err error) {
	if err != nil {
		log.WithError(err).Warn("File bootstrap failed, attempting remote reseed")
	} else {
		log.Warn("File bootstrap returned no peers, attempting remote reseed")
	}
}

// logReseedFailure logs appropriate warnings for reseed bootstrap failures.
func logReseedFailure(err error) {
	if err != nil {
		log.WithError(err).Warn("Reseed bootstrap failed, attempting local netDb fallback")
	} else {
		log.Warn("Reseed bootstrap returned no peers, attempting local netDb fallback")
	}
}

// buildAggregatedError creates a detailed error message including all bootstrap method failures.
func buildAggregatedError(fileErr, reseedErr, netDbErr error) error {
	log.Error("All bootstrap methods failed")

	// Build error message with all available error details
	errMsg := "all bootstrap methods failed:"

	if fileErr != nil {
		errMsg += fmt.Sprintf(" file=%v;", fileErr)
	} else {
		errMsg += " file=not attempted;"
	}

	if reseedErr != nil {
		errMsg += fmt.Sprintf(" reseed=%v;", reseedErr)
	}

	if netDbErr != nil {
		errMsg += fmt.Sprintf(" netDb=%v", netDbErr)
	}

	return fmt.Errorf("%s", errMsg)
}
