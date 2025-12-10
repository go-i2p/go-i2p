package bootstrap

import (
	"context"
	"fmt"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
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
	log.WithFields(logger.Fields{
		"at":     "(CompositeBootstrap) NewCompositeBootstrap",
		"phase":  "bootstrap",
		"step":   1,
		"reason": "initializing composite bootstrap strategy",
	}).Info("initializing composite bootstrap (file + reseed + local netDb fallback)")

	cb := &CompositeBootstrap{
		reseedBootstrap:     NewReseedBootstrap(cfg),
		localNetDbBootstrap: NewLocalNetDbBootstrap(cfg),
		config:              cfg,
	}

	// Only create file bootstrap if a file path is specified
	if cfg.ReseedFilePath != "" {
		log.WithFields(logger.Fields{
			"at":        "(CompositeBootstrap) NewCompositeBootstrap",
			"phase":     "bootstrap",
			"step":      2,
			"reason":    "local reseed file configured",
			"file_path": cfg.ReseedFilePath,
			"priority":  "highest",
		}).Info("local reseed file specified - will use as highest priority")
		cb.fileBootstrap = NewFileBootstrap(cfg.ReseedFilePath)
	} else {
		log.WithFields(logger.Fields{
			"at":       "(CompositeBootstrap) NewCompositeBootstrap",
			"phase":    "bootstrap",
			"step":     2,
			"reason":   "no local reseed file configured, using remote servers",
			"fallback": "reseed_servers",
			"strategy": "remote_first",
		}).Warn("no local reseed file configured - will use remote reseed servers")
	}

	return cb
}

// GetPeers implements the Bootstrap interface by trying file first (if specified),
// then reseed, then falling back to local netDb if both fail
func (cb *CompositeBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"at":              "(CompositeBootstrap) GetPeers",
		"phase":           "bootstrap",
		"step":            "start",
		"reason":          "starting composite bootstrap with fallback strategy",
		"requested_peers": n,
		"has_file_source": cb.fileBootstrap != nil,
		"strategy":        "file -> reseed -> local_netdb",
	}).Info("starting composite bootstrap")

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
	log.WithFields(logger.Fields{
		"at":     "(CompositeBootstrap) tryFileBootstrap",
		"phase":  "bootstrap",
		"step":   1,
		"reason": "attempting file bootstrap from local reseed file",
		"limit":  n,
	}).Info("attempting file bootstrap from local reseed file")
	peers, err := fb.GetPeers(ctx, n)

	if err == nil && len(peers) > 0 {
		log.WithFields(logger.Fields{
			"at":           "(CompositeBootstrap) tryFileBootstrap",
			"phase":        "bootstrap",
			"step":         1,
			"reason":       "file bootstrap succeeded",
			"router_count": len(peers),
			"requested":    n,
		}).Info("successfully obtained peers from local reseed file")
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
	log.WithFields(logger.Fields{
		"at":     "(CompositeBootstrap) tryReseedBootstrap",
		"phase":  "bootstrap",
		"step":   2,
		"reason": "attempting reseed bootstrap from remote servers",
		"limit":  n,
	}).Info("attempting reseed bootstrap")
	peers, err := rb.GetPeers(ctx, n)

	if err == nil && len(peers) > 0 {
		log.WithFields(logger.Fields{
			"at":           "(CompositeBootstrap) tryReseedBootstrap",
			"phase":        "bootstrap",
			"step":         2,
			"reason":       "reseed bootstrap succeeded",
			"router_count": len(peers),
			"requested":    n,
		}).Info("successfully obtained peers from reseed")
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
	log.WithFields(logger.Fields{
		"at":     "(CompositeBootstrap) tryLocalNetDbBootstrap",
		"phase":  "bootstrap",
		"step":   3,
		"reason": "attempting local netdb bootstrap fallback",
		"limit":  n,
	}).Info("attempting local netDb bootstrap")
	peers, err := lb.GetPeers(ctx, n)
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(CompositeBootstrap) tryLocalNetDbBootstrap",
			"phase":  "bootstrap",
			"step":   3,
			"reason": "local netdb bootstrap failed",
		}).Error("local netDb bootstrap failed")
		// Preserve error details with consistent wrapping
		return nil, fmt.Errorf("local netDb bootstrap failed: %w", err)
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("local netDb bootstrap returned no peers")
	}

	log.WithFields(logger.Fields{
		"at":           "(CompositeBootstrap) tryLocalNetDbBootstrap",
		"phase":        "bootstrap",
		"step":         3,
		"reason":       "local netdb bootstrap succeeded",
		"router_count": len(peers),
		"requested":    n,
	}).Info("successfully obtained peers from local netDb")
	return peers, nil
}

// logFileBootstrapFailure logs appropriate warnings for file bootstrap failures.
func logFileBootstrapFailure(err error) {
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "(CompositeBootstrap) tryFileBootstrap",
			"phase":      "bootstrap",
			"step":       1,
			"reason":     "file bootstrap failed, will try reseed",
			"error_type": fmt.Sprintf("%T", err),
			"fallback":   "reseed_bootstrap",
			"next_step":  "attempting remote reseed servers",
		}).Warn("file bootstrap failed, attempting remote reseed")
	} else {
		log.WithFields(logger.Fields{
			"at":        "(CompositeBootstrap) tryFileBootstrap",
			"phase":     "bootstrap",
			"step":      1,
			"reason":    "file bootstrap returned no peers",
			"peers":     0,
			"expected":  ">0",
			"fallback":  "reseed_bootstrap",
			"next_step": "attempting remote reseed servers",
		}).Warn("file bootstrap returned no peers, attempting remote reseed")
	}
}

// logReseedFailure logs appropriate warnings for reseed bootstrap failures.
func logReseedFailure(err error) {
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "(CompositeBootstrap) tryReseedBootstrap",
			"phase":      "bootstrap",
			"step":       2,
			"reason":     "reseed bootstrap failed, will try local netdb",
			"error_type": fmt.Sprintf("%T", err),
			"fallback":   "local_netdb_bootstrap",
			"next_step":  "scanning for existing I2P netDb directories",
		}).Warn("reseed bootstrap failed, attempting local netDb fallback")
	} else {
		log.WithFields(logger.Fields{
			"at":        "(CompositeBootstrap) tryReseedBootstrap",
			"phase":     "bootstrap",
			"step":      2,
			"reason":    "reseed bootstrap returned no peers",
			"peers":     0,
			"expected":  ">0",
			"fallback":  "local_netdb_bootstrap",
			"next_step": "scanning for existing I2P netDb directories",
		}).Warn("reseed bootstrap returned no peers, attempting local netDb fallback")
	}
}

// buildAggregatedError creates a detailed error message including all bootstrap method failures.
func buildAggregatedError(fileErr, reseedErr, netDbErr error) error {
	// Helper function to count failures
	countFailures := func(errs ...error) int {
		count := 0
		for _, err := range errs {
			if err != nil {
				count++
			}
		}
		return count
	}

	log.WithFields(logger.Fields{
		"at":             "(CompositeBootstrap) Bootstrap",
		"phase":          "bootstrap",
		"reason":         "all_methods_exhausted",
		"file_attempted": fileErr != nil,
		"reseed_failed":  reseedErr != nil,
		"netdb_failed":   netDbErr != nil,
		"methods_tried":  3,
		"methods_failed": countFailures(fileErr, reseedErr, netDbErr),
		"recommendation": "check network connectivity and reseed server availability",
	}).Error("all bootstrap methods failed")

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
