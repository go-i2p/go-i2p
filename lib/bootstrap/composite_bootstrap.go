package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// CompositeBootstrap implements the Bootstrap interface by trying multiple
// bootstrap methods in sequence:
// 1. Peer cache (if enabled) - fastest, no network, repeat-startup speedup
// 2. Local reseed file (if specified) - high priority
// 3. Remote reseed servers
// 4. Local netDb directories - fallback
type CompositeBootstrap struct {
	fileBootstrap       *FileBootstrap
	reseedBootstrap     *ReseedBootstrap
	localNetDBBootstrap *LocalNetDBBootstrap
	peerCache           *PeerCache
	config              *config.BootstrapConfig
}

// NewCompositeBootstrap creates a new composite bootstrap with peer cache,
// file, reseed, and local netDb fallback.
func NewCompositeBootstrap(cfg *config.BootstrapConfig) *CompositeBootstrap {
	cb := &CompositeBootstrap{
		reseedBootstrap:     NewReseedBootstrap(cfg),
		localNetDBBootstrap: NewLocalNetDBBootstrap(cfg),
		config:              cfg,
	}

	// Only create file bootstrap if a file path is specified
	if cfg.ReseedFilePath != "" {
		cb.fileBootstrap = NewFileBootstrap(cfg.ReseedFilePath)
	}

	// Create and load the peer cache if enabled and a path is configured.
	// Loading failures are non-fatal: the cache simply stays empty and the
	// composite falls back to the other sources.
	if cfg.PeerCacheEnabled && cfg.PeerCachePath != "" {
		cache := NewPeerCache(cfg.PeerCachePath, cfg.PeerCacheMaxSize)
		if err := cache.Load(context.Background()); err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"at":     "(CompositeBootstrap) NewCompositeBootstrap",
				"phase":  "bootstrap",
				"reason": "peer_cache_load_failed",
				"file":   cfg.PeerCachePath,
			}).Warn("failed to load peer cache, continuing without it")
		} else {
			cb.peerCache = cache
		}
	}

	return cb
}

// GetPeers implements the Bootstrap interface. When BootstrapType is "auto"
// (default), it tries all methods in sequence: file → reseed → local netDb.
// When set to a specific type ("file", "reseed", "local"), only that method
// is used. This allows users in air-gapped environments to prevent remote
// reseed connections, or to force a specific bootstrap strategy.
func (cb *CompositeBootstrap) GetPeers(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	bootstrapType := "auto"
	if cb.config != nil && cb.config.BootstrapType != "" {
		bootstrapType = cb.config.BootstrapType
	}

	// Process bootstrap strategy selection

	switch bootstrapType {
	case "file":
		return cb.getPeersFileOnly(ctx, n)
	case "reseed":
		return cb.getPeersReseedOnly(ctx, n)
	case "local":
		return cb.getPeersLocalOnly(ctx, n)
	default:
		// "auto" or unrecognized: try all methods in sequence
		return cb.getPeersAutoFallback(ctx, n)
	}
}

// getPeersFileOnly uses only the file bootstrap method.
func (cb *CompositeBootstrap) getPeersFileOnly(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	if cb.fileBootstrap == nil {
		return nil, oops.Errorf("bootstrap type is 'file' but no reseed file path is configured")
	}
	return tryFileBootstrap(cb.fileBootstrap, ctx, n)
}

// getPeersReseedOnly uses only the remote reseed bootstrap method.
func (cb *CompositeBootstrap) getPeersReseedOnly(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	return tryReseedBootstrap(cb.reseedBootstrap, ctx, n)
}

// getPeersLocalOnly uses only the local netDb bootstrap method.
func (cb *CompositeBootstrap) getPeersLocalOnly(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	return tryLocalNetDBBootstrap(cb.localNetDBBootstrap, ctx, n)
}

// getPeersAutoFallback tries all methods in sequence: peer cache → file →
// reseed → local netDb. The peer cache is tried first because it is the
// fastest source (no network, no reseed-server round trip); when it yields
// enough fresh peers, repeat startups skip the network entirely. Any peers
// obtained from a successful source are recorded back into the cache.
func (cb *CompositeBootstrap) getPeersAutoFallback(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	// Collect errors from all methods for better debugging
	var cacheErr, fileErr, reseedErr, netDBErr error

	// Try the peer cache first — fastest source for repeat startups.
	if cb.peerCache != nil {
		peers, err := cb.tryPeerCache(ctx, n)
		if err == nil {
			return peers, nil
		}
		cacheErr = err
	}

	// Try file bootstrap if configured
	if cb.fileBootstrap != nil {
		peers, err := tryFileBootstrap(cb.fileBootstrap, ctx, n)
		if err == nil {
			cb.recordPeers(peers)
			return peers, nil
		}
		fileErr = err
	}

	// Try reseed bootstrap
	peers, err := tryReseedBootstrap(cb.reseedBootstrap, ctx, n)
	if err == nil {
		cb.recordPeers(peers)
		return peers, nil
	}
	reseedErr = err

	// Fall back to local netDb
	localCtx, cancel := localFallbackContext(ctx)
	defer cancel()
	peers, err = tryLocalNetDBBootstrap(cb.localNetDBBootstrap, localCtx, n)
	if err == nil {
		cb.recordPeers(peers)
		return peers, nil
	}
	netDBErr = err

	// All methods failed - return aggregated error for debugging
	return nil, buildAggregatedError(cacheErr, fileErr, reseedErr, netDBErr)
}

// tryPeerCache attempts to obtain peers from the on-disk peer cache.
func (cb *CompositeBootstrap) tryPeerCache(ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	peers, err := cb.peerCache.GetPeers(ctx, n)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":    "(CompositeBootstrap) tryPeerCache",
			"phase": "bootstrap",
			"reason": "cache_empty_or_unavailable",
		}).Debug("peer cache has no usable peers, falling back to other sources")
		return nil, err
	}
	return peers, nil
}

// recordPeers persists the given peers into the peer cache for future
// startups. Failures are logged but never propagated — caching is best-effort.
func (cb *CompositeBootstrap) recordPeers(peers []router_info.RouterInfo) {
	if cb.peerCache == nil || len(peers) == 0 {
		return
	}
	if err := cb.peerCache.Record(peers); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":    "(CompositeBootstrap) recordPeers",
			"phase": "bootstrap",
			"reason": "peer_cache_record_failed",
		}).Warn("failed to record peers to cache")
	}
}

// localFallbackContext ensures the local netDb fallback is not skipped just
// because a previous remote bootstrap phase exhausted the caller's deadline.
// Local filesystem bootstrap is fast and independent of network timing, so when
// the parent context's deadline was exceeded we give the local fallback a short
// fresh budget to evaluate available RouterInfo files.
//
// An explicit cancellation (context.Canceled) is different: the caller has asked
// us to abort, so we honor it and propagate the cancelled context rather than
// starting a fresh budget.
func localFallbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), 5*time.Second)
	}

	if ctx.Err() == nil {
		return ctx, func() {}
	}

	// Caller explicitly cancelled — do not resurrect a fresh budget; abort.
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx, func() {}
	}

	// Parent deadline exceeded: give local filesystem bootstrap a fresh budget.
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// tryFileBootstrap attempts to obtain peers from the local reseed file.
func tryFileBootstrap(fb *FileBootstrap, ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	peers, err := tryBootstrapSource(fb, ctx, n, "file")

	if err == nil {
		return peers, nil
	}

	logFileBootstrapFailure(err)
	// Preserve actual error details for debugging
	return nil, err
}

// tryReseedBootstrap attempts to obtain peers from remote reseed servers.
func tryReseedBootstrap(rb *ReseedBootstrap, ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	peers, err := tryBootstrapSource(rb, ctx, n, "reseed")

	if err == nil {
		return peers, nil
	}

	logReseedFailure(err)
	// Preserve actual error details for debugging
	return nil, err
}

// tryLocalNetDBBootstrap attempts to obtain peers from local netDb directories.
func tryLocalNetDBBootstrap(lb *LocalNetDBBootstrap, ctx context.Context, n int) ([]router_info.RouterInfo, error) {
	peers, err := tryBootstrapSource(lb, ctx, n, "local netDb")
	if err != nil {
		return nil, err
	}
	return peers, nil
}

// logFileBootstrapFailure logs appropriate warnings for file bootstrap failures.
func logFileBootstrapFailure(err error) {
	if err != nil {
		log.WithError(err).Warn("file bootstrap failed")
	}
}

// logReseedFailure logs appropriate warnings for reseed bootstrap failures.
func logReseedFailure(err error) {
	if err != nil {
		log.WithError(err).Warn("reseed bootstrap failed")
	}
}

// buildAggregatedError creates a detailed error message including all bootstrap method failures.
func buildAggregatedError(cacheErr, fileErr, reseedErr, netDBErr error) error {
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
		"cache_attempted": cacheErr != nil,
		"file_attempted": fileErr != nil,
		"reseed_failed":  reseedErr != nil,
		"netdb_failed":   netDBErr != nil,
		"methods_tried":  4,
		"methods_failed": countFailures(cacheErr, fileErr, reseedErr, netDBErr),
		"recommendation": "check network connectivity and reseed server availability",
	}).Error("all bootstrap methods failed")

	// Build error message with all available error details
	errMsg := "all bootstrap methods failed:"

	if cacheErr != nil {
		errMsg += fmt.Sprintf(" cache=%v;", cacheErr)
	} else {
		errMsg += " cache=not attempted;"
	}

	if fileErr != nil {
		errMsg += fmt.Sprintf(" file=%v;", fileErr)
	} else {
		errMsg += " file=not attempted;"
	}

	if reseedErr != nil {
		errMsg += fmt.Sprintf(" reseed=%v;", reseedErr)
	}

	if netDBErr != nil {
		errMsg += fmt.Sprintf(" netDb=%v", netDBErr)
	}

	return oops.Errorf("%s", errMsg)
}
