package router

import (
	"context"
	"strconv"
	"time"

	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

const (
	inNetworkPeerTarget  = 500
	emergencyReseedFloor = 40
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).
func (r *Router) ensureNetDBReady() error {
	if r.netdb == nil {
		return oops.Errorf("StdNetDB is nil (router may be shutting down)")
	}
	if err := r.netdb.Ensure(); err != nil {
		log.WithError(err).Error("Failed to ensure NetDB")
		return err
	}

	if sz := r.netdb.Size(); sz >= 0 {
		log.WithField("size", sz).Debug("NetDB Size: " + strconv.Itoa(sz))
	} else {
		log.WithFields(logger.Fields{"at": "ensureNetDBReady"}).Warn("Unable to determine NetDB size")
	}

	if r.netdb.Size() < r.emergencyReseedThreshold() {
		return r.performReseed()
	}
	return nil
}

// performReseed executes network database reseeding process.
// It selects the appropriate bootstrapper based on configuration and executes the reseed operation.
func (r *Router) performReseed() error {
	return r.performReseedWithContext(context.Background())
}

// performReseedWithContext executes network database reseeding process.
// It selects the appropriate bootstrapper based on configuration and executes
// the reseed operation with cancellation support.
func (r *Router) performReseedWithContext(ctx context.Context) error {
	r.markReseedAttempt()
	r.setReseedingFlag(true)
	defer r.setReseedingFlag(false)

	r.logReseedStart()

	bootstrapper, err := r.createBootstrapper()
	if err != nil {
		return err
	}

	return r.executeReseedWithContext(ctx, bootstrapper)
}

func (r *Router) markReseedAttempt() {
	r.reseedMutex.Lock()
	r.lastReseedAttempt = time.Now()
	r.reseedMutex.Unlock()
}

func (r *Router) reseedCooldownInterval() time.Duration {
	if r.cfg != nil && r.cfg.Bootstrap.ReseedRetryInterval > 0 {
		return r.cfg.Bootstrap.ReseedRetryInterval
	}
	return 5 * time.Minute
}

func (r *Router) canAttemptReseedNow() bool {
	r.reseedMutex.RLock()
	defer r.reseedMutex.RUnlock()

	if r.isReseeding {
		return false
	}
	if r.lastReseedAttempt.IsZero() {
		return true
	}
	return time.Since(r.lastReseedAttempt) >= r.reseedCooldownInterval()
}

func (r *Router) emergencyReseedThreshold() int {
	threshold := emergencyReseedFloor
	if r.cfg != nil && r.cfg.Bootstrap.LowPeerThreshold > threshold {
		threshold = r.cfg.Bootstrap.LowPeerThreshold
	}
	return threshold
}

// maintainNetDBPeerFloor prefers in-network recovery for low peer counts and
// uses reseed only as an emergency fallback when peer counts are critically low.
func (r *Router) maintainNetDBPeerFloor() {
	if r.netdb == nil {
		return
	}

	current := r.netdb.Size()
	reseedThreshold := r.emergencyReseedThreshold()

	// Stay in-network for peer recovery under normal low-count conditions.
	if current >= reseedThreshold {
		if current < inNetworkPeerTarget {
			log.WithFields(logger.Fields{
				"at":      "maintainNetDBPeerFloor",
				"current": current,
				"target":  inNetworkPeerTarget,
				"mode":    "in-network-exploration",
			}).Info("NetDB below integration target; continuing in-network discovery")
		}
		return
	}

	if !r.canAttemptReseedNow() {
		return
	}

	log.WithFields(logger.Fields{
		"at":               "maintainNetDBPeerFloor",
		"current":          current,
		"reseed_threshold": reseedThreshold,
		"target":           inNetworkPeerTarget,
		"mode":             "emergency-reseed",
	}).Warn("NetDB critically low, triggering emergency reseed")

	ctx := context.Background()
	if r.cfg != nil && r.cfg.Bootstrap.ReseedTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.cfg.Bootstrap.ReseedTimeout)
		defer cancel()
	}

	if err := r.performReseedWithContext(ctx); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":               "maintainNetDBPeerFloor",
			"current":          current,
			"reseed_threshold": reseedThreshold,
			"mode":             "emergency-reseed",
		}).Warn("Emergency reseed attempt failed")
	}
}

// setReseedingFlag safely sets the isReseeding flag with proper mutex protection.
func (r *Router) setReseedingFlag(value bool) {
	r.reseedMutex.Lock()
	r.isReseeding = value
	r.reseedMutex.Unlock()
}

// logReseedStart logs the beginning of the reseed operation with relevant metrics.
func (r *Router) logReseedStart() {
	reseedThreshold := r.emergencyReseedThreshold()
	log.WithFields(logger.Fields{
		"at":             "(Router) performReseed",
		"phase":          "bootstrap",
		"reason":         "netdb critically low, initiating emergency bootstrap",
		"current_size":   r.netdb.Size(),
		"threshold":      reseedThreshold,
		"shortfall":      reseedThreshold - r.netdb.Size(),
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
	}).Warn("netDb critically low, initiating emergency bootstrap")
}

// createBootstrapper creates the appropriate bootstrapper based on user configuration.
// Returns the bootstrapper instance and any configuration error encountered.
func (r *Router) createBootstrapper() (bootstrap.Bootstrap, error) {
	switch r.cfg.Bootstrap.BootstrapType {
	case "file":
		return r.createFileBootstrapper()
	case "reseed":
		return r.createReseedBootstrapper(), nil
	case "local":
		return r.createLocalBootstrapper(), nil
	case "auto", "":
		return r.createCompositeBootstrapper(), nil
	default:
		return r.createFallbackBootstrapper(), nil
	}
}

// createFileBootstrapper creates a file-based bootstrapper from a local reseed file.
// Returns an error if the reseed file path is not configured.
func (r *Router) createFileBootstrapper() (bootstrap.Bootstrap, error) {
	if r.cfg.Bootstrap.ReseedFilePath == "" {
		log.WithFields(logger.Fields{
			"at":             "(Router) createFileBootstrapper",
			"phase":          "bootstrap",
			"reason":         "bootstrap_type is file but path not configured",
			"bootstrap_type": "file",
		}).Error("bootstrap configuration error")
		return nil, oops.Errorf("bootstrap_type is 'file' but no reseed_file_path is configured")
	}
	log.WithFields(logger.Fields{
		"at":        "(Router) createFileBootstrapper",
		"phase":     "bootstrap",
		"reason":    "using file bootstrap as configured",
		"file_path": r.cfg.Bootstrap.ReseedFilePath,
		"strategy":  "file_only",
	}).Info("using file bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewFileBootstrap(r.cfg.Bootstrap.ReseedFilePath), nil
}

// createReseedBootstrapper creates a bootstrapper that fetches peers from reseed servers.
func (r *Router) createReseedBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{"at": "createReseedBootstrapper"}).Info("Using reseed bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewReseedBootstrap(r.cfg.Bootstrap)
}

// createLocalBootstrapper creates a bootstrapper that reads from local netDb directories.
func (r *Router) createLocalBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{"at": "createLocalBootstrapper"}).Info("Using local netDb bootstrap only (as specified by bootstrap_type)")
	return bootstrap.NewLocalNetDBBootstrap(r.cfg.Bootstrap)
}

// createCompositeBootstrapper creates a bootstrapper that tries all methods sequentially.
func (r *Router) createCompositeBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{
		"at":             "(Router) createCompositeBootstrapper",
		"phase":          "bootstrap",
		"reason":         "using composite bootstrap strategy",
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
		"strategy":       "file -> reseed -> local_netdb",
		"reseed_servers": len(r.cfg.Bootstrap.ReseedServers),
	}).Info("using composite bootstrap (tries all methods)")
	return bootstrap.NewCompositeBootstrap(r.cfg.Bootstrap)
}

// createFallbackBootstrapper creates a composite bootstrapper as fallback for unknown types.
func (r *Router) createFallbackBootstrapper() bootstrap.Bootstrap {
	log.WithFields(logger.Fields{
		"at":             "(Router) createFallbackBootstrapper",
		"phase":          "bootstrap",
		"reason":         "unknown bootstrap_type, using fallback",
		"bootstrap_type": r.cfg.Bootstrap.BootstrapType,
		"fallback":       "composite",
		"valid_types":    "file, reseed, local, auto",
	}).Warn("unknown bootstrap_type, falling back to composite bootstrap")
	return bootstrap.NewCompositeBootstrap(r.cfg.Bootstrap)
}

// executeReseed performs the actual reseed operation using the provided bootstrapper.
// It logs success or failure and returns any error encountered.
func (r *Router) executeReseed(bootstrapper bootstrap.Bootstrap) error {
	return r.executeReseedWithContext(context.Background(), bootstrapper)
}

// executeReseedWithContext performs the actual reseed operation using the provided bootstrapper.
// It logs success or failure and returns any error encountered.
func (r *Router) executeReseedWithContext(ctx context.Context, bootstrapper bootstrap.Bootstrap) error {
	targetFloor := r.emergencyReseedThreshold()
	if err := r.netdb.ReseedWithContext(ctx, bootstrapper, targetFloor); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":           "(Router) executeReseed",
			"phase":        "bootstrap",
			"reason":       "bootstrap failed but continuing",
			"current_size": r.netdb.Size(),
			"target":       targetFloor,
			"impact":       "router will operate with limited peer connectivity",
		}).Warn("bootstrap failed, continuing with limited NetDB")
		return err
	}
	log.WithFields(logger.Fields{
		"at":           "(Router) executeReseed",
		"phase":        "bootstrap",
		"reason":       "bootstrap completed successfully",
		"netdb_size":   r.netdb.Size(),
		"threshold":    targetFloor,
		"peers_gained": r.netdb.Size() - (targetFloor - 1),
	}).Info("bootstrap completed successfully")
	return nil
}
