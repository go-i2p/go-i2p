package router

import (
	"context"

	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

// logSubsystemStop logs a subsystem shutdown event with standard fields.
// This reduces duplication across the various stopXxx methods.

// Start starts router mainloop and returns an error if startup-critical
// subsystems (NetDB, I2CP, I2PControl) fail to initialize.
// The router must be created via CreateRouter (not bare FromConfig) so that
// the keystore and transport are properly initialized before Start is called.
// Start initializes all subsystems and starts the router's main loop.
// It acquires runMux for the duration of pre-launch setup, then releases it
// before blocking on the mainloop's startup-error channel.
func (r *Router) Start() error {
	r.runMux.Lock()

	if err := r.validateSubsystems(); err != nil {
		r.runMux.Unlock()
		return err
	}

	if r.running {
		r.runMux.Unlock()
		log.WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "startup",
			"reason": "router is already running",
			"state":  "running",
		}).Warn("attempted to start already running router")
		return nil
	}

	r.markRunning()
	log.WithField("at", "Start").Debug("step 2/6: initializing lifecycle context")
	r.initializeLifecycleContext()
	log.WithField("at", "Start").Debug("step 3/6: initializing bandwidth tracker")
	r.initializeBandwidthTracker()
	log.WithField("at", "Start").Debug("step 4/6: initializing congestion monitoring")
	r.initializeCongestionMonitoring()
	log.WithField("at", "Start").Debug("step 5/6: initializing router info provider")
	r.initializeRouterInfoProvider()
	log.WithField("at", "Start").Debug("step 6/6: launching mainloop")
	r.launchMainloop()

	// Release runMux BEFORE blocking on startupErr to prevent deadlocking
	// Stop() which also needs runMux. The running flag is already set, so
	// Stop() can proceed if called while we wait.
	r.runMux.Unlock()

	return r.awaitStartupResult()
}

// validateSubsystems checks that CreateRouter has fully initialized the router.
// Must be called while runMux is held.
func (r *Router) validateSubsystems() error {
	if r.RouterInfoKeystore == nil {
		return oops.Errorf("router not fully initialized: keystore is nil (use CreateRouter, not FromConfig directly)")
	}
	if r.TransportMuxer == nil {
		return oops.Errorf("router not fully initialized: transport muxer is nil (use CreateRouter, not FromConfig directly)")
	}
	return nil
}

// markRunning sets the running flag and logs the startup initiation.
// Must be called while runMux is held.
func (r *Router) markRunning() {
	log.WithFields(logger.Fields{
		"at":           "(Router) Start",
		"phase":        "startup",
		"step":         1,
		"reason":       "initiating router startup sequence",
		"i2cp_enabled": r.cfg.I2CP != nil && r.cfg.I2CP.Enabled,
	}).Info("starting router")
	r.running = true
}

// initializeLifecycleContext creates the router-level context for coordinated shutdown.
func (r *Router) initializeLifecycleContext() {
	r.ctx, r.cancel = context.WithCancel(context.Background())
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   2,
		"reason": "lifecycle context initialized",
	}).Debug("router context initialized")
}

// initializeBandwidthTracker creates and starts the bandwidth sampling tracker.
func (r *Router) initializeBandwidthTracker() {
	r.bandwidthTracker = NewBandwidthTracker()
	r.bandwidthTracker.Start(r.getTotalBandwidth)
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   3,
		"reason": "bandwidth tracker initialized",
	}).Debug("bandwidth tracker started")
}

// initializeCongestionMonitoring starts congestion monitoring per PROP_162.
func (r *Router) initializeCongestionMonitoring() {
	r.startCongestionMonitor()
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   4,
		"reason": "congestion monitor initialized",
	}).Debug("congestion monitor started")
}

// initializeRouterInfoProvider wires the routerInfoProvider so the NetDB publisher
// can access the local RouterInfo, optionally attaching the congestion monitor.
func (r *Router) initializeRouterInfoProvider() {
	r.routerInfoProv = newRouterInfoProvider(r)
	if r.congestionMonitor != nil {
		r.routerInfoProv.SetCongestionMonitor(r.congestionMonitor)
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "startup",
		"step":   5,
		"reason": "routerInfoProvider wired",
	}).Debug("router info provider initialized")
}

// launchMainloop starts the main event loop in a tracked goroutine.
func (r *Router) launchMainloop() {
	r.startupErr = make(chan error, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.mainloop()
	}()
}

// awaitStartupResult blocks until the mainloop reports startup success or failure.
func (r *Router) awaitStartupResult() error {
	if err := <-r.startupErr; err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "startup",
			"reason": "startup-critical subsystem failed",
		}).Error("router startup failed")
		return err
	}
	log.WithFields(logger.Fields{
		"at":     "(Router) Start",
		"phase":  "running",
		"reason": "all startup-critical subsystems initialized",
	}).Info("router started successfully")
	if r.cfg != nil && r.cfg.Hidden {
		log.WithFields(logger.Fields{
			"at":     "(Router) Start",
			"phase":  "running",
			"reason": "hidden mode active",
			"caps":   "NUH (no transit, no inbound from network)",
		}).Info("router is in hidden mode: refusing transit, publishing no transport addresses")
	}
	return nil
}
