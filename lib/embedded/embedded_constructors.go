package embedded

import (
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

func NewStandardEmbeddedRouter(cfg *config.RouterConfig) (*StandardEmbeddedRouter, error) {
	if cfg == nil {
		return nil, oops.Errorf("configuration cannot be nil")
	}

	log.WithFields(logger.Fields{
		"at":     "NewStandardEmbeddedRouter",
		"phase":  "initialization",
		"reason": "creating embedded router instance",
	}).Debug("creating new standard embedded router")

	e := &StandardEmbeddedRouter{
		cfg:        cfg,
		configured: false,
		running:    false,
	}

	// Auto-configure the router so callers don't need a separate Configure() call.
	// Configure() creates the underlying router instance using the provided config.
	if err := e.Configure(cfg); err != nil {
		return nil, oops.Wrapf(err, "auto-configure failed")
	}

	return e, nil
}

// NewStandardEmbeddedRouterWith creates a new embedded router instance with
// an injected router.Lifecycle implementation. This constructor is primarily
// useful for testing, where a stub or mock router can be provided instead of
// the production router.Router.
//
// The provided router must be already started or will be started by the caller.
// This constructor skips the auto-configuration step that NewStandardEmbeddedRouter
// performs, allowing full control over router setup.
//
// Returns error if the router parameter is nil.
func NewStandardEmbeddedRouterWith(r router.Lifecycle, cfg *config.RouterConfig) (*StandardEmbeddedRouter, error) {
	if r == nil {
		return nil, oops.Errorf("router.Lifecycle cannot be nil")
	}

	if cfg == nil {
		return nil, oops.Errorf("configuration cannot be nil")
	}

	log.WithFields(logger.Fields{
		"at":     "NewStandardEmbeddedRouterWith",
		"phase":  "initialization",
		"reason": "creating embedded router instance with injected lifecycle",
	}).Debug("creating standard embedded router with injected router")

	return &StandardEmbeddedRouter{
		router:     r,
		cfg:        cfg,
		configured: true, // Assume injected router is already configured
		running:    false,
	}, nil
}

// Configure initializes the router with the provided configuration.
// This method creates the underlying router instance but does not start it.
//
// Note: NewStandardEmbeddedRouter already calls Configure() internally.
// Callers using the constructor do NOT need to call Configure() again.
// Calling Configure() on an already-configured router returns nil (no-op)
// to prevent errors from the documented constructor + Configure pattern.
