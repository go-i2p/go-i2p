package config

import (
	"path/filepath"
	"time"

	"github.com/go-i2p/logger"
)

// ConfigDefaults contains all default configuration values for go-i2p.
// This centralizes default values to make them easy to discover, document, and modify.
//
// Design Principles:
// - All defaults should be sensible for typical use cases
// - Values should match I2P protocol standards where applicable
// - Performance defaults balance resource usage with responsiveness
// - Security defaults favor safety over convenience
type ConfigDefaults struct {
	// Router defaults
	Router RouterDefaults

	// Network Database defaults
	NetDB NetDBDefaults

	// Bootstrap defaults
	Bootstrap BootstrapDefaults

	// I2CP server defaults
	I2CP I2CPDefaults

	// Tunnel defaults
	Tunnel TunnelDefaults

	// Transport defaults
	Transport TransportDefaults

	// Performance tuning defaults
	Performance PerformanceDefaults
}

// RouterDefaults contains default values for router configuration
type RouterDefaults struct {
	// BaseDir is where per-system defaults are stored
	// Default: $HOME/.go-i2p/base
	BaseDir string

	// WorkingDir is where runtime files are modified
	// Default: $HOME/.go-i2p/config
	WorkingDir string

	// RouterInfoRefreshInterval is how often to update our RouterInfo
	// Default: 30 minutes
	RouterInfoRefreshInterval time.Duration

	// MessageExpirationTime is how long messages stay valid
	// Default: 60 seconds (I2P protocol standard)
	MessageExpirationTime time.Duration

	// MaxConcurrentSessions is maximum number of active transport sessions
	// Default: 200
	MaxConcurrentSessions int
}

// NetDBDefaults contains default values for network database configuration
type NetDBDefaults struct {
	// Path is the directory for storing network database files
	// Default: $HOME/.go-i2p/config/netDb
	Path string

	// MaxRouterInfos is maximum RouterInfos to store locally
	// Default: 5000
	MaxRouterInfos int

	// MaxLeaseSets is maximum LeaseSets to cache
	// Default: 1000
	MaxLeaseSets int

	// ExpirationCheckInterval is how often to check for expired entries
	// Default: 1 minute
	ExpirationCheckInterval time.Duration

	// LeaseSetRefreshThreshold is when to refresh before expiration
	// Default: 2 minutes before expiration
	LeaseSetRefreshThreshold time.Duration

	// ExplorationInterval is how often to explore the network
	// Default: 5 minutes
	ExplorationInterval time.Duration

	// FloodfillEnabled determines if this router acts as floodfill
	// Default: false (regular router mode)
	FloodfillEnabled bool
}

// BootstrapDefaults contains default values for network bootstrap
type BootstrapDefaults struct {
	// LowPeerThreshold triggers reseeding when peer count falls below this
	// Default: 10 peers
	LowPeerThreshold int

	// ReseedTimeout is maximum time to wait for reseed operations
	// Default: 60 seconds
	ReseedTimeout time.Duration

	// MinimumReseedPeers is minimum peers to get from reseed
	// Default: 50 peers
	MinimumReseedPeers int

	// ReseedRetryInterval is time between reseed attempts
	// Default: 5 minutes
	ReseedRetryInterval time.Duration

	// ReseedServers are the default reseed server configurations
	// Only reseed.i2pgit.org is included by default (maintained by go-i2p dev team)
	// Additional reseed servers should be configured via config file
	ReseedServers []*ReseedConfig
}

// I2CPDefaults contains default values for I2CP server
type I2CPDefaults struct {
	// Enabled determines if I2CP server starts automatically
	// Default: true
	Enabled bool

	// Address is the listen address for I2CP server
	// Default: "localhost:7654" (I2P protocol standard port)
	Address string

	// Network is the network type: "tcp" or "unix"
	// Default: "tcp"
	Network string

	// MaxSessions is maximum concurrent I2CP sessions
	// Default: 100 sessions
	MaxSessions int

	// MessageQueueSize is the buffer size for outbound messages per session
	// Default: 64 messages
	MessageQueueSize int

	// SessionTimeout is how long idle sessions stay alive
	// Default: 30 minutes
	SessionTimeout time.Duration

	// ReadTimeout is maximum time to wait for client reads
	// Default: 60 seconds
	ReadTimeout time.Duration

	// WriteTimeout is maximum time to wait for client writes
	// Default: 30 seconds
	WriteTimeout time.Duration
}

// TunnelDefaults contains default values for tunnel management
type TunnelDefaults struct {
	// MinPoolSize is minimum tunnels to maintain per pool
	// Default: 4 tunnels
	MinPoolSize int

	// MaxPoolSize is maximum tunnels to maintain per pool
	// Default: 6 tunnels
	MaxPoolSize int

	// TunnelLength is hops per tunnel
	// Default: 3 hops (I2P protocol standard)
	TunnelLength int

	// TunnelLifetime is how long tunnels stay active
	// Default: 10 minutes (I2P protocol standard)
	TunnelLifetime time.Duration

	// TunnelTestInterval is how often to test tunnel health
	// Default: 60 seconds
	TunnelTestInterval time.Duration

	// TunnelTestTimeout is maximum time to wait for test response
	// Default: 5 seconds
	TunnelTestTimeout time.Duration

	// BuildTimeout is maximum time to wait for tunnel build
	// Default: 90 seconds (I2P protocol standard)
	BuildTimeout time.Duration

	// BuildRetries is maximum attempts to build a tunnel
	// Default: 3 attempts
	BuildRetries int

	// ReplaceBeforeExpiration is when to build replacement tunnel
	// Default: 2 minutes before expiration
	ReplaceBeforeExpiration time.Duration

	// MaintenanceInterval is how often to run pool maintenance
	// Default: 30 seconds
	MaintenanceInterval time.Duration
}

// TransportDefaults contains default values for transport layer
type TransportDefaults struct {
	// NTCP2Enabled determines if NTCP2 transport is active
	// Default: true
	NTCP2Enabled bool

	// NTCP2Port is the listen port for NTCP2
	// Default: 0 (random port assigned by OS)
	NTCP2Port int

	// NTCP2MaxConnections is maximum concurrent NTCP2 sessions
	// Default: 200
	NTCP2MaxConnections int

	// SSU2Enabled determines if SSU2 transport is active
	// Default: false (not yet implemented)
	SSU2Enabled bool

	// SSU2Port is the listen port for SSU2
	// Default: 0 (random port assigned by OS)
	SSU2Port int

	// ConnectionTimeout is maximum time to establish connection
	// Default: 30 seconds
	ConnectionTimeout time.Duration

	// IdleTimeout is when to close idle connections
	// Default: 5 minutes
	IdleTimeout time.Duration

	// MaxMessageSize is maximum I2NP message size
	// Default: 32768 bytes (32 KiB)
	MaxMessageSize int
}

// PerformanceDefaults contains default values for performance tuning
type PerformanceDefaults struct {
	// MessageQueueSize is the buffer for router message processing
	// Default: 256 messages
	MessageQueueSize int

	// WorkerPoolSize is concurrent message processing workers
	// Default: 8 workers (or GOMAXPROCS)
	WorkerPoolSize int

	// GarlicEncryptionCacheSize is cache size for garlic sessions
	// Default: 1000 sessions
	GarlicEncryptionCacheSize int

	// FragmentCacheSize is cache size for message fragment reassembly
	// Default: 500 fragments
	FragmentCacheSize int

	// CleanupInterval is how often to run cleanup tasks
	// Default: 5 minutes
	CleanupInterval time.Duration
}

// Defaults returns a ConfigDefaults instance with all default values set.
// This is the single source of truth for all configuration defaults.
func Defaults() ConfigDefaults {
	baseDir := filepath.Join(BuildI2PDirPath(), "base")
	workingDir := filepath.Join(BuildI2PDirPath(), "config")

	return ConfigDefaults{
		Router:      buildRouterDefaults(baseDir, workingDir),
		NetDB:       buildNetDBDefaults(workingDir),
		Bootstrap:   buildBootstrapDefaults(),
		I2CP:        buildI2CPDefaults(),
		Tunnel:      buildTunnelDefaults(),
		Transport:   buildTransportDefaults(),
		Performance: buildPerformanceDefaults(),
	}
}

// buildRouterDefaults creates default router configuration values.
func buildRouterDefaults(baseDir, workingDir string) RouterDefaults {
	return RouterDefaults{
		BaseDir:                   baseDir,
		WorkingDir:                workingDir,
		RouterInfoRefreshInterval: 30 * time.Minute,
		MessageExpirationTime:     60 * time.Second,
		MaxConcurrentSessions:     200,
	}
}

// buildNetDBDefaults creates default network database configuration values.
func buildNetDBDefaults(workingDir string) NetDBDefaults {
	return NetDBDefaults{
		Path:                     filepath.Join(workingDir, "netDb"),
		MaxRouterInfos:           5000,
		MaxLeaseSets:             1000,
		ExpirationCheckInterval:  1 * time.Minute,
		LeaseSetRefreshThreshold: 2 * time.Minute,
		ExplorationInterval:      5 * time.Minute,
		FloodfillEnabled:         false,
	}
}

// buildBootstrapDefaults creates default bootstrap configuration values.
// Note: Only reseed.i2pgit.org is included by default as it is maintained by the go-i2p dev team.
// Additional reseed servers from the I2P network should be configured via config file.
func buildBootstrapDefaults() BootstrapDefaults {
	return BootstrapDefaults{
		LowPeerThreshold:    10,
		ReseedTimeout:       60 * time.Second,
		MinimumReseedPeers:  50,
		ReseedRetryInterval: 5 * time.Minute,
		ReseedServers: []*ReseedConfig{
			{
				Url:            "https://reseed.i2pgit.org/",
				SU3Fingerprint: "hankhill19580_at_gmail.com.crt",
			},
		},
	}
}

// buildI2CPDefaults creates default I2CP server configuration values.
func buildI2CPDefaults() I2CPDefaults {
	return I2CPDefaults{
		Enabled:          true,
		Address:          "localhost:7654",
		Network:          "tcp",
		MaxSessions:      100,
		MessageQueueSize: 64,
		SessionTimeout:   30 * time.Minute,
		ReadTimeout:      60 * time.Second,
		WriteTimeout:     30 * time.Second,
	}
}

// buildTunnelDefaults creates default tunnel configuration values.
func buildTunnelDefaults() TunnelDefaults {
	return TunnelDefaults{
		MinPoolSize:             4,
		MaxPoolSize:             6,
		TunnelLength:            3,
		TunnelLifetime:          10 * time.Minute,
		TunnelTestInterval:      60 * time.Second,
		TunnelTestTimeout:       5 * time.Second,
		BuildTimeout:            90 * time.Second,
		BuildRetries:            3,
		ReplaceBeforeExpiration: 2 * time.Minute,
		MaintenanceInterval:     30 * time.Second,
	}
}

// buildTransportDefaults creates default transport layer configuration values.
func buildTransportDefaults() TransportDefaults {
	return TransportDefaults{
		NTCP2Enabled:        true,
		NTCP2Port:           0, // Random port
		NTCP2MaxConnections: 200,
		SSU2Enabled:         false,
		SSU2Port:            0,
		ConnectionTimeout:   30 * time.Second,
		IdleTimeout:         5 * time.Minute,
		MaxMessageSize:      32768, // 32 KiB
	}
}

// buildPerformanceDefaults creates default performance tuning configuration values.
func buildPerformanceDefaults() PerformanceDefaults {
	return PerformanceDefaults{
		MessageQueueSize:          256,
		WorkerPoolSize:            8,
		GarlicEncryptionCacheSize: 1000,
		FragmentCacheSize:         500,
		CleanupInterval:           5 * time.Minute,
	}
}

// Validate checks if the provided configuration values are reasonable.
// Returns an error describing the first invalid value found.
func Validate(cfg ConfigDefaults) error {
	log.Debug("Validating configuration defaults")
	return runConfigValidators(cfg)
}

// runConfigValidators executes all configuration validators in sequence.
// Returns the first error encountered or nil if all validations pass.
func runConfigValidators(cfg ConfigDefaults) error {
	log.Debug("Running all configuration validators")
	validators := []func() error{
		func() error { return validateRouter(cfg.Router) },
		func() error { return validateNetDB(cfg.NetDB) },
		func() error { return validateBootstrap(cfg.Bootstrap) },
		func() error { return validateI2CP(cfg.I2CP) },
		func() error { return validateTunnel(cfg.Tunnel) },
		func() error { return validateTransport(cfg.Transport) },
		func() error { return validatePerformance(cfg.Performance) },
	}

	for _, validator := range validators {
		if err := validator(); err != nil {
			log.WithError(err).Error("Configuration validation failed")
			return err
		}
	}
	log.Info("All configuration validations passed successfully")
	return nil
}

// validateRouter validates router configuration settings.
func validateRouter(router RouterDefaults) error {
	log.Debug("Validating router configuration")
	if router.MaxConcurrentSessions < 1 {
		log.WithField("max_concurrent_sessions", router.MaxConcurrentSessions).Error("Invalid router configuration")
		return newValidationError("Router.MaxConcurrentSessions must be at least 1")
	}
	if router.MessageExpirationTime < 1*time.Second {
		log.WithField("message_expiration_time", router.MessageExpirationTime).Error("Invalid router configuration")
		return newValidationError("Router.MessageExpirationTime must be at least 1 second")
	}
	log.Debug("Router configuration validated successfully")
	return nil
}

// validateNetDB validates network database configuration settings.
func validateNetDB(netdb NetDBDefaults) error {
	log.Debug("Validating NetDB configuration")
	if netdb.MaxRouterInfos < 10 {
		log.WithField("max_router_infos", netdb.MaxRouterInfos).Error("Invalid NetDB configuration")
		return newValidationError("NetDB.MaxRouterInfos must be at least 10")
	}
	if netdb.MaxLeaseSets < 1 {
		log.WithField("max_lease_sets", netdb.MaxLeaseSets).Error("Invalid NetDB configuration")
		return newValidationError("NetDB.MaxLeaseSets must be at least 1")
	}
	log.Debug("NetDB configuration validated successfully")
	return nil
}

// validateBootstrap validates bootstrap configuration settings.
func validateBootstrap(bootstrap BootstrapDefaults) error {
	log.Debug("Validating bootstrap configuration")
	if bootstrap.LowPeerThreshold < 1 {
		log.WithField("low_peer_threshold", bootstrap.LowPeerThreshold).Error("Invalid bootstrap configuration")
		return newValidationError("Bootstrap.LowPeerThreshold must be at least 1")
	}
	if bootstrap.MinimumReseedPeers < 1 {
		log.WithField("minimum_reseed_peers", bootstrap.MinimumReseedPeers).Error("Invalid bootstrap configuration")
		return newValidationError("Bootstrap.MinimumReseedPeers must be at least 1")
	}
	log.Debug("Bootstrap configuration validated successfully")
	return nil
}

// validateI2CP validates I2CP server configuration settings.
func validateI2CP(i2cp I2CPDefaults) error {
	log.Debug("Validating I2CP configuration")
	if i2cp.MaxSessions < 1 {
		log.WithField("max_sessions", i2cp.MaxSessions).Error("Invalid I2CP configuration")
		return newValidationError("I2CP.MaxSessions must be at least 1")
	}
	if i2cp.MessageQueueSize < 1 {
		log.WithField("message_queue_size", i2cp.MessageQueueSize).Error("Invalid I2CP configuration")
		return newValidationError("I2CP.MessageQueueSize must be at least 1")
	}
	log.Debug("I2CP configuration validated successfully")
	return nil
}

// validateTunnel validates tunnel configuration settings.
func validateTunnel(tunnel TunnelDefaults) error {
	log.Debug("Validating tunnel configuration")
	if tunnel.MinPoolSize < 1 {
		log.WithField("min_pool_size", tunnel.MinPoolSize).Error("Invalid tunnel configuration")
		return newValidationError("Tunnel.MinPoolSize must be at least 1")
	}
	if tunnel.MaxPoolSize < tunnel.MinPoolSize {
		log.WithFields(logger.Fields{"max_pool_size": tunnel.MaxPoolSize, "min_pool_size": tunnel.MinPoolSize}).Error("Invalid tunnel configuration")
		return newValidationError("Tunnel.MaxPoolSize must be >= MinPoolSize")
	}
	if tunnel.TunnelLength < 1 || tunnel.TunnelLength > 8 {
		log.WithField("tunnel_length", tunnel.TunnelLength).Error("Invalid tunnel configuration")
		return newValidationError("Tunnel.TunnelLength must be between 1 and 8")
	}
	if tunnel.BuildRetries < 1 {
		log.WithField("build_retries", tunnel.BuildRetries).Error("Invalid tunnel configuration")
		return newValidationError("Tunnel.BuildRetries must be at least 1")
	}
	log.Debug("Tunnel configuration validated successfully")
	return nil
}

// validateTransport validates transport layer configuration settings.
func validateTransport(transport TransportDefaults) error {
	log.Debug("Validating transport configuration")
	if transport.MaxMessageSize < 1024 {
		log.WithField("max_message_size", transport.MaxMessageSize).Error("Invalid transport configuration")
		return newValidationError("Transport.MaxMessageSize must be at least 1024 bytes")
	}
	if transport.NTCP2MaxConnections < 1 {
		log.WithField("ntcp2_max_connections", transport.NTCP2MaxConnections).Error("Invalid transport configuration")
		return newValidationError("Transport.NTCP2MaxConnections must be at least 1")
	}
	log.Debug("Transport configuration validated successfully")
	return nil
}

// validatePerformance validates performance tuning configuration settings.
func validatePerformance(performance PerformanceDefaults) error {
	log.Debug("Validating performance configuration")
	if performance.WorkerPoolSize < 1 {
		log.WithField("worker_pool_size", performance.WorkerPoolSize).Error("Invalid performance configuration")
		return newValidationError("Performance.WorkerPoolSize must be at least 1")
	}
	if performance.MessageQueueSize < 1 {
		log.WithField("message_queue_size", performance.MessageQueueSize).Error("Invalid performance configuration")
		return newValidationError("Performance.MessageQueueSize must be at least 1")
	}
	log.Debug("Performance configuration validated successfully")
	return nil
}

// validationError is returned when configuration validation fails
type validationError struct {
	message string
}

func newValidationError(message string) error {
	return &validationError{message: message}
}

func (e *validationError) Error() string {
	return "configuration validation failed: " + e.message
}
