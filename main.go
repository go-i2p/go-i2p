package main

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/embedded"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	tuipkg "github.com/go-i2p/go-i2p/lib/tui"
	"github.com/go-i2p/go-i2p/lib/util"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	"github.com/go-i2p/i2ptui"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	embeddedRouter   *embedded.StandardEmbeddedRouter
	embeddedRouterMu sync.Mutex
	log              = logger.GetGoI2PLogger()
)

// RootCmd is the top-level cobra command for the go-i2p router, handling CLI argument parsing and router startup.
var RootCmd = &cobra.Command{
	Use:   "go-i2p",
	Short: "I2P Router implementation in Go",
	Run: func(cmd *cobra.Command, args []string) {
		runRouter()
	},
}

func init() {
	// Register the certificate provider with the reseed package to break the import cycle.
	// This allows reseed to access embedded certificates without importing embedded directly.
	reseed.SetCertificateProvider(func() (fs.FS, error) {
		return embedded.GetReseedCertificates()
	})
	reseed.SetSSLCertificateProvider(func() (fs.FS, error) {
		return embedded.GetSSLCertificates()
	})

	cobra.OnInitialize(config.InitConfigOrExit)
	registerGlobalFlags()
	registerRouterFlags()
	registerNetDbFlags()
	registerBootstrapFlags()
	registerI2CPFlags()
	registerI2PControlFlags()
	registerTransportFlags()
	registerTunnelFlags()
	registerPerformanceFlags()
	registerCongestionFlags()
	bindFlagsToViper()
}

// registerGlobalFlags registers global command-line flags for the application.
func registerGlobalFlags() {
	RootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "", "config file (default is $HOME/.go-i2p/config.yaml)")
}

// registerRouterFlags registers router-specific configuration flags.
func registerRouterFlags() {
	routerCfg := config.DefaultRouterConfig()
	defaults := config.Defaults()
	RootCmd.PersistentFlags().String("base-dir", routerCfg.BaseDir, "Base directory for I2P router")
	RootCmd.PersistentFlags().String("working-dir", routerCfg.WorkingDir, "Working directory for I2P router")
	RootCmd.PersistentFlags().Uint64("router.max-bandwidth", routerCfg.MaxBandwidth,
		"Maximum bandwidth in bytes/sec (0 = unlimited)")
	RootCmd.PersistentFlags().Int("router.max-connections", routerCfg.MaxConnections,
		"Maximum concurrent transport connections")
	RootCmd.PersistentFlags().Bool("router.accept-tunnels", routerCfg.AcceptTunnels,
		"Participate in transit tunnels for the network")
	RootCmd.PersistentFlags().Duration("router.info-refresh-interval", defaults.Router.RouterInfoRefreshInterval,
		"How often to refresh our RouterInfo")
	RootCmd.PersistentFlags().Duration("router.message-expiration-time", defaults.Router.MessageExpirationTime,
		"How long messages stay valid")
	RootCmd.PersistentFlags().Int("router.max-concurrent-sessions", defaults.Router.MaxConcurrentSessions,
		"Maximum active transport sessions")
}

// registerNetDbFlags registers NetDB configuration flags.
func registerNetDbFlags() {
	defaults := config.Defaults()
	RootCmd.PersistentFlags().String("netdb.path", config.DefaultNetDBConfig.Path, "Path to the netDb")
	RootCmd.PersistentFlags().Int("netdb.max-router-infos", defaults.NetDB.MaxRouterInfos,
		"Maximum RouterInfos to store locally")
	RootCmd.PersistentFlags().Int("netdb.max-lease-sets", defaults.NetDB.MaxLeaseSets,
		"Maximum LeaseSets to cache")
	RootCmd.PersistentFlags().Duration("netdb.expiration-check-interval", defaults.NetDB.ExpirationCheckInterval,
		"How often to check for expired entries")
	RootCmd.PersistentFlags().Duration("netdb.lease-set-refresh-threshold", defaults.NetDB.LeaseSetRefreshThreshold,
		"How far before expiration to refresh a LeaseSet")
	RootCmd.PersistentFlags().Duration("netdb.exploration-interval", defaults.NetDB.ExplorationInterval,
		"How often to explore the network for new peers")
	RootCmd.PersistentFlags().Bool("netdb.floodfill-enabled", defaults.NetDB.FloodfillEnabled,
		"Operate as a floodfill router")
}

// registerBootstrapFlags registers bootstrap configuration flags.
func registerBootstrapFlags() {
	defaults := config.Defaults()
	RootCmd.PersistentFlags().Int("bootstrap.low-peer-threshold", config.DefaultBootstrapConfig.LowPeerThreshold,
		"Minimum number of peers before reseeding")
	RootCmd.PersistentFlags().String("bootstrap.type", config.DefaultBootstrapConfig.BootstrapType,
		"Bootstrap type: auto (tries all methods), file (local file only), reseed (remote only), local (netDb only)")
	RootCmd.PersistentFlags().String("bootstrap.reseed-file", "",
		"Path to local reseed file (zip or su3) - takes priority over remote reseed servers")
	RootCmd.PersistentFlags().Duration("bootstrap.reseed-timeout", defaults.Bootstrap.ReseedTimeout,
		"Maximum time to wait for reseed operations")
	RootCmd.PersistentFlags().Int("bootstrap.minimum-reseed-peers", defaults.Bootstrap.MinimumReseedPeers,
		"Minimum peers to obtain from reseed")
	RootCmd.PersistentFlags().Duration("bootstrap.reseed-retry-interval", defaults.Bootstrap.ReseedRetryInterval,
		"Time between reseed attempts")
	RootCmd.PersistentFlags().Int("bootstrap.min-reseed-servers", config.DefaultBootstrapConfig.MinReseedServers,
		"Minimum successful reseed servers required")
	RootCmd.PersistentFlags().String("bootstrap.reseed-strategy", config.DefaultBootstrapConfig.ReseedStrategy,
		"How to combine RouterInfos from multiple servers: union, intersection, or random")
}

// registerI2CPFlags registers I2CP server configuration flags.
func registerI2CPFlags() {
	RootCmd.PersistentFlags().Bool("i2cp.enabled", config.DefaultI2CPConfig.Enabled,
		"Enable I2CP server for client applications")
	RootCmd.PersistentFlags().String("i2cp.address", config.DefaultI2CPConfig.Address,
		"I2CP server listen address")
	RootCmd.PersistentFlags().String("i2cp.network", config.DefaultI2CPConfig.Network,
		"I2CP network type (tcp or unix)")
	RootCmd.PersistentFlags().Int("i2cp.max-sessions", config.DefaultI2CPConfig.MaxSessions,
		"Maximum number of concurrent I2CP sessions (range: 1-320)")
	RootCmd.PersistentFlags().String("i2cp.username", "",
		"I2CP authentication username (empty = no auth)")
	RootCmd.PersistentFlags().String("i2cp.password", "",
		"I2CP authentication password (empty = no auth)")
	RootCmd.PersistentFlags().Int("i2cp.message-queue-size", config.DefaultI2CPConfig.MessageQueueSize,
		"Buffer size for outbound messages per session")
	RootCmd.PersistentFlags().Duration("i2cp.session-timeout", config.DefaultI2CPConfig.SessionTimeout,
		"Idle session timeout (0 = no timeout)")
	RootCmd.PersistentFlags().Duration("i2cp.read-timeout", config.DefaultI2CPConfig.ReadTimeout,
		"Maximum time to wait for client reads")
	RootCmd.PersistentFlags().Duration("i2cp.write-timeout", config.DefaultI2CPConfig.WriteTimeout,
		"Maximum time to wait for client writes")
}

// registerI2PControlFlags registers I2PControl RPC server configuration flags.
func registerI2PControlFlags() {
	defaultCfg := config.DefaultI2PControlConfig()
	RootCmd.PersistentFlags().Bool("i2pcontrol.enabled", defaultCfg.Enabled,
		"Enable I2PControl JSON-RPC server")
	RootCmd.PersistentFlags().String("i2pcontrol.address", defaultCfg.Address,
		"I2PControl server listen address (host:port)")
	RootCmd.PersistentFlags().String("i2pcontrol.password", "",
		"I2PControl API password (default: random from config file, or 'itoopie' if no config)")
	RootCmd.PersistentFlags().Bool("i2pcontrol.use-https", defaultCfg.UseHTTPS,
		"Enable TLS/HTTPS for I2PControl server")
	RootCmd.PersistentFlags().String("i2pcontrol.cert-file", defaultCfg.CertFile,
		"Path to TLS certificate file (PEM format, required when HTTPS enabled)")
	RootCmd.PersistentFlags().String("i2pcontrol.key-file", defaultCfg.KeyFile,
		"Path to TLS private key file (PEM format, required when HTTPS enabled)")
	RootCmd.PersistentFlags().Duration("i2pcontrol.token-expiration", defaultCfg.TokenExpiration,
		"How long authentication tokens remain valid")
}

// registerTransportFlags registers transport layer configuration flags.
func registerTransportFlags() {
	RootCmd.PersistentFlags().Bool("transport.ntcp2-enabled", config.DefaultTransportConfig.NTCP2Enabled,
		"Enable NTCP2 transport (TCP-based)")
	RootCmd.PersistentFlags().Int("transport.ntcp2-port", config.DefaultTransportConfig.NTCP2Port,
		"NTCP2 listen port (0 = random port assigned by OS)")
	RootCmd.PersistentFlags().Int("transport.ntcp2-max-connections", config.DefaultTransportConfig.NTCP2MaxConnections,
		"Maximum concurrent NTCP2 sessions")
	RootCmd.PersistentFlags().Bool("transport.ssu2-enabled", config.DefaultTransportConfig.SSU2Enabled,
		"Enable SSU2 transport (UDP-based, currently experimental)")
	RootCmd.PersistentFlags().Int("transport.ssu2-port", config.DefaultTransportConfig.SSU2Port,
		"SSU2 listen port (0 = random port assigned by OS)")
	RootCmd.PersistentFlags().Duration("transport.connection-timeout", config.DefaultTransportConfig.ConnectionTimeout,
		"Maximum time to establish a connection")
	RootCmd.PersistentFlags().Duration("transport.idle-timeout", config.DefaultTransportConfig.IdleTimeout,
		"When to close idle connections")
	RootCmd.PersistentFlags().Int("transport.max-message-size", config.DefaultTransportConfig.MaxMessageSize,
		"Maximum I2NP message size in bytes")
}

// registerTunnelFlags registers tunnel pool management configuration flags.
func registerTunnelFlags() {
	defaults := config.Defaults()
	RootCmd.PersistentFlags().Int("tunnel.min-pool-size", defaults.Tunnel.MinPoolSize,
		"Minimum tunnels to maintain per pool")
	RootCmd.PersistentFlags().Int("tunnel.max-pool-size", defaults.Tunnel.MaxPoolSize,
		"Maximum tunnels to maintain per pool")
	RootCmd.PersistentFlags().Int("tunnel.length", defaults.Tunnel.TunnelLength,
		"Hops per tunnel (I2P protocol standard: 3)")
	RootCmd.PersistentFlags().Duration("tunnel.lifetime", defaults.Tunnel.TunnelLifetime,
		"How long tunnels stay active")
	RootCmd.PersistentFlags().Duration("tunnel.test-interval", defaults.Tunnel.TunnelTestInterval,
		"How often to test tunnel health")
	RootCmd.PersistentFlags().Duration("tunnel.test-timeout", defaults.Tunnel.TunnelTestTimeout,
		"Maximum time to wait for tunnel test response")
	RootCmd.PersistentFlags().Duration("tunnel.build-timeout", defaults.Tunnel.BuildTimeout,
		"Maximum time to wait for tunnel build")
	RootCmd.PersistentFlags().Int("tunnel.build-retries", defaults.Tunnel.BuildRetries,
		"Maximum attempts to build a tunnel")
	RootCmd.PersistentFlags().Duration("tunnel.replace-before-expiration", defaults.Tunnel.ReplaceBeforeExpiration,
		"When to build replacement tunnel before expiration")
	RootCmd.PersistentFlags().Duration("tunnel.maintenance-interval", defaults.Tunnel.MaintenanceInterval,
		"How often to run pool maintenance")
	RootCmd.PersistentFlags().Int("tunnel.max-participating-tunnels", defaults.Tunnel.MaxParticipatingTunnels,
		"Hard limit on tunnels where we act as intermediate hop")
	RootCmd.PersistentFlags().Bool("tunnel.participating-limits-enabled", defaults.Tunnel.ParticipatingLimitsEnabled,
		"Enable global participating tunnel limits")
	RootCmd.PersistentFlags().Bool("tunnel.per-source-rate-limit-enabled", defaults.Tunnel.PerSourceRateLimitEnabled,
		"Enable per-source tunnel build request rate limiting")
	RootCmd.PersistentFlags().Int("tunnel.max-build-requests-per-minute", defaults.Tunnel.MaxBuildRequestsPerMinute,
		"Maximum tunnel build requests per source per minute")
	RootCmd.PersistentFlags().Int("tunnel.build-request-burst-size", defaults.Tunnel.BuildRequestBurstSize,
		"Burst allowance for tunnel build requests")
	RootCmd.PersistentFlags().Duration("tunnel.source-ban-duration", defaults.Tunnel.SourceBanDuration,
		"How long to ban sources that exceed rate limits")
}

// registerPerformanceFlags registers performance tuning configuration flags.
func registerPerformanceFlags() {
	defaults := config.Defaults()
	RootCmd.PersistentFlags().Int("performance.message-queue-size", defaults.Performance.MessageQueueSize,
		"Buffer size for router message processing")
	RootCmd.PersistentFlags().Int("performance.worker-pool-size", defaults.Performance.WorkerPoolSize,
		"Concurrent message processing workers")
	RootCmd.PersistentFlags().Int("performance.garlic-encryption-cache-size", defaults.Performance.GarlicEncryptionCacheSize,
		"Cache size for garlic encryption sessions")
	RootCmd.PersistentFlags().Int("performance.fragment-cache-size", defaults.Performance.FragmentCacheSize,
		"Cache size for message fragment reassembly")
	RootCmd.PersistentFlags().Duration("performance.cleanup-interval", defaults.Performance.CleanupInterval,
		"How often to run cleanup tasks")
}

// registerCongestionFlags registers congestion advertisement configuration flags (Proposal 162).
func registerCongestionFlags() {
	defaults := config.Defaults()
	RootCmd.PersistentFlags().Float64("congestion.d-flag-threshold", defaults.Congestion.DFlagThreshold,
		"Participating tunnel ratio to advertise D (medium congestion) flag")
	RootCmd.PersistentFlags().Float64("congestion.e-flag-threshold", defaults.Congestion.EFlagThreshold,
		"Participating tunnel ratio to advertise E (high congestion) flag")
	RootCmd.PersistentFlags().Float64("congestion.g-flag-threshold", defaults.Congestion.GFlagThreshold,
		"Participating tunnel ratio to advertise G (critical congestion) flag")
	RootCmd.PersistentFlags().Float64("congestion.clear-d-flag-threshold", defaults.Congestion.ClearDFlagThreshold,
		"Ratio to clear D flag and return to normal")
	RootCmd.PersistentFlags().Float64("congestion.clear-e-flag-threshold", defaults.Congestion.ClearEFlagThreshold,
		"Ratio to clear E flag (downgrade to D or clear)")
	RootCmd.PersistentFlags().Float64("congestion.clear-g-flag-threshold", defaults.Congestion.ClearGFlagThreshold,
		"Ratio to clear G flag (downgrade to E)")
	RootCmd.PersistentFlags().Duration("congestion.averaging-window", defaults.Congestion.AveragingWindow,
		"Duration to average congestion metrics over")
	RootCmd.PersistentFlags().Duration("congestion.e-flag-age-threshold", defaults.Congestion.EFlagAgeThreshold,
		"When E flag on stale RouterInfo is treated as D flag")
	RootCmd.PersistentFlags().Float64("congestion.d-flag-capacity-multiplier", defaults.Congestion.DFlagCapacityMultiplier,
		"Capacity multiplier for D-flagged peers in tunnel building")
	RootCmd.PersistentFlags().Float64("congestion.e-flag-capacity-multiplier", defaults.Congestion.EFlagCapacityMultiplier,
		"Capacity multiplier for E-flagged peers in tunnel building")
	RootCmd.PersistentFlags().Float64("congestion.stale-e-flag-capacity-multiplier", defaults.Congestion.StaleEFlagCapacityMultiplier,
		"Capacity multiplier for E-flagged peers with stale RouterInfo")
}

// mustBindPFlag binds a persistent flag to a viper configuration key, terminating on error.
func mustBindPFlag(viperKey, flagName string) {
	if err := viper.BindPFlag(viperKey, RootCmd.PersistentFlags().Lookup(flagName)); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "mustBindPFlag",
			"phase":  "startup",
			"reason": fmt.Sprintf("failed to bind %s configuration flag", viperKey),
			"flag":   flagName,
		}).Fatalf("failed to bind %s flag", viperKey)
	}
}

// bindFlagsToViper binds all command-line flags to viper configuration keys.
func bindFlagsToViper() {
	bindRouterFlagsToViper()
	bindNetDbFlagsToViper()
	bindBootstrapFlagsToViper()
	bindI2CPFlagsToViper()
	bindI2PControlFlagsToViper()
	bindTransportFlagsToViper()
	bindTunnelFlagsToViper()
	bindPerformanceFlagsToViper()
	bindCongestionFlagsToViper()
}

// bindRouterFlagsToViper binds router flags to viper configuration.
func bindRouterFlagsToViper() {
	if err := viper.BindPFlag("base_dir", RootCmd.PersistentFlags().Lookup("base-dir")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindRouterFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind base_dir configuration flag",
			"flag":   "base-dir",
		}).Fatal("failed to bind base_dir flag")
	}
	if err := viper.BindPFlag("working_dir", RootCmd.PersistentFlags().Lookup("working-dir")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindRouterFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind working_dir configuration flag",
			"flag":   "working-dir",
		}).Fatal("failed to bind working_dir flag")
	}
	mustBindPFlag("router.max_bandwidth", "router.max-bandwidth")
	mustBindPFlag("router.max_connections", "router.max-connections")
	mustBindPFlag("router.accept_tunnels", "router.accept-tunnels")
	mustBindPFlag("router.info_refresh_interval", "router.info-refresh-interval")
	mustBindPFlag("router.message_expiration_time", "router.message-expiration-time")
	mustBindPFlag("router.max_concurrent_sessions", "router.max-concurrent-sessions")
}

// bindNetDbFlagsToViper binds NetDB flags to viper configuration.
func bindNetDbFlagsToViper() {
	if err := viper.BindPFlag("netdb.path", RootCmd.PersistentFlags().Lookup("netdb.path")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindNetDbFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind netdb.path configuration flag",
			"flag":   "netdb.path",
		}).Fatal("failed to bind netdb.path flag")
	}
	mustBindPFlag("netdb.max_router_infos", "netdb.max-router-infos")
	mustBindPFlag("netdb.max_lease_sets", "netdb.max-lease-sets")
	mustBindPFlag("netdb.expiration_check_interval", "netdb.expiration-check-interval")
	mustBindPFlag("netdb.lease_set_refresh_threshold", "netdb.lease-set-refresh-threshold")
	mustBindPFlag("netdb.exploration_interval", "netdb.exploration-interval")
	mustBindPFlag("netdb.floodfill_enabled", "netdb.floodfill-enabled")
}

// bindBootstrapFlagsToViper binds bootstrap flags to viper configuration.
func bindBootstrapFlagsToViper() {
	if err := viper.BindPFlag("bootstrap.low_peer_threshold", RootCmd.PersistentFlags().Lookup("bootstrap.low-peer-threshold")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindBootstrapFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind bootstrap threshold flag",
			"flag":   "bootstrap.low-peer-threshold",
		}).Fatal("failed to bind bootstrap.low_peer_threshold flag")
	}
	if err := viper.BindPFlag("bootstrap.bootstrap_type", RootCmd.PersistentFlags().Lookup("bootstrap.type")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindBootstrapFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind bootstrap type flag",
			"flag":   "bootstrap.type",
		}).Fatal("failed to bind bootstrap.bootstrap_type flag")
	}
	if err := viper.BindPFlag("bootstrap.reseed_file_path", RootCmd.PersistentFlags().Lookup("bootstrap.reseed-file")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindBootstrapFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind reseed file path flag",
			"flag":   "bootstrap.reseed-file",
		}).Fatal("failed to bind bootstrap.reseed_file_path flag")
	}
	mustBindPFlag("bootstrap.reseed_timeout", "bootstrap.reseed-timeout")
	mustBindPFlag("bootstrap.minimum_reseed_peers", "bootstrap.minimum-reseed-peers")
	mustBindPFlag("bootstrap.reseed_retry_interval", "bootstrap.reseed-retry-interval")
	mustBindPFlag("bootstrap.min_reseed_servers", "bootstrap.min-reseed-servers")
	mustBindPFlag("bootstrap.reseed_strategy", "bootstrap.reseed-strategy")
}

// bindI2CPFlagsToViper binds I2CP flags to viper configuration.
func bindI2CPFlagsToViper() {
	if err := viper.BindPFlag("i2cp.enabled", RootCmd.PersistentFlags().Lookup("i2cp.enabled")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2CPFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2cp.enabled flag",
			"flag":   "i2cp.enabled",
		}).Fatal("failed to bind i2cp.enabled flag")
	}
	if err := viper.BindPFlag("i2cp.address", RootCmd.PersistentFlags().Lookup("i2cp.address")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2CPFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2cp.address flag",
			"flag":   "i2cp.address",
		}).Fatal("failed to bind i2cp.address flag")
	}
	if err := viper.BindPFlag("i2cp.network", RootCmd.PersistentFlags().Lookup("i2cp.network")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2CPFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2cp.network flag",
			"flag":   "i2cp.network",
		}).Fatal("failed to bind i2cp.network flag")
	}
	if err := viper.BindPFlag("i2cp.max_sessions", RootCmd.PersistentFlags().Lookup("i2cp.max-sessions")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2CPFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2cp.max_sessions flag",
			"flag":   "i2cp.max-sessions",
		}).Fatal("failed to bind i2cp.max_sessions flag")
	}
	mustBindPFlag("i2cp.username", "i2cp.username")
	mustBindPFlag("i2cp.password", "i2cp.password")
	mustBindPFlag("i2cp.message_queue_size", "i2cp.message-queue-size")
	mustBindPFlag("i2cp.session_timeout", "i2cp.session-timeout")
	mustBindPFlag("i2cp.read_timeout", "i2cp.read-timeout")
	mustBindPFlag("i2cp.write_timeout", "i2cp.write-timeout")
}

// bindI2PControlFlagsToViper binds I2PControl flags to viper configuration.
func bindI2PControlFlagsToViper() {
	if err := viper.BindPFlag("i2pcontrol.enabled", RootCmd.PersistentFlags().Lookup("i2pcontrol.enabled")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2PControlFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2pcontrol.enabled flag",
			"flag":   "i2pcontrol.enabled",
		}).Fatal("failed to bind i2pcontrol.enabled flag")
	}
	if err := viper.BindPFlag("i2pcontrol.address", RootCmd.PersistentFlags().Lookup("i2pcontrol.address")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2PControlFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2pcontrol.address flag",
			"flag":   "i2pcontrol.address",
		}).Fatal("failed to bind i2pcontrol.address flag")
	}
	if err := viper.BindPFlag("i2pcontrol.password", RootCmd.PersistentFlags().Lookup("i2pcontrol.password")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindI2PControlFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind i2pcontrol.password flag",
			"flag":   "i2pcontrol.password",
		}).Fatal("failed to bind i2pcontrol.password flag")
	}
	mustBindPFlag("i2pcontrol.use_https", "i2pcontrol.use-https")
	mustBindPFlag("i2pcontrol.cert_file", "i2pcontrol.cert-file")
	mustBindPFlag("i2pcontrol.key_file", "i2pcontrol.key-file")
	mustBindPFlag("i2pcontrol.token_expiration", "i2pcontrol.token-expiration")
}

// bindTransportFlagsToViper binds transport flags to viper configuration.
func bindTransportFlagsToViper() {
	mustBindPFlag("transport.ntcp2_enabled", "transport.ntcp2-enabled")
	mustBindPFlag("transport.ntcp2_port", "transport.ntcp2-port")
	mustBindPFlag("transport.ntcp2_max_connections", "transport.ntcp2-max-connections")
	if err := viper.BindPFlag("transport.ssu2_enabled", RootCmd.PersistentFlags().Lookup("transport.ssu2-enabled")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindTransportFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind transport.ssu2_enabled flag",
			"flag":   "transport.ssu2-enabled",
		}).Fatal("failed to bind transport.ssu2_enabled flag")
	}
	if err := viper.BindPFlag("transport.ssu2_port", RootCmd.PersistentFlags().Lookup("transport.ssu2-port")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindTransportFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind transport.ssu2_port flag",
			"flag":   "transport.ssu2-port",
		}).Fatal("failed to bind transport.ssu2_port flag")
	}
	mustBindPFlag("transport.connection_timeout", "transport.connection-timeout")
	mustBindPFlag("transport.idle_timeout", "transport.idle-timeout")
	mustBindPFlag("transport.max_message_size", "transport.max-message-size")
}

// bindTunnelFlagsToViper binds tunnel flags to viper configuration.
func bindTunnelFlagsToViper() {
	mustBindPFlag("tunnel.min_pool_size", "tunnel.min-pool-size")
	mustBindPFlag("tunnel.max_pool_size", "tunnel.max-pool-size")
	mustBindPFlag("tunnel.length", "tunnel.length")
	mustBindPFlag("tunnel.lifetime", "tunnel.lifetime")
	mustBindPFlag("tunnel.test_interval", "tunnel.test-interval")
	mustBindPFlag("tunnel.test_timeout", "tunnel.test-timeout")
	mustBindPFlag("tunnel.build_timeout", "tunnel.build-timeout")
	mustBindPFlag("tunnel.build_retries", "tunnel.build-retries")
	mustBindPFlag("tunnel.replace_before_expiration", "tunnel.replace-before-expiration")
	mustBindPFlag("tunnel.maintenance_interval", "tunnel.maintenance-interval")
	mustBindPFlag("tunnel.max_participating_tunnels", "tunnel.max-participating-tunnels")
	mustBindPFlag("tunnel.participating_limits_enabled", "tunnel.participating-limits-enabled")
	mustBindPFlag("tunnel.per_source_rate_limit_enabled", "tunnel.per-source-rate-limit-enabled")
	mustBindPFlag("tunnel.max_build_requests_per_minute", "tunnel.max-build-requests-per-minute")
	mustBindPFlag("tunnel.build_request_burst_size", "tunnel.build-request-burst-size")
	mustBindPFlag("tunnel.source_ban_duration", "tunnel.source-ban-duration")
}

// bindPerformanceFlagsToViper binds performance flags to viper configuration.
func bindPerformanceFlagsToViper() {
	mustBindPFlag("performance.message_queue_size", "performance.message-queue-size")
	mustBindPFlag("performance.worker_pool_size", "performance.worker-pool-size")
	mustBindPFlag("performance.garlic_encryption_cache_size", "performance.garlic-encryption-cache-size")
	mustBindPFlag("performance.fragment_cache_size", "performance.fragment-cache-size")
	mustBindPFlag("performance.cleanup_interval", "performance.cleanup-interval")
}

// bindCongestionFlagsToViper binds congestion flags to viper configuration.
func bindCongestionFlagsToViper() {
	mustBindPFlag("router.congestion.d_flag_threshold", "congestion.d-flag-threshold")
	mustBindPFlag("router.congestion.e_flag_threshold", "congestion.e-flag-threshold")
	mustBindPFlag("router.congestion.g_flag_threshold", "congestion.g-flag-threshold")
	mustBindPFlag("router.congestion.clear_d_flag_threshold", "congestion.clear-d-flag-threshold")
	mustBindPFlag("router.congestion.clear_e_flag_threshold", "congestion.clear-e-flag-threshold")
	mustBindPFlag("router.congestion.clear_g_flag_threshold", "congestion.clear-g-flag-threshold")
	mustBindPFlag("router.congestion.averaging_window", "congestion.averaging-window")
	mustBindPFlag("router.congestion.e_flag_age_threshold", "congestion.e-flag-age-threshold")
	mustBindPFlag("router.congestion.d_flag_capacity_multiplier", "congestion.d-flag-capacity-multiplier")
	mustBindPFlag("router.congestion.e_flag_capacity_multiplier", "congestion.e-flag-capacity-multiplier")
	mustBindPFlag("router.congestion.stale_e_flag_capacity_multiplier", "congestion.stale-e-flag-capacity-multiplier")
}

// tuiCmd launches the embedded bubbletea TUI for I2P router management
// via the I2PControl JSON-RPC interface.
var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the I2P router TUI (terminal user interface)",
	Long: `Launch an interactive terminal UI for monitoring and managing the I2P router.
The TUI communicates via the I2PControl JSON-RPC interface. By default, all
connection parameters are derived from the config file.`,
	Run: func(cmd *cobra.Command, args []string) {
		address := viper.GetString("i2pcontrol.address")
		password := viper.GetString("i2pcontrol.password")

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			log.WithError(err).WithFields(logger.Fields{
				"at":      "tuiCmd",
				"address": address,
			}).Fatal("invalid i2pcontrol address format, expected host:port")
		}

		log.WithFields(logger.Fields{
			"at":       "tuiCmd",
			"host":     host,
			"port":     port,
			"password": password != "itoopie",
		}).Info("launching TUI")

		opts := []i2ptui.Option{
			i2ptui.WithHost(host),
			i2ptui.WithPort(port),
			i2ptui.WithPassword(password),
			i2ptui.WithPath("jsonrpc"),
		}

		m := tuipkg.New(password, address, opts...)
		p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
		if _, err := p.Run(); err != nil {
			log.WithError(err).Fatal("TUI exited with error")
		}
	},
}

// configCmd shows current configuration
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.GetRouterConfig()

		log.WithFields(logger.Fields{
			"at":          "configCmd",
			"phase":       "startup",
			"reason":      "displaying configuration",
			"config_file": viper.ConfigFileUsed(),
		}).Info("configuration file")

		log.WithFields(logger.Fields{
			"at":          "configCmd",
			"phase":       "startup",
			"reason":      "router configuration loaded",
			"base_dir":    cfg.BaseDir,
			"working_dir": cfg.WorkingDir,
		}).Info("router configuration")

		log.WithFields(logger.Fields{
			"at":         "configCmd",
			"phase":      "startup",
			"reason":     "netdb configuration loaded",
			"netdb_path": cfg.NetDB.Path,
		}).Info("netDb configuration")

		log.WithFields(logger.Fields{
			"at":                 "configCmd",
			"phase":              "startup",
			"reason":             "bootstrap configuration loaded",
			"low_peer_threshold": cfg.Bootstrap.LowPeerThreshold,
			"bootstrap_type":     cfg.Bootstrap.BootstrapType,
		}).Info("bootstrap configuration")

		log.WithFields(logger.Fields{
			"at":     "configCmd",
			"phase":  "startup",
			"reason": "displaying reseed servers",
			"count":  len(cfg.Bootstrap.ReseedServers),
		}).Info("reseed servers:")
		for i, server := range cfg.Bootstrap.ReseedServers {
			log.WithFields(logger.Fields{
				"at":              "configCmd",
				"phase":           "startup",
				"reason":          "reseed server configured",
				"index":           i,
				"url":             server.URL,
				"su3_fingerprint": server.SU3Fingerprint,
			}).Info("  reseed server")
		}
	},
}

func debugPrintConfig() {
	cfg := config.GetRouterConfig()
	currentConfig := struct {
		BaseDir    string                  `yaml:"base_dir"`
		WorkingDir string                  `yaml:"working_dir"`
		NetDB      *config.NetDBConfig     `yaml:"netdb,omitempty"`
		Bootstrap  *config.BootstrapConfig `yaml:"bootstrap,omitempty"`
	}{
		BaseDir:    cfg.BaseDir,
		WorkingDir: cfg.WorkingDir,
		NetDB:      cfg.NetDB,
		Bootstrap:  cfg.Bootstrap,
	}

	yamlData, err := yaml.Marshal(currentConfig)
	if err != nil {
		log.Errorf("Error marshaling config for debug: %s", err)
		return
	}

	log.Debugf("Current configuration:\\n%s", string(yamlData))
}

// testNetworkConnectivity performs basic network connectivity checks at startup
// PRIORITY 3: Validate that the router has external network access
func testNetworkConnectivity() error {
	log.WithFields(logger.Fields{
		"at":     "testNetworkConnectivity",
		"phase":  "startup",
		"reason": "validating external network access",
	}).Info("running network connectivity pre-check")

	if err := testDNSResolution(); err != nil {
		return err
	}

	if err := testTCPConnectivity(); err != nil {
		return err
	}

	log.WithFields(logger.Fields{
		"at":     "testNetworkConnectivity",
		"phase":  "startup",
		"result": "success",
	}).Info("Network connectivity pre-check passed - external access confirmed")

	return nil
}

// testDNSResolution verifies DNS resolution works for reseed hosts.
func testDNSResolution() error {
	log.Debug("Testing DNS resolution...")
	testHosts := []string{
		"reseed.i2pgit.org",
	}

	for _, host := range testHosts {
		addrs, err := net.LookupHost(host)
		if err != nil {
			log.WithFields(logger.Fields{
				"host":  host,
				"error": err.Error(),
			}).Warn("DNS lookup failed for reseed host")
			continue
		}
		log.WithFields(logger.Fields{
			"host":       host,
			"resolved":   len(addrs),
			"first_addr": addrs[0],
		}).Debug("DNS resolution successful")
		log.Infof("DNS resolution successful: %s -> %s", host, addrs[0])
		return nil
	}

	return fmt.Errorf("DNS resolution failed for all test hosts - check network/DNS configuration")
}

// testTCPConnectivity verifies TCP connectivity to reseed servers.
func testTCPConnectivity() error {
	log.Debug("Testing TCP connectivity to reseed server...")
	tcpTestHosts := []string{
		"reseed.i2pgit.org:443",
	}

	for _, hostPort := range tcpTestHosts {
		log.Infof("Testing TCP connection to %s...", hostPort)
		conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
		if err != nil {
			log.WithFields(logger.Fields{
				"target": hostPort,
				"error":  err.Error(),
			}).Warn("TCP connectivity test failed")
			log.Warnf("TCP connectivity test failed to %s: %v", hostPort, err)
			continue
		}
		conn.Close()
		log.WithFields(logger.Fields{
			"target": hostPort,
		}).Debug("TCP connectivity test successful")
		log.Infof("TCP connectivity test successful to %s", hostPort)
		return nil
	}

	return fmt.Errorf("TCP connectivity failed to all test hosts - check firewall/network configuration")
}

// logConfigurationSource logs whether configuration was loaded from file or using defaults.
func logConfigurationSource() {
	if viper.ConfigFileUsed() == "" {
		log.WithFields(logger.Fields{
			"at":       "runRouter",
			"phase":    "startup",
			"step":     1,
			"reason":   "no config file found, using defaults",
			"strategy": "defaults_and_flags",
		}).Warn("no configuration file loaded, using default values and command-line flags")
	} else {
		log.WithFields(logger.Fields{
			"at":          "runRouter",
			"phase":       "startup",
			"step":        1,
			"reason":      "configuration file loaded",
			"config_file": viper.ConfigFileUsed(),
		}).Info("loaded configuration from file")
	}
}

// manageRouterLifecycle handles the full router lifecycle: creation, startup, execution, and shutdown.
// manageRouterLifecycle handles the complete router lifecycle from creation to shutdown.
func manageRouterLifecycle() error {
	if err := createAndConfigureRouter(); err != nil {
		return err
	}

	registerSignalHandlers()

	if err := startAndRunRouter(); err != nil {
		return err
	}

	return closeRouter()
}

// createAndConfigureRouter creates and configures the embedded router instance.
func createAndConfigureRouter() error {
	embeddedRouterMu.Lock()
	defer embeddedRouterMu.Unlock()

	routerCfg := config.GetRouterConfig()

	log.WithField("at", "createAndConfigureRouter").Debug("calling NewStandardEmbeddedRouter")
	var err error
	embeddedRouter, err = embedded.NewStandardEmbeddedRouter(routerCfg)
	if err != nil {
		return fmt.Errorf("failed to create embedded router: %w", err)
	}
	log.WithField("at", "createAndConfigureRouter").Debug("NewStandardEmbeddedRouter returned")

	// Note: NewStandardEmbeddedRouter already calls Configure() internally.
	// The second Configure() call below is a documented no-op for the
	// constructor + Configure pattern.
	log.WithField("at", "createAndConfigureRouter").Debug("calling Configure (expected no-op)")
	if err := embeddedRouter.Configure(routerCfg); err != nil {
		return fmt.Errorf("failed to configure router: %w", err)
	}
	log.WithField("at", "createAndConfigureRouter").Debug("router creation and configuration complete")
	return nil
}

// registerSignalHandlers sets up reload and interrupt handlers for the router.
func registerSignalHandlers() {
	signals.RegisterReloadHandler(func() {
		if err := viper.ReadInConfig(); err != nil {
			log.Errorf("failed to reload config: %s", err)
			return
		}
		config.SetRouterConfig(config.NewRouterConfigFromViper())
	})

	signals.RegisterInterruptHandler(func() {
		embeddedRouterMu.Lock()
		defer embeddedRouterMu.Unlock()
		if embeddedRouter != nil && embeddedRouter.IsRunning() {
			log.WithFields(logger.Fields{
				"at":     "runRouter",
				"phase":  "shutdown",
				"reason": "interrupt signal received",
			}).Info("stopping embedded router")
			if err := embeddedRouter.Stop(); err != nil {
				log.WithError(err).Error("error during graceful stop, forcing hard stop")
				embeddedRouter.HardStop()
			}
		}
	})
}

// startAndRunRouter starts the router and waits for it to complete.
func startAndRunRouter() error {
	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "startup",
		"step":   5,
		"reason": "starting router subsystems",
	}).Info("starting embedded router")

	embeddedRouterMu.Lock()
	r := embeddedRouter
	embeddedRouterMu.Unlock()

	if r == nil {
		return fmt.Errorf("router not initialized")
	}

	if err := r.Start(); err != nil {
		return fmt.Errorf("failed to start router: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "running",
		"reason": "router running, waiting for shutdown",
	}).Info("embedded router started, entering main loop")

	r.Wait()
	return nil
}

// closeRouter performs final cleanup and closes the embedded router.
func closeRouter() error {
	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "shutdown",
		"reason": "router shutdown complete, cleaning up",
	}).Info("closing embedded router")

	embeddedRouterMu.Lock()
	r := embeddedRouter
	embeddedRouterMu.Unlock()

	if r == nil {
		return nil
	}

	// Always close all registered resources, even if r.Close() fails
	defer util.CloseAll()

	if err := r.Close(); err != nil {
		return fmt.Errorf("failed to close router: %w", err)
	}

	return nil
}

func runRouter() {
	go signals.Handle()

	logStartupConfiguration()
	logConfigurationSource()
	logNetDbPath()
	runNetworkPreChecks()
	launchRouterLifecycle()
}

// logStartupConfiguration logs that the router configuration is being parsed.
func logStartupConfiguration() {
	log.WithFields(logger.Fields{
		"at":          "runRouter",
		"phase":       "startup",
		"step":        1,
		"reason":      "parsing router configuration",
		"config_file": viper.ConfigFileUsed(),
		"config_used": viper.ConfigFileUsed() != "",
	}).Info("parsing i2p router configuration")
}

// logNetDbPath logs the configured NetDB path.
func logNetDbPath() {
	routerCfg := config.GetRouterConfig()
	log.WithFields(logger.Fields{
		"at":         "runRouter",
		"phase":      "startup",
		"step":       2,
		"reason":     "netdb path configured",
		"netdb_path": routerCfg.NetDB.Path,
		"source":     "configuration",
	}).Info("using netDb path: " + routerCfg.NetDB.Path)
}

// runNetworkPreChecks tests network connectivity and logs a warning on failure.
func runNetworkPreChecks() {
	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "startup",
		"step":   3,
		"reason": "testing network connectivity",
	}).Debug("running network pre-checks")

	if err := testNetworkConnectivity(); err != nil {
		log.WithFields(logger.Fields{
			"at":     "runRouter",
			"phase":  "startup",
			"step":   3,
			"error":  err.Error(),
			"reason": "network connectivity check failed",
		}).Warn("Network connectivity test failed - router may not be able to connect to peers")
	}
}

// launchRouterLifecycle starts the router lifecycle, exiting the process on failure.
func launchRouterLifecycle() {
	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "startup",
		"step":   4,
		"reason": "initiating router creation",
	}).Debug("starting up i2p router")

	if err := manageRouterLifecycle(); err != nil {
		routerCfg := config.GetRouterConfig()
		log.WithError(err).WithFields(logger.Fields{
			"at":         "runRouter",
			"phase":      "startup",
			"reason":     "router creation failed",
			"error_type": fmt.Sprintf("%T", err),
			"config":     routerCfg != nil,
			"suggestion": "check configuration values and system resources",
		}).Errorf("failed to create i2p router: %s", err)
		os.Exit(1)
	}
}

func main() {
	RootCmd.AddCommand(configCmd)
	RootCmd.AddCommand(tuiCmd)
	if err := RootCmd.Execute(); err != nil {
		log.Error(err)
		debugPrintConfig()
		os.Exit(1)
	}
}
