// Package cliflags registers and binds all go-i2p CLI flags for the cobra/viper
// configuration pipeline. Extracting this wiring from package main lets any
// future binary (cmd/go-i2pd, a test harness, a TUI-only daemon) reuse the
// exact same flag surface with one import.
package cliflags

import (
	"fmt"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RegisterAll registers every go-i2p CLI flag as a persistent flag on cmd.
// Call this once from init(), before cobra parses arguments.
func RegisterAll(cmd *cobra.Command) {
	registerGlobalFlags(cmd)
	registerRouterFlags(cmd)
	registerNetDBFlags(cmd)
	registerBootstrapFlags(cmd)
	registerI2CPFlags(cmd)
	registerI2PControlFlags(cmd)
	registerTransportFlags(cmd)
	registerTunnelFlags(cmd)
	registerPerformanceFlags(cmd)
	registerCongestionFlags(cmd)
}

// BindAll binds every flag registered by RegisterAll to the viper instance v.
// cmd must be the same command passed to RegisterAll.
// Returns the first binding error encountered, or nil.
func BindAll(cmd *cobra.Command, v *viper.Viper) error {
	binders := []func(*cobra.Command, *viper.Viper) error{
		bindRouterFlags,
		bindNetDBFlags,
		bindBootstrapFlags,
		bindI2CPFlags,
		bindI2PControlFlags,
		bindTransportFlags,
		bindTunnelFlags,
		bindPerformanceFlags,
		bindCongestionFlags,
	}
	for _, fn := range binders {
		if err := fn(cmd, v); err != nil {
			return err
		}
	}
	return nil
}

// bind is the single low-level helper: it looks up flagName on cmd's persistent
// flags and binds it to viperKey in v. Returns an error describing the problem
// so callers can propagate or fatal as appropriate.
func bind(v *viper.Viper, cmd *cobra.Command, viperKey, flagName string) error {
	flag := cmd.PersistentFlags().Lookup(flagName)
	if flag == nil {
		return fmt.Errorf("cliflags: flag %q not registered on command %q", flagName, cmd.Name())
	}
	if err := v.BindPFlag(viperKey, flag); err != nil {
		return fmt.Errorf("cliflags: BindPFlag(%q, %q): %w", viperKey, flagName, err)
	}
	return nil
}

// bindPairs calls bind for each (viperKey, flagName) pair in pairs.
// Returns the first binding error encountered, or nil.
func bindPairs(cmd *cobra.Command, v *viper.Viper, pairs [][2]string) error {
	for _, p := range pairs {
		if err := bind(v, cmd, p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

// ── registration ─────────────────────────────────────────────────────────────

func registerGlobalFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&config.CfgFile, "config", "",
		"config file (default is $HOME/.go-i2p/config.yaml)")
}

func registerRouterFlags(cmd *cobra.Command) {
	routerCfg := config.DefaultRouterConfig()
	defaults := config.Defaults()
	cmd.PersistentFlags().String("base-dir", routerCfg.BaseDir,
		"Base directory for I2P router")
	cmd.PersistentFlags().String("working-dir", routerCfg.WorkingDir,
		"Working directory for I2P router")
	cmd.PersistentFlags().Uint64("router.max-bandwidth", routerCfg.MaxBandwidth,
		"Maximum bandwidth in bytes/sec (0 = unlimited)")
	cmd.PersistentFlags().Int("router.max-connections", routerCfg.MaxConnections,
		"Maximum concurrent transport connections")
	cmd.PersistentFlags().Bool("router.accept-tunnels", routerCfg.AcceptTunnels,
		"Participate in transit tunnels for the network")
	cmd.PersistentFlags().Bool("router.hidden", routerCfg.Hidden,
		"Hidden mode: client-only operation, no transit, no published transport addresses")
	cmd.PersistentFlags().Duration("router.info-refresh-interval",
		defaults.Router.RouterInfoRefreshInterval,
		"How often to refresh our RouterInfo")
	cmd.PersistentFlags().Duration("router.message-expiration-time",
		defaults.Router.MessageExpirationTime,
		"How long messages stay valid")
	cmd.PersistentFlags().Int("router.max-concurrent-sessions",
		defaults.Router.MaxConcurrentSessions,
		"Maximum active transport sessions")
}

func registerNetDBFlags(cmd *cobra.Command) {
	defaults := config.Defaults()
	cmd.PersistentFlags().String("netdb.path", config.DefaultNetDBConfig.Path,
		"Path to the netDb")
	cmd.PersistentFlags().Int("netdb.max-router-infos", defaults.NetDB.MaxRouterInfos,
		"Maximum RouterInfos to store locally")
	cmd.PersistentFlags().Int("netdb.max-lease-sets", defaults.NetDB.MaxLeaseSets,
		"Maximum LeaseSets to cache")
	cmd.PersistentFlags().Duration("netdb.expiration-check-interval",
		defaults.NetDB.ExpirationCheckInterval,
		"How often to check for expired entries")
	cmd.PersistentFlags().Duration("netdb.lease-set-refresh-threshold",
		defaults.NetDB.LeaseSetRefreshThreshold,
		"How far before expiration to refresh a LeaseSet")
	cmd.PersistentFlags().Duration("netdb.exploration-interval",
		defaults.NetDB.ExplorationInterval,
		"How often to explore the network for new peers")
	cmd.PersistentFlags().Bool("netdb.floodfill-enabled", defaults.NetDB.FloodfillEnabled,
		"Operate as a floodfill router")
}

func registerBootstrapFlags(cmd *cobra.Command) {
	defaults := config.Defaults()
	cmd.PersistentFlags().Int("bootstrap.low-peer-threshold",
		config.DefaultBootstrapConfig.LowPeerThreshold,
		"Minimum number of peers before reseeding")
	cmd.PersistentFlags().String("bootstrap.type",
		config.DefaultBootstrapConfig.BootstrapType,
		"Bootstrap type: auto (tries all methods), file (local file only), reseed (remote only), local (netDb only)")
	cmd.PersistentFlags().String("bootstrap.reseed-file", "",
		"Path to local reseed file (zip or su3) - takes priority over remote reseed servers")
	cmd.PersistentFlags().Duration("bootstrap.reseed-timeout",
		defaults.Bootstrap.ReseedTimeout,
		"Maximum time to wait for reseed operations")
	cmd.PersistentFlags().Int("bootstrap.minimum-reseed-peers",
		defaults.Bootstrap.MinimumReseedPeers,
		"Minimum peers to obtain from reseed")
	cmd.PersistentFlags().Duration("bootstrap.reseed-retry-interval",
		defaults.Bootstrap.ReseedRetryInterval,
		"Time between reseed attempts")
	cmd.PersistentFlags().Int("bootstrap.min-reseed-servers",
		config.DefaultBootstrapConfig.MinReseedServers,
		"Minimum successful reseed servers required")
	cmd.PersistentFlags().String("bootstrap.reseed-strategy",
		config.DefaultBootstrapConfig.ReseedStrategy,
		"How to combine RouterInfos from multiple servers: union, intersection, or random")
}

func registerI2CPFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().Bool("i2cp.enabled", config.DefaultI2CPConfig.Enabled,
		"Enable I2CP server for client applications")
	cmd.PersistentFlags().String("i2cp.address", config.DefaultI2CPConfig.Address,
		"I2CP server listen address")
	cmd.PersistentFlags().String("i2cp.network", config.DefaultI2CPConfig.Network,
		"I2CP network type (tcp or unix)")
	cmd.PersistentFlags().Int("i2cp.max-sessions", config.DefaultI2CPConfig.MaxSessions,
		"Maximum number of concurrent I2CP sessions (range: 1-320)")
	cmd.PersistentFlags().String("i2cp.username", "",
		"I2CP authentication username (empty = no auth)")
	cmd.PersistentFlags().String("i2cp.password", "",
		"I2CP authentication password (empty = no auth)")
	cmd.PersistentFlags().Bool("i2cp.allow-insecure-cleartext-auth",
		config.DefaultI2CPConfig.AllowInsecureCleartextAuth,
		"Allow non-loopback authenticated I2CP over cleartext TCP (unsafe; prefer TLS/front-proxy)")
	cmd.PersistentFlags().Int("i2cp.message-queue-size",
		config.DefaultI2CPConfig.MessageQueueSize,
		"Buffer size for outbound messages per session")
	cmd.PersistentFlags().Duration("i2cp.session-timeout",
		config.DefaultI2CPConfig.SessionTimeout,
		"Idle session timeout (0 = no timeout)")
	cmd.PersistentFlags().Duration("i2cp.read-timeout",
		config.DefaultI2CPConfig.ReadTimeout,
		"Maximum time to wait for client reads")
	cmd.PersistentFlags().Duration("i2cp.write-timeout",
		config.DefaultI2CPConfig.WriteTimeout,
		"Maximum time to wait for client writes")
}

func registerI2PControlFlags(cmd *cobra.Command) {
	defaultCfg := config.DefaultI2PControlConfig()
	cmd.PersistentFlags().Bool("i2pcontrol.enabled", defaultCfg.Enabled,
		"Enable I2PControl JSON-RPC server")
	cmd.PersistentFlags().String("i2pcontrol.address", defaultCfg.Address,
		"I2PControl server listen address (host:port)")
	cmd.PersistentFlags().String("i2pcontrol.password", "",
		"I2PControl API password (default: random from config file, or 'itoopie' if no config)")
	cmd.PersistentFlags().Bool("i2pcontrol.use-https", defaultCfg.UseHTTPS,
		"Enable TLS/HTTPS for I2PControl server")
	cmd.PersistentFlags().String("i2pcontrol.cert-file", defaultCfg.CertFile,
		"Path to TLS certificate file (PEM format, required when HTTPS enabled)")
	cmd.PersistentFlags().String("i2pcontrol.key-file", defaultCfg.KeyFile,
		"Path to TLS private key file (PEM format, required when HTTPS enabled)")
	cmd.PersistentFlags().Duration("i2pcontrol.token-expiration",
		defaultCfg.TokenExpiration,
		"How long authentication tokens remain valid")
}

func registerTransportFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().Bool("transport.ntcp2-enabled",
		config.DefaultTransportConfig.NTCP2Enabled,
		"Enable NTCP2 transport (TCP-based)")
	cmd.PersistentFlags().Int("transport.ntcp2-port",
		config.DefaultTransportConfig.NTCP2Port,
		"NTCP2 listen port (0 = random port assigned by OS)")
	cmd.PersistentFlags().Int("transport.ntcp2-max-connections",
		config.DefaultTransportConfig.NTCP2MaxConnections,
		"Maximum concurrent NTCP2 sessions")
	cmd.PersistentFlags().Bool("transport.ssu2-enabled",
		config.DefaultTransportConfig.SSU2Enabled,
		"Enable SSU2 transport (UDP-based, currently experimental)")
	cmd.PersistentFlags().Int("transport.ssu2-port",
		config.DefaultTransportConfig.SSU2Port,
		"SSU2 listen port (0 = random port assigned by OS)")
	cmd.PersistentFlags().Duration("transport.connection-timeout",
		config.DefaultTransportConfig.ConnectionTimeout,
		"Maximum time to establish a connection")
	cmd.PersistentFlags().Duration("transport.idle-timeout",
		config.DefaultTransportConfig.IdleTimeout,
		"When to close idle connections")
	cmd.PersistentFlags().Int("transport.max-message-size",
		config.DefaultTransportConfig.MaxMessageSize,
		"Maximum I2NP message size in bytes")
}

func registerTunnelFlags(cmd *cobra.Command) {
	defaults := config.Defaults()
	cmd.PersistentFlags().Int("tunnel.min-pool-size", defaults.Tunnel.MinPoolSize,
		"Minimum tunnels to maintain per pool")
	cmd.PersistentFlags().Int("tunnel.max-pool-size", defaults.Tunnel.MaxPoolSize,
		"Maximum tunnels to maintain per pool")
	cmd.PersistentFlags().Int("tunnel.length", defaults.Tunnel.TunnelLength,
		"Hops per tunnel (I2P protocol standard: 3)")
	cmd.PersistentFlags().Duration("tunnel.lifetime", defaults.Tunnel.TunnelLifetime,
		"How long tunnels stay active")
	cmd.PersistentFlags().Duration("tunnel.test-interval",
		defaults.Tunnel.TunnelTestInterval,
		"How often to test tunnel health")
	cmd.PersistentFlags().Duration("tunnel.test-timeout",
		defaults.Tunnel.TunnelTestTimeout,
		"Maximum time to wait for tunnel test response")
	cmd.PersistentFlags().Duration("tunnel.build-timeout",
		defaults.Tunnel.BuildTimeout,
		"Maximum time to wait for tunnel build")
	cmd.PersistentFlags().Int("tunnel.build-retries", defaults.Tunnel.BuildRetries,
		"Maximum attempts to build a tunnel")
	cmd.PersistentFlags().Duration("tunnel.replace-before-expiration",
		defaults.Tunnel.ReplaceBeforeExpiration,
		"When to build replacement tunnel before expiration")
	cmd.PersistentFlags().Duration("tunnel.maintenance-interval",
		defaults.Tunnel.MaintenanceInterval,
		"How often to run pool maintenance")
	cmd.PersistentFlags().Int("tunnel.max-participating-tunnels",
		defaults.Tunnel.MaxParticipatingTunnels,
		"Hard limit on tunnels where we act as intermediate hop")
	cmd.PersistentFlags().Bool("tunnel.participating-limits-enabled",
		defaults.Tunnel.ParticipatingLimitsEnabled,
		"Enable global participating tunnel limits")
	cmd.PersistentFlags().Bool("tunnel.per-source-rate-limit-enabled",
		defaults.Tunnel.PerSourceRateLimitEnabled,
		"Enable per-source tunnel build request rate limiting")
	cmd.PersistentFlags().Int("tunnel.max-build-requests-per-minute",
		defaults.Tunnel.MaxBuildRequestsPerMinute,
		"Maximum tunnel build requests per source per minute")
	cmd.PersistentFlags().Int("tunnel.build-request-burst-size",
		defaults.Tunnel.BuildRequestBurstSize,
		"Burst allowance for tunnel build requests")
	cmd.PersistentFlags().Duration("tunnel.source-ban-duration",
		defaults.Tunnel.SourceBanDuration,
		"How long to ban sources that exceed rate limits")
}

func registerPerformanceFlags(cmd *cobra.Command) {
	defaults := config.Defaults()
	cmd.PersistentFlags().Int("performance.message-queue-size",
		defaults.Performance.MessageQueueSize,
		"Buffer size for router message processing")
	cmd.PersistentFlags().Int("performance.worker-pool-size",
		defaults.Performance.WorkerPoolSize,
		"Concurrent message processing workers")
	cmd.PersistentFlags().Int("performance.garlic-encryption-cache-size",
		defaults.Performance.GarlicEncryptionCacheSize,
		"Cache size for garlic encryption sessions")
	cmd.PersistentFlags().Int("performance.fragment-cache-size",
		defaults.Performance.FragmentCacheSize,
		"Cache size for message fragment reassembly")
	cmd.PersistentFlags().Duration("performance.cleanup-interval",
		defaults.Performance.CleanupInterval,
		"How often to run cleanup tasks")
}

func registerCongestionFlags(cmd *cobra.Command) {
	defaults := config.Defaults()
	cmd.PersistentFlags().Float64("congestion.d-flag-threshold",
		defaults.Congestion.DFlagThreshold,
		"Participating tunnel ratio to advertise D (medium congestion) flag")
	cmd.PersistentFlags().Float64("congestion.e-flag-threshold",
		defaults.Congestion.EFlagThreshold,
		"Participating tunnel ratio to advertise E (high congestion) flag")
	cmd.PersistentFlags().Float64("congestion.g-flag-threshold",
		defaults.Congestion.GFlagThreshold,
		"Participating tunnel ratio to advertise G (critical congestion) flag")
	cmd.PersistentFlags().Float64("congestion.clear-d-flag-threshold",
		defaults.Congestion.ClearDFlagThreshold,
		"Ratio to clear D flag and return to normal")
	cmd.PersistentFlags().Float64("congestion.clear-e-flag-threshold",
		defaults.Congestion.ClearEFlagThreshold,
		"Ratio to clear E flag (downgrade to D or clear)")
	cmd.PersistentFlags().Float64("congestion.clear-g-flag-threshold",
		defaults.Congestion.ClearGFlagThreshold,
		"Ratio to clear G flag (downgrade to E)")
	cmd.PersistentFlags().Duration("congestion.averaging-window",
		defaults.Congestion.AveragingWindow,
		"Duration to average congestion metrics over")
	cmd.PersistentFlags().Duration("congestion.e-flag-age-threshold",
		defaults.Congestion.EFlagAgeThreshold,
		"When E flag on stale RouterInfo is treated as D flag")
	cmd.PersistentFlags().Float64("congestion.d-flag-capacity-multiplier",
		defaults.Congestion.DFlagCapacityMultiplier,
		"Capacity multiplier for D-flagged peers in tunnel building")
	cmd.PersistentFlags().Float64("congestion.e-flag-capacity-multiplier",
		defaults.Congestion.EFlagCapacityMultiplier,
		"Capacity multiplier for E-flagged peers in tunnel building")
	cmd.PersistentFlags().Float64("congestion.stale-e-flag-capacity-multiplier",
		defaults.Congestion.StaleEFlagCapacityMultiplier,
		"Capacity multiplier for E-flagged peers with stale RouterInfo")
}

// ── binding ───────────────────────────────────────────────────────────────────

func bindRouterFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"base_dir", "base-dir"},
		{"working_dir", "working-dir"},
		{"router.max_bandwidth", "router.max-bandwidth"},
		{"router.max_connections", "router.max-connections"},
		{"router.accept_tunnels", "router.accept-tunnels"},
		{"router.hidden", "router.hidden"},
		{"router.info_refresh_interval", "router.info-refresh-interval"},
		{"router.message_expiration_time", "router.message-expiration-time"},
		{"router.max_concurrent_sessions", "router.max-concurrent-sessions"},
	})
}

func bindNetDBFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"netdb.path", "netdb.path"},
		{"netdb.max_router_infos", "netdb.max-router-infos"},
		{"netdb.max_lease_sets", "netdb.max-lease-sets"},
		{"netdb.expiration_check_interval", "netdb.expiration-check-interval"},
		{"netdb.lease_set_refresh_threshold", "netdb.lease-set-refresh-threshold"},
		{"netdb.exploration_interval", "netdb.exploration-interval"},
		{"netdb.floodfill_enabled", "netdb.floodfill-enabled"},
	})
}

func bindBootstrapFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"bootstrap.low_peer_threshold", "bootstrap.low-peer-threshold"},
		{"bootstrap.bootstrap_type", "bootstrap.type"},
		{"bootstrap.reseed_file_path", "bootstrap.reseed-file"},
		{"bootstrap.reseed_timeout", "bootstrap.reseed-timeout"},
		{"bootstrap.minimum_reseed_peers", "bootstrap.minimum-reseed-peers"},
		{"bootstrap.reseed_retry_interval", "bootstrap.reseed-retry-interval"},
		{"bootstrap.min_reseed_servers", "bootstrap.min-reseed-servers"},
		{"bootstrap.reseed_strategy", "bootstrap.reseed-strategy"},
	})
}

func bindI2CPFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"i2cp.enabled", "i2cp.enabled"},
		{"i2cp.address", "i2cp.address"},
		{"i2cp.network", "i2cp.network"},
		{"i2cp.max_sessions", "i2cp.max-sessions"},
		{"i2cp.username", "i2cp.username"},
		{"i2cp.password", "i2cp.password"},
		{"i2cp.allow_insecure_cleartext_auth", "i2cp.allow-insecure-cleartext-auth"},
		{"i2cp.message_queue_size", "i2cp.message-queue-size"},
		{"i2cp.session_timeout", "i2cp.session-timeout"},
		{"i2cp.read_timeout", "i2cp.read-timeout"},
		{"i2cp.write_timeout", "i2cp.write-timeout"},
	})
}

func bindI2PControlFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"i2pcontrol.enabled", "i2pcontrol.enabled"},
		{"i2pcontrol.address", "i2pcontrol.address"},
		{"i2pcontrol.password", "i2pcontrol.password"},
		{"i2pcontrol.use_https", "i2pcontrol.use-https"},
		{"i2pcontrol.cert_file", "i2pcontrol.cert-file"},
		{"i2pcontrol.key_file", "i2pcontrol.key-file"},
		{"i2pcontrol.token_expiration", "i2pcontrol.token-expiration"},
	})
}

func bindTransportFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"transport.ntcp2_enabled", "transport.ntcp2-enabled"},
		{"transport.ntcp2_port", "transport.ntcp2-port"},
		{"transport.ntcp2_max_connections", "transport.ntcp2-max-connections"},
		{"transport.ssu2_enabled", "transport.ssu2-enabled"},
		{"transport.ssu2_port", "transport.ssu2-port"},
		{"transport.connection_timeout", "transport.connection-timeout"},
		{"transport.idle_timeout", "transport.idle-timeout"},
		{"transport.max_message_size", "transport.max-message-size"},
	})
}

func bindTunnelFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"tunnel.min_pool_size", "tunnel.min-pool-size"},
		{"tunnel.max_pool_size", "tunnel.max-pool-size"},
		{"tunnel.length", "tunnel.length"},
		{"tunnel.lifetime", "tunnel.lifetime"},
		{"tunnel.test_interval", "tunnel.test-interval"},
		{"tunnel.test_timeout", "tunnel.test-timeout"},
		{"tunnel.build_timeout", "tunnel.build-timeout"},
		{"tunnel.build_retries", "tunnel.build-retries"},
		{"tunnel.replace_before_expiration", "tunnel.replace-before-expiration"},
		{"tunnel.maintenance_interval", "tunnel.maintenance-interval"},
		{"tunnel.max_participating_tunnels", "tunnel.max-participating-tunnels"},
		{"tunnel.participating_limits_enabled", "tunnel.participating-limits-enabled"},
		{"tunnel.per_source_rate_limit_enabled", "tunnel.per-source-rate-limit-enabled"},
		{"tunnel.max_build_requests_per_minute", "tunnel.max-build-requests-per-minute"},
		{"tunnel.build_request_burst_size", "tunnel.build-request-burst-size"},
		{"tunnel.source_ban_duration", "tunnel.source-ban-duration"},
	})
}

func bindPerformanceFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"performance.message_queue_size", "performance.message-queue-size"},
		{"performance.worker_pool_size", "performance.worker-pool-size"},
		{"performance.garlic_encryption_cache_size", "performance.garlic-encryption-cache-size"},
		{"performance.fragment_cache_size", "performance.fragment-cache-size"},
		{"performance.cleanup_interval", "performance.cleanup-interval"},
	})
}

func bindCongestionFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindPairs(cmd, v, [][2]string{
		{"router.congestion.d_flag_threshold", "congestion.d-flag-threshold"},
		{"router.congestion.e_flag_threshold", "congestion.e-flag-threshold"},
		{"router.congestion.g_flag_threshold", "congestion.g-flag-threshold"},
		{"router.congestion.clear_d_flag_threshold", "congestion.clear-d-flag-threshold"},
		{"router.congestion.clear_e_flag_threshold", "congestion.clear-e-flag-threshold"},
		{"router.congestion.clear_g_flag_threshold", "congestion.clear-g-flag-threshold"},
		{"router.congestion.averaging_window", "congestion.averaging-window"},
		{"router.congestion.e_flag_age_threshold", "congestion.e-flag-age-threshold"},
		{"router.congestion.d_flag_capacity_multiplier", "congestion.d-flag-capacity-multiplier"},
		{"router.congestion.e_flag_capacity_multiplier", "congestion.e-flag-capacity-multiplier"},
		{"router.congestion.stale_e_flag_capacity_multiplier", "congestion.stale-e-flag-capacity-multiplier"},
	})
}
