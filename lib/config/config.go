package config

import (
	"os"
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/util"
	"github.com/go-i2p/logger"
	"github.com/spf13/viper"
)

var CfgFile string

const GOI2P_BASE_DIR = ".go-i2p"

func InitConfig() {
	if CfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(CfgFile)
	} else {
		// Set up viper to use the default config path $HOME/.go-ip/
		viper.AddConfigPath(BuildI2PDirPath())
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Load defaults
	setDefaults()

	// handle config file creating it if needed
	handleConfigFile()

	// Update RouterConfigProperties
	UpdateRouterConfig()
}

func setDefaults() {
	// Get comprehensive defaults from defaults.go
	defaults := Defaults()

	// Router defaults
	viper.SetDefault("base_dir", defaults.Router.BaseDir)
	viper.SetDefault("working_dir", defaults.Router.WorkingDir)
	viper.SetDefault("router.info_refresh_interval", defaults.Router.RouterInfoRefreshInterval)
	viper.SetDefault("router.message_expiration_time", defaults.Router.MessageExpirationTime)
	viper.SetDefault("router.max_concurrent_sessions", defaults.Router.MaxConcurrentSessions)

	// NetDB defaults
	viper.SetDefault("netdb.path", defaults.NetDB.Path)
	viper.SetDefault("netdb.max_router_infos", defaults.NetDB.MaxRouterInfos)
	viper.SetDefault("netdb.max_lease_sets", defaults.NetDB.MaxLeaseSets)
	viper.SetDefault("netdb.expiration_check_interval", defaults.NetDB.ExpirationCheckInterval)
	viper.SetDefault("netdb.lease_set_refresh_threshold", defaults.NetDB.LeaseSetRefreshThreshold)
	viper.SetDefault("netdb.exploration_interval", defaults.NetDB.ExplorationInterval)
	viper.SetDefault("netdb.floodfill_enabled", defaults.NetDB.FloodfillEnabled)

	// Bootstrap defaults
	viper.SetDefault("bootstrap.low_peer_threshold", defaults.Bootstrap.LowPeerThreshold)
	viper.SetDefault("bootstrap.bootstrap_type", defaults.Bootstrap.BootstrapType)
	viper.SetDefault("bootstrap.reseed_timeout", defaults.Bootstrap.ReseedTimeout)
	viper.SetDefault("bootstrap.minimum_reseed_peers", defaults.Bootstrap.MinimumReseedPeers)
	viper.SetDefault("bootstrap.reseed_retry_interval", defaults.Bootstrap.ReseedRetryInterval)
	viper.SetDefault("bootstrap.reseed_servers", defaults.Bootstrap.ReseedServers)

	// I2CP defaults
	viper.SetDefault("i2cp.enabled", defaults.I2CP.Enabled)
	viper.SetDefault("i2cp.address", defaults.I2CP.Address)
	viper.SetDefault("i2cp.network", defaults.I2CP.Network)
	viper.SetDefault("i2cp.max_sessions", defaults.I2CP.MaxSessions)
	viper.SetDefault("i2cp.message_queue_size", defaults.I2CP.MessageQueueSize)
	viper.SetDefault("i2cp.session_timeout", defaults.I2CP.SessionTimeout)
	viper.SetDefault("i2cp.read_timeout", defaults.I2CP.ReadTimeout)
	viper.SetDefault("i2cp.write_timeout", defaults.I2CP.WriteTimeout)

	// I2PControl defaults
	viper.SetDefault("i2pcontrol.enabled", defaults.I2PControl.Enabled)
	viper.SetDefault("i2pcontrol.address", defaults.I2PControl.Address)
	viper.SetDefault("i2pcontrol.password", defaults.I2PControl.Password)
	viper.SetDefault("i2pcontrol.use_https", defaults.I2PControl.UseHTTPS)
	viper.SetDefault("i2pcontrol.cert_file", defaults.I2PControl.CertFile)
	viper.SetDefault("i2pcontrol.key_file", defaults.I2PControl.KeyFile)
	viper.SetDefault("i2pcontrol.token_expiration", defaults.I2PControl.TokenExpiration)

	// Tunnel defaults
	viper.SetDefault("tunnel.min_pool_size", defaults.Tunnel.MinPoolSize)
	viper.SetDefault("tunnel.max_pool_size", defaults.Tunnel.MaxPoolSize)
	viper.SetDefault("tunnel.length", defaults.Tunnel.TunnelLength)
	viper.SetDefault("tunnel.lifetime", defaults.Tunnel.TunnelLifetime)
	viper.SetDefault("tunnel.test_interval", defaults.Tunnel.TunnelTestInterval)
	viper.SetDefault("tunnel.test_timeout", defaults.Tunnel.TunnelTestTimeout)
	viper.SetDefault("tunnel.build_timeout", defaults.Tunnel.BuildTimeout)
	viper.SetDefault("tunnel.build_retries", defaults.Tunnel.BuildRetries)
	viper.SetDefault("tunnel.replace_before_expiration", defaults.Tunnel.ReplaceBeforeExpiration)
	viper.SetDefault("tunnel.maintenance_interval", defaults.Tunnel.MaintenanceInterval)

	// Transport defaults
	viper.SetDefault("transport.ntcp2_enabled", defaults.Transport.NTCP2Enabled)
	viper.SetDefault("transport.ntcp2_port", defaults.Transport.NTCP2Port)
	viper.SetDefault("transport.ntcp2_max_connections", defaults.Transport.NTCP2MaxConnections)
	viper.SetDefault("transport.ssu2_enabled", defaults.Transport.SSU2Enabled)
	viper.SetDefault("transport.ssu2_port", defaults.Transport.SSU2Port)
	viper.SetDefault("transport.connection_timeout", defaults.Transport.ConnectionTimeout)
	viper.SetDefault("transport.idle_timeout", defaults.Transport.IdleTimeout)
	viper.SetDefault("transport.max_message_size", defaults.Transport.MaxMessageSize)

	// Performance defaults
	viper.SetDefault("performance.message_queue_size", defaults.Performance.MessageQueueSize)
	viper.SetDefault("performance.worker_pool_size", defaults.Performance.WorkerPoolSize)
	viper.SetDefault("performance.garlic_encryption_cache_size", defaults.Performance.GarlicEncryptionCacheSize)
	viper.SetDefault("performance.fragment_cache_size", defaults.Performance.FragmentCacheSize)
	viper.SetDefault("performance.cleanup_interval", defaults.Performance.CleanupInterval)
}

// NewRouterConfigFromViper creates a new RouterConfig from current viper settings
// This is the preferred way to get config instead of using the global RouterConfigProperties
func NewRouterConfigFromViper() *RouterConfig {
	// Create NetDb configuration
	netDbConfig := &NetDbConfig{
		Path: viper.GetString("netdb.path"),
	}

	// Create Bootstrap configuration
	var reseedServers []*ReseedConfig
	if err := viper.UnmarshalKey("bootstrap.reseed_servers", &reseedServers); err != nil {
		log.WithFields(logger.Fields{
			"at":     "NewRouterConfigFromViper",
			"reason": "reseed_servers_parse_error",
			"phase":  "startup",
			"error":  err.Error(),
		}).Warn("error parsing reseed servers, using empty list")
		reseedServers = []*ReseedConfig{}
	}

	var localNetDbPaths []string
	if err := viper.UnmarshalKey("bootstrap.local_netdb_paths", &localNetDbPaths); err != nil {
		log.Debugf("No local netDb paths configured, will use defaults")
		localNetDbPaths = []string{}
	}

	bootstrapConfig := &BootstrapConfig{
		LowPeerThreshold: viper.GetInt("bootstrap.low_peer_threshold"),
		BootstrapType:    viper.GetString("bootstrap.bootstrap_type"),
		ReseedFilePath:   viper.GetString("bootstrap.reseed_file_path"),
		ReseedServers:    reseedServers,
		LocalNetDbPaths:  localNetDbPaths,
	}

	// Create I2CP configuration
	i2cpConfig := &I2CPConfig{
		Enabled:     viper.GetBool("i2cp.enabled"),
		Address:     viper.GetString("i2cp.address"),
		Network:     viper.GetString("i2cp.network"),
		MaxSessions: viper.GetInt("i2cp.max_sessions"),
	}

	// Create and return new RouterConfig
	return &RouterConfig{
		BaseDir:    viper.GetString("base_dir"),
		WorkingDir: viper.GetString("working_dir"),
		NetDb:      netDbConfig,
		Bootstrap:  bootstrapConfig,
		I2CP:       i2cpConfig,
	}
}

// UpdateRouterConfig updates the global RouterConfigProperties from viper settings
// DEPRECATED: Use NewRouterConfigFromViper() instead to avoid global state mutation
func UpdateRouterConfig() {
	// Update Router configuration
	RouterConfigProperties.BaseDir = viper.GetString("base_dir")
	RouterConfigProperties.WorkingDir = viper.GetString("working_dir")

	// Update NetDb configuration
	RouterConfigProperties.NetDb = &NetDbConfig{
		Path: viper.GetString("netdb.path"),
	}

	// Update Bootstrap configuration
	var reseedServers []*ReseedConfig
	if err := viper.UnmarshalKey("bootstrap.reseed_servers", &reseedServers); err != nil {
		log.WithFields(logger.Fields{
			"at":     "UpdateRouterConfig",
			"reason": "reseed_servers_parse_error",
			"phase":  "startup",
			"error":  err.Error(),
		}).Warn("error parsing reseed servers, using empty list")
		reseedServers = []*ReseedConfig{}
	}

	var localNetDbPaths []string
	if err := viper.UnmarshalKey("bootstrap.local_netdb_paths", &localNetDbPaths); err != nil {
		log.WithFields(logger.Fields{
			"at":     "UpdateRouterConfig",
			"reason": "no_local_netdb_paths_configured",
			"phase":  "startup",
		}).Debug("using default netDb paths")
		localNetDbPaths = []string{}
	}

	RouterConfigProperties.Bootstrap = &BootstrapConfig{
		LowPeerThreshold: viper.GetInt("bootstrap.low_peer_threshold"),
		BootstrapType:    viper.GetString("bootstrap.bootstrap_type"),
		ReseedFilePath:   viper.GetString("bootstrap.reseed_file_path"),
		ReseedServers:    reseedServers,
		LocalNetDbPaths:  localNetDbPaths,
	}

	// Update I2CP configuration
	RouterConfigProperties.I2CP = &I2CPConfig{
		Enabled:     viper.GetBool("i2cp.enabled"),
		Address:     viper.GetString("i2cp.address"),
		Network:     viper.GetString("i2cp.network"),
		MaxSessions: viper.GetInt("i2cp.max_sessions"),
	}

	// Update I2PControl configuration
	RouterConfigProperties.I2PControl = &I2PControlConfig{
		Enabled:         viper.GetBool("i2pcontrol.enabled"),
		Address:         viper.GetString("i2pcontrol.address"),
		Password:        viper.GetString("i2pcontrol.password"),
		UseHTTPS:        viper.GetBool("i2pcontrol.use_https"),
		CertFile:        viper.GetString("i2pcontrol.cert_file"),
		KeyFile:         viper.GetString("i2pcontrol.key_file"),
		TokenExpiration: viper.GetDuration("i2pcontrol.token_expiration"),
	}
}

func createDefaultConfig(defaultConfigDir string) {
	defaultConfigFile := filepath.Join(defaultConfigDir, "config.yaml")
	// Ensure directory exists
	if err := os.MkdirAll(defaultConfigDir, 0o755); err != nil {
		log.Fatalf("Could not create config directory: %s", err)
	}

	// Write current config file
	if err := viper.SafeWriteConfig(); err != nil {
		log.Fatalf("Could not write default config file: %s", err)
	}

	log.WithFields(logger.Fields{
		"at":          "createDefaultConfig",
		"reason":      "default_config_created",
		"phase":       "startup",
		"config_file": defaultConfigFile,
		"config_dir":  defaultConfigDir,
	}).Debug("created default configuration")
}

func handleConfigFile() {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			if CfgFile != "" {
				log.Fatalf("Config file %s is not found: %s", CfgFile, err)
			} else {
				createDefaultConfig(BuildI2PDirPath())
			}
		} else {
			log.Fatalf("Error reading config file: %s", err)
		}
	} else {
		log.WithFields(logger.Fields{
			"at":          "handleConfigFile",
			"reason":      "config_file_loaded",
			"phase":       "startup",
			"config_file": viper.ConfigFileUsed(),
		}).Debug("using config file")
	}
}

func BuildI2PDirPath() string {
	return filepath.Join(util.UserHome(), GOI2P_BASE_DIR)
}
