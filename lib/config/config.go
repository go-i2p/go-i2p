package config

import (
	"os"
	"path/filepath"

	"github.com/go-i2p/logger"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	CfgFile string
	log     = logger.GetGoI2PLogger()
)

const GOI2P_BASE_DIR = ".go-i2p"

func InitConfig() {
	defaultConfigDir := filepath.Join(os.Getenv("HOME"), GOI2P_BASE_DIR)
	defaultConfigFile := filepath.Join(defaultConfigDir, "config.yaml")

	if CfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(CfgFile)
	} else {
		// Create default config if it doesn't exist
		if _, err := os.Stat(defaultConfigFile); os.IsNotExist(err) {
			// Ensure directory exists
			if err := os.MkdirAll(defaultConfigDir, 0o755); err != nil {
				log.Fatalf("Could not create config directory: %s", err)
			}

			// Create default configuration
			defaultConfig := struct {
				BaseDir    string          `yaml:"base_dir"`
				WorkingDir string          `yaml:"working_dir"`
				NetDB      NetDbConfig     `yaml:"netdb"`
				Bootstrap  BootstrapConfig `yaml:"bootstrap"`
			}{
				BaseDir:    DefaultRouterConfig().BaseDir,
				WorkingDir: DefaultRouterConfig().WorkingDir,
				NetDB:      *DefaultRouterConfig().NetDb,
				Bootstrap:  *DefaultRouterConfig().Bootstrap,
			}

			yamlData, err := yaml.Marshal(defaultConfig)
			if err != nil {
				log.Fatalf("Could not marshal default config: %s", err)
			}

			// Write default config file
			if err := os.WriteFile(defaultConfigFile, yamlData, 0o644); err != nil {
				log.Fatalf("Could not write default config file: %s", err)
			}

			log.Debugf("Created default configuration at: %s", defaultConfigFile)
		}

		// Set up viper to use the config file
		viper.AddConfigPath(defaultConfigDir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Load defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		log.Warnf("Error reading config file: %s", err)
	} else {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}

	// Update RouterConfigProperties
	UpdateRouterConfig()
}

func setDefaults() {
	// Router defaults
	viper.SetDefault("base_dir", DefaultRouterConfig().BaseDir)
	viper.SetDefault("working_dir", DefaultRouterConfig().WorkingDir)

	// NetDb defaults
	viper.SetDefault("netdb.path", DefaultNetDbConfig.Path)

	// Bootstrap defaults
	viper.SetDefault("bootstrap.low_peer_threshold", DefaultBootstrapConfig.LowPeerThreshold)
	viper.SetDefault("bootstrap.reseed_servers", []ReseedConfig{})
}

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
		log.Warnf("Error parsing reseed servers: %s", err)
		reseedServers = []*ReseedConfig{}
	}

	RouterConfigProperties.Bootstrap = &BootstrapConfig{
		LowPeerThreshold: viper.GetInt("bootstrap.low_peer_threshold"),
		ReseedServers:    reseedServers,
	}
}
