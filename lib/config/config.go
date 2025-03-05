package config

import (
	"os"
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/util"
	"github.com/go-i2p/logger"
	"github.com/spf13/viper"
)

var (
	CfgFile string
	log     = logger.GetGoI2PLogger()
)

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

	// handle config file creating if needed
	handleConfigFile()

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

func createDefaultConfig(defaultConfigDir string) {

	defaultConfigFile := filepath.Join(defaultConfigDir, "config.yaml")
	// Ensure directory exists
	if err := os.MkdirAll(defaultConfigDir, 0o755); err != nil {
		log.Fatalf("Could not create config directory: %s", err)
	}

	// Write current config file
	if err := viper.WriteConfig(); err != nil {
		log.Fatalf("Could not write default config file: %s", err)
	}

	log.Debugf("Created default configuration at: %s", defaultConfigFile)

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
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}

}

func BuildI2PDirPath() string {
	return filepath.Join(util.UserHome(), GOI2P_BASE_DIR)
}
