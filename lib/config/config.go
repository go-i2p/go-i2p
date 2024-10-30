package config

import (
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

var (
	CfgFile        string
	routerInstance *router.Router
	log            = logger.GetGoI2PLogger()
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "go-i2p",
	Short: "I2P Router implementation in Go",
	Run: func(cmd *cobra.Command, args []string) {
		runRouter()
	},
}

func InitConfig() {
	defaultConfigDir := filepath.Join(os.Getenv("HOME"), ".go-i2p")
	defaultConfigFile := filepath.Join(defaultConfigDir, "config.yaml")

	if CfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(CfgFile)
	} else {
		// Create default config if it doesn't exist
		if _, err := os.Stat(defaultConfigFile); os.IsNotExist(err) {
			// Ensure directory exists
			if err := os.MkdirAll(defaultConfigDir, 0755); err != nil {
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

			// Marshal config to YAML
			yamlData, err := yaml.Marshal(defaultConfig)
			if err != nil {
				log.Fatalf("Could not marshal default config: %s", err)
			}

			// Write default config file
			if err := os.WriteFile(defaultConfigFile, yamlData, 0644); err != nil {
				log.Fatalf("Could not write default config file: %s", err)
			}

			log.Infof("Created default configuration at: %s", defaultConfigFile)
		}

		// Set up viper to use the config file
		viper.AddConfigPath(defaultConfigDir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Load defaults
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		log.Warnf("Error reading config file: %s", err)
	} else {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}

	// Update RouterConfigProperties
	updateRouterConfig()
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

func updateRouterConfig() {
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

func runRouter() {
	go signals.Handle()

	log.Debug("parsing i2p router configuration")
	log.Debug("using netDb in:", RouterConfigProperties.NetDb.Path)
	log.Debug("starting up i2p router")

	var err error
	routerInstance, err = router.CreateRouter()
	if err == nil {
		signals.RegisterReloadHandler(func() {
			if err := viper.ReadInConfig(); err != nil {
				log.Errorf("failed to reload config: %s", err)
				return
			}
			updateRouterConfig()
		})

		signals.RegisterInterruptHandler(func() {
			if routerInstance != nil {
				routerInstance.Stop()
			}
		})

		routerInstance.Start()
		routerInstance.Wait()
		routerInstance.Close()
	} else {
		log.Errorf("failed to create i2p router: %s", err)
	}
}
