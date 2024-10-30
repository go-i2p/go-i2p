package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/go-i2p/go-i2p/lib/util/signals"
)

var (
	cfgFile        string
	routerInstance *router.Router
	log            = logger.GetGoI2PLogger()
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-i2p",
	Short: "I2P Router implementation in Go",
	Run: func(cmd *cobra.Command, args []string) {
		runRouter()
	},
}

func initConfig() {
	defaultConfigDir := filepath.Join(os.Getenv("HOME"), ".go-i2p")
	defaultConfigFile := filepath.Join(defaultConfigDir, "config.yaml")

	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Create default config if it doesn't exist
		if _, err := os.Stat(defaultConfigFile); os.IsNotExist(err) {
			// Ensure directory exists
			if err := os.MkdirAll(defaultConfigDir, 0755); err != nil {
				log.Fatalf("Could not create config directory: %s", err)
			}

			// Create default configuration
			defaultConfig := struct {
				BaseDir    string                 `yaml:"base_dir"`
				WorkingDir string                 `yaml:"working_dir"`
				NetDB      config.NetDbConfig     `yaml:"netdb"`
				Bootstrap  config.BootstrapConfig `yaml:"bootstrap"`
			}{
				BaseDir:    config.DefaultRouterConfig().BaseDir,
				WorkingDir: config.DefaultRouterConfig().WorkingDir,
				NetDB:      *config.DefaultRouterConfig().NetDb,
				Bootstrap:  *config.DefaultRouterConfig().Bootstrap,
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

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-i2p/config.yaml)")

	// Router configuration flags
	rootCmd.PersistentFlags().String("base-dir", config.DefaultRouterConfig().BaseDir, "Base directory for I2P router")
	rootCmd.PersistentFlags().String("working-dir", config.DefaultRouterConfig().WorkingDir, "Working directory for I2P router")

	// NetDb flags
	rootCmd.PersistentFlags().String("netdb.path", config.DefaultNetDbConfig.Path, "Path to the netDb")

	// Bootstrap flags
	rootCmd.PersistentFlags().Int("bootstrap.low-peer-threshold", config.DefaultBootstrapConfig.LowPeerThreshold,
		"Minimum number of peers before reseeding")

	// Bind flags to viper
	viper.BindPFlag("base_dir", rootCmd.PersistentFlags().Lookup("base-dir"))
	viper.BindPFlag("working_dir", rootCmd.PersistentFlags().Lookup("working-dir"))
	viper.BindPFlag("netdb.path", rootCmd.PersistentFlags().Lookup("netdb.path"))
	viper.BindPFlag("bootstrap.low_peer_threshold", rootCmd.PersistentFlags().Lookup("bootstrap.low-peer-threshold"))
}

func setDefaults() {
	// Router defaults
	viper.SetDefault("base_dir", config.DefaultRouterConfig().BaseDir)
	viper.SetDefault("working_dir", config.DefaultRouterConfig().WorkingDir)

	// NetDb defaults
	viper.SetDefault("netdb.path", config.DefaultNetDbConfig.Path)

	// Bootstrap defaults
	viper.SetDefault("bootstrap.low_peer_threshold", config.DefaultBootstrapConfig.LowPeerThreshold)
	viper.SetDefault("bootstrap.reseed_servers", []config.ReseedConfig{})
}

func updateRouterConfig() {
	// Update Router configuration
	config.RouterConfigProperties.BaseDir = viper.GetString("base_dir")
	config.RouterConfigProperties.WorkingDir = viper.GetString("working_dir")

	// Update NetDb configuration
	config.RouterConfigProperties.NetDb = &config.NetDbConfig{
		Path: viper.GetString("netdb.path"),
	}

	// Update Bootstrap configuration
	var reseedServers []*config.ReseedConfig
	if err := viper.UnmarshalKey("bootstrap.reseed_servers", &reseedServers); err != nil {
		log.Warnf("Error parsing reseed servers: %s", err)
		reseedServers = []*config.ReseedConfig{}
	}

	config.RouterConfigProperties.Bootstrap = &config.BootstrapConfig{
		LowPeerThreshold: viper.GetInt("bootstrap.low_peer_threshold"),
		ReseedServers:    reseedServers,
	}
}
func runRouter() {
	go signals.Handle()

	log.Debug("parsing i2p router configuration")
	log.Debug("using netDb in:", config.RouterConfigProperties.NetDb.Path)
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

// configCmd shows current configuration
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Configuration file: %s\n", viper.ConfigFileUsed())
		fmt.Printf("\nRouter Configuration:")
		fmt.Printf("  Base Directory: %s", config.RouterConfigProperties.BaseDir)
		fmt.Printf("  Working Directory: %s", config.RouterConfigProperties.WorkingDir)

		fmt.Printf("\nNetDb Configuration:")
		fmt.Printf("  Path: %s", config.RouterConfigProperties.NetDb.Path)

		fmt.Printf("\nBootstrap Configuration:")
		fmt.Printf("  Low Peer Threshold: %d", config.RouterConfigProperties.Bootstrap.LowPeerThreshold)
		fmt.Printf("  Reseed Servers:")
		for _, server := range config.RouterConfigProperties.Bootstrap.ReseedServers {
			fmt.Printf("    - URL: %s", server.Url)
			fmt.Printf("      SU3 Fingerprint: %s", server.SU3Fingerprint)
		}
	},
}

func main() {
	rootCmd.AddCommand(configCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	/*
		netDbPath := flag.String("netDb", config.DefaultNetDbConfig.Path, "Path to the netDb")
		flag.Parse()
		config.RouterConfigProperties.NetDb.Path = *netDbPath
		go signals.Handle()
		log.Debug("parsing i2p router configuration")
		log.Debug("using netDb in:", config.RouterConfigProperties.NetDb.Path)
		log.Debug("starting up i2p router")
		r, err := router.CreateRouter()
		if err == nil {
			signals.RegisterReloadHandler(func() {
				// TODO: reload config
			})
			signals.RegisterInterruptHandler(func() {
				// TODO: graceful shutdown
				r.Stop()
			})
			r.Start()
			r.Wait()
			r.Close()
		} else {
			log.Errorf("failed to create i2p router: %s", err)
		}

	*/
}
