package main

import (
	"os"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/router"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	routerInstance *router.Router
	log            = logger.GetGoI2PLogger()
)

var RootCmd = &cobra.Command{
	Use:   "go-i2p",
	Short: "I2P Router implementation in Go",
	Run: func(cmd *cobra.Command, args []string) {
		runRouter()
	},
}

func init() {
	cobra.OnInitialize(config.InitConfig)

	// Global flags
	RootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "", "config file (default is $HOME/.go-i2p/config.yaml)")

	// Router configuration flags
	RootCmd.PersistentFlags().String("base-dir", config.DefaultRouterConfig().BaseDir, "Base directory for I2P router")
	RootCmd.PersistentFlags().String("working-dir", config.DefaultRouterConfig().WorkingDir, "Working directory for I2P router")

	// NetDb flags
	RootCmd.PersistentFlags().String("netdb.path", config.DefaultNetDbConfig.Path, "Path to the netDb")

	// Bootstrap flags
	RootCmd.PersistentFlags().Int("bootstrap.low-peer-threshold", config.DefaultBootstrapConfig.LowPeerThreshold,
		"Minimum number of peers before reseeding")

	// Bind flags to viper
	viper.BindPFlag("base_dir", RootCmd.PersistentFlags().Lookup("base-dir"))
	viper.BindPFlag("working_dir", RootCmd.PersistentFlags().Lookup("working-dir"))
	viper.BindPFlag("netdb.path", RootCmd.PersistentFlags().Lookup("netdb.path"))
	viper.BindPFlag("bootstrap.low_peer_threshold", RootCmd.PersistentFlags().Lookup("bootstrap.low-peer-threshold"))
}

// configCmd shows current configuration
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		log.WithField("config_file", viper.ConfigFileUsed()).Info("Configuration file")

		log.WithFields(logger.Fields{
			"base_dir":    config.RouterConfigProperties.BaseDir,
			"working_dir": config.RouterConfigProperties.WorkingDir,
		}).Info("Router configuration")

		log.WithField("netdb_path", config.RouterConfigProperties.NetDb.Path).Info("NetDb configuration")

		log.WithField("low_peer_threshold", config.RouterConfigProperties.Bootstrap.LowPeerThreshold).Info("Bootstrap configuration")

		log.Info("Reseed servers:")
		for _, server := range config.RouterConfigProperties.Bootstrap.ReseedServers {
			log.WithFields(logger.Fields{
				"url":             server.Url,
				"su3_fingerprint": server.SU3Fingerprint,
			}).Info("  Reseed server")
		}
	},
}

func debugPrintConfig() {
	currentConfig := struct {
		BaseDir    string                 `yaml:"base_dir"`
		WorkingDir string                 `yaml:"working_dir"`
		NetDB      config.NetDbConfig     `yaml:"netdb"`
		Bootstrap  config.BootstrapConfig `yaml:"bootstrap"`
	}{
		BaseDir:    config.RouterConfigProperties.BaseDir,
		WorkingDir: config.RouterConfigProperties.WorkingDir,
		NetDB:      *config.RouterConfigProperties.NetDb,
		Bootstrap:  *config.RouterConfigProperties.Bootstrap,
	}

	yamlData, err := yaml.Marshal(currentConfig)
	if err != nil {
		log.Errorf("Error marshaling config for debug: %s", err)
		return
	}

	log.Debugf("Current configuration:\n%s", string(yamlData))
}

func runRouter() {
	go signals.Handle()

	log.Debug("parsing i2p router configuration")
	log.Debug("using netDb in:", config.RouterConfigProperties.NetDb.Path)
	log.Debug("starting up i2p router")

	var err error
	routerInstance, err = router.CreateRouter(config.RouterConfigProperties)
	if err == nil {
		signals.RegisterReloadHandler(func() {
			if err := viper.ReadInConfig(); err != nil {
				log.Errorf("failed to reload config: %s", err)
				return
			}
			config.UpdateRouterConfig()
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

func main() {
	RootCmd.AddCommand(configCmd)
	if err := RootCmd.Execute(); err != nil {
		log.Error(err)
		debugPrintConfig()
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
