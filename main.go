package main

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/embedded"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/go-i2p/lib/util/signals"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	embeddedRouter *embedded.StandardEmbeddedRouter
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
	// Register the certificate provider with the reseed package to break the import cycle.
	// This allows reseed to access embedded certificates without importing embedded directly.
	reseed.SetCertificateProvider(func() (fs.FS, error) {
		return embedded.GetReseedCertificates()
	})

	cobra.OnInitialize(config.InitConfig)
	registerGlobalFlags()
	registerRouterFlags()
	registerNetDbFlags()
	registerBootstrapFlags()
	registerI2CPFlags()
	bindFlagsToViper()
}

// registerGlobalFlags registers global command-line flags for the application.
func registerGlobalFlags() {
	RootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "", "config file (default is $HOME/.go-i2p/config.yaml)")
}

// registerRouterFlags registers router-specific configuration flags.
func registerRouterFlags() {
	RootCmd.PersistentFlags().String("base-dir", config.DefaultRouterConfig().BaseDir, "Base directory for I2P router")
	RootCmd.PersistentFlags().String("working-dir", config.DefaultRouterConfig().WorkingDir, "Working directory for I2P router")
}

// registerNetDbFlags registers NetDb configuration flags.
func registerNetDbFlags() {
	RootCmd.PersistentFlags().String("netdb.path", config.DefaultNetDbConfig.Path, "Path to the netDb")
}

// registerBootstrapFlags registers bootstrap configuration flags.
func registerBootstrapFlags() {
	RootCmd.PersistentFlags().Int("bootstrap.low-peer-threshold", config.DefaultBootstrapConfig.LowPeerThreshold,
		"Minimum number of peers before reseeding")
	RootCmd.PersistentFlags().String("bootstrap.type", config.DefaultBootstrapConfig.BootstrapType,
		"Bootstrap type: auto (tries all methods), file (local file only), reseed (remote only), local (netDb only)")
	RootCmd.PersistentFlags().String("bootstrap.reseed-file", "",
		"Path to local reseed file (zip or su3) - takes priority over remote reseed servers")
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
		"Maximum number of concurrent I2CP sessions")
}

// bindFlagsToViper binds all command-line flags to viper configuration keys.
func bindFlagsToViper() {
	bindRouterFlagsToViper()
	bindNetDbFlagsToViper()
	bindBootstrapFlagsToViper()
	bindI2CPFlagsToViper()
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
}

// bindNetDbFlagsToViper binds NetDb flags to viper configuration.
func bindNetDbFlagsToViper() {
	if err := viper.BindPFlag("netdb.path", RootCmd.PersistentFlags().Lookup("netdb.path")); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "bindNetDbFlagsToViper",
			"phase":  "startup",
			"reason": "failed to bind netdb.path configuration flag",
			"flag":   "netdb.path",
		}).Fatal("failed to bind netdb.path flag")
	}
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
}

// configCmd shows current configuration
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
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
			"base_dir":    config.RouterConfigProperties.BaseDir,
			"working_dir": config.RouterConfigProperties.WorkingDir,
		}).Info("router configuration")

		log.WithFields(logger.Fields{
			"at":         "configCmd",
			"phase":      "startup",
			"reason":     "netdb configuration loaded",
			"netdb_path": config.RouterConfigProperties.NetDb.Path,
		}).Info("netDb configuration")

		log.WithFields(logger.Fields{
			"at":                 "configCmd",
			"phase":              "startup",
			"reason":             "bootstrap configuration loaded",
			"low_peer_threshold": config.RouterConfigProperties.Bootstrap.LowPeerThreshold,
			"bootstrap_type":     config.RouterConfigProperties.Bootstrap.BootstrapType,
		}).Info("bootstrap configuration")

		log.WithFields(logger.Fields{
			"at":     "configCmd",
			"phase":  "startup",
			"reason": "displaying reseed servers",
			"count":  len(config.RouterConfigProperties.Bootstrap.ReseedServers),
		}).Info("reseed servers:")
		for i, server := range config.RouterConfigProperties.Bootstrap.ReseedServers {
			log.WithFields(logger.Fields{
				"at":              "configCmd",
				"phase":           "startup",
				"reason":          "reseed server configured",
				"index":           i,
				"url":             server.Url,
				"su3_fingerprint": server.SU3Fingerprint,
			}).Info("  reseed server")
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
	var err error
	embeddedRouter, err = embedded.NewStandardEmbeddedRouter(config.RouterConfigProperties)
	if err != nil {
		return fmt.Errorf("failed to create embedded router: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "startup",
		"step":   4,
		"reason": "embedded router created successfully",
	}).Info("embedded router instance created")

	if err := embeddedRouter.Configure(config.RouterConfigProperties); err != nil {
		return fmt.Errorf("failed to configure router: %w", err)
	}
	return nil
}

// registerSignalHandlers sets up reload and interrupt handlers for the router.
func registerSignalHandlers() {
	signals.RegisterReloadHandler(func() {
		if err := viper.ReadInConfig(); err != nil {
			log.Errorf("failed to reload config: %s", err)
			return
		}
		config.UpdateRouterConfig()
	})

	signals.RegisterInterruptHandler(func() {
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

	if err := embeddedRouter.Start(); err != nil {
		return fmt.Errorf("failed to start router: %w", err)
	}

	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "running",
		"reason": "router running, waiting for shutdown",
	}).Info("embedded router started, entering main loop")

	embeddedRouter.Wait()
	return nil
}

// closeRouter performs final cleanup and closes the embedded router.
func closeRouter() error {
	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "shutdown",
		"reason": "router shutdown complete, cleaning up",
	}).Info("closing embedded router")

	if err := embeddedRouter.Close(); err != nil {
		return fmt.Errorf("failed to close router: %w", err)
	}
	return nil
}

func runRouter() {
	go signals.Handle()

	log.WithFields(logger.Fields{
		"at":          "runRouter",
		"phase":       "startup",
		"step":        1,
		"reason":      "parsing router configuration",
		"config_file": viper.ConfigFileUsed(),
		"config_used": viper.ConfigFileUsed() != "",
	}).Info("parsing i2p router configuration")

	logConfigurationSource()

	log.WithFields(logger.Fields{
		"at":         "runRouter",
		"phase":      "startup",
		"step":       2,
		"reason":     "netdb path configured",
		"netdb_path": config.RouterConfigProperties.NetDb.Path,
		"source":     "configuration",
	}).Info("using netDb path: " + config.RouterConfigProperties.NetDb.Path)

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

	log.WithFields(logger.Fields{
		"at":     "runRouter",
		"phase":  "startup",
		"step":   4,
		"reason": "initiating router creation",
	}).Debug("starting up i2p router")

	if err := manageRouterLifecycle(); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":         "runRouter",
			"phase":      "startup",
			"reason":     "router creation failed",
			"error_type": fmt.Sprintf("%T", err),
			"config":     config.RouterConfigProperties != nil,
			"suggestion": "check configuration values and system resources",
		}).Errorf("failed to create i2p router: %s", err)
		os.Exit(1)
	}
}

func main() {
	RootCmd.AddCommand(configCmd)
	if err := RootCmd.Execute(); err != nil {
		log.Error(err)
		debugPrintConfig()
		os.Exit(1)
	}
}
