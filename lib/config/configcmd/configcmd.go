// Package configcmd provides cobra subcommands for go-i2p configuration management.
package configcmd

import (
	"fmt"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var log = logger.GetGoI2PLogger()

// New returns the cobra command that prints the current router configuration.
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show current configuration",
		Run:   runConfig,
	}
}

func runConfig(cmd *cobra.Command, args []string) {
	cfg := config.GetRouterConfig()
	out := cmd.OutOrStdout()

	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		configFile = "(none; using defaults and command-line flags)"
	}
	fmt.Fprintf(out, "configuration file: %s\n", configFile)
	fmt.Fprintf(out, "base directory:     %s\n", cfg.BaseDir)
	fmt.Fprintf(out, "working directory:  %s\n", cfg.WorkingDir)
	if cfg.NetDB != nil {
		fmt.Fprintf(out, "netDb path:         %s\n", cfg.NetDB.Path)
	}
	if cfg.Bootstrap != nil {
		fmt.Fprintf(out, "bootstrap type:     %s\n", cfg.Bootstrap.BootstrapType)
		fmt.Fprintf(out, "low peer threshold: %d\n", cfg.Bootstrap.LowPeerThreshold)
		fmt.Fprintf(out, "reseed servers (%d):\n", len(cfg.Bootstrap.ReseedServers))
		for i, server := range cfg.Bootstrap.ReseedServers {
			fmt.Fprintf(out, "  [%d] %s\n", i, server.URL)
			if server.SU3Fingerprint != "" {
				fmt.Fprintf(out, "      su3 fingerprint: %s\n", server.SU3Fingerprint)
			}
		}
	}
}

// DebugPrintConfig logs the current configuration at DEBUG level.
// It is called from main when cobra returns an execution error.
func DebugPrintConfig() {
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
