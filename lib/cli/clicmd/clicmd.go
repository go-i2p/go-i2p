package clicmd

import (
	"fmt"
	"net"

	"github.com/go-i2p/i2p-control/lib"
	"github.com/go-i2p/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var log = logger.GetGoI2PLogger()

// I2PControlCmd represents the i2pcontrol command
var I2PControlCmd = &cobra.Command{
	Use:     "i2pcontrol [method] [args...]",
	Short:   "Execute I2PControl JSON-RPC method",
	Long:    "Execute a JSON-RPC method on the I2PControl interface of a running go-i2p router.",
	Example: "go-i2p i2pcontrol echo\ngo-i2p i2pcontrol router.info\ngo-i2p i2pcontrol bw.sendBps 300000",
	Args:    cobra.MinimumNArgs(1),
	RunE:    executeI2PControl,
}

// Flags
var (
	host      string
	port      string
	path      string
	password  string
	verbose   bool
	block     bool
	parseAddr bool
)

func init() {
	// Define flags with short and long options
	I2PControlCmd.Flags().StringVarP(&host, "host", "H", "", "Host of the i2pcontrol interface (default: from config)")
	I2PControlCmd.Flags().StringVarP(&port, "port", "P", "", "Port of the i2pcontrol interface (default: from config)")
	I2PControlCmd.Flags().StringVarP(&path, "path", "", "jsonrpc", "Path to the i2pcontrol interface")
	I2PControlCmd.Flags().StringVarP(&password, "password", "p", "", "Password for the i2pcontrol interface (default: from config)")
	I2PControlCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	I2PControlCmd.Flags().BoolVarP(&block, "block", "b", false, "Block until router is completely shut down")
	I2PControlCmd.Flags().BoolVar(&parseAddr, "parse-addr", false, "Parse Address from config (internal use)")
}

// executeI2PControl executes an I2PControl JSON-RPC method
func executeI2PControl(cmd *cobra.Command, args []string) error {
	// Extract method from first argument
	method := args[0]
	methodArgs := args[1:]

	// If no method args provided, use defaults (for echo, etc.)
	if len(methodArgs) == 0 {
		methodArgs = []string{"bw.sendBps", "300000"}
	}

	// Get configuration from Viper with sensible defaults
	hostVal := host
	portVal := port
	passwordVal := password

	// If flags not provided, get from Viper config
	if hostVal == "" || portVal == "" || passwordVal == "" {
		address := viper.GetString("i2pcontrol.address")
		configPassword := viper.GetString("i2pcontrol.password")

		if hostVal == "" || portVal == "" {
			if address != "" {
				// Parse address from config (format: "host:port" or "[::1]:port" for IPv6)
				// Use net.SplitHostPort to properly handle both IPv4 and IPv6 addresses
				host, port, err := net.SplitHostPort(address)
				if err == nil {
					if hostVal == "" {
						hostVal = host
					}
					if portVal == "" {
						portVal = port
					}
				}
			}
			// Fall back to defaults if still not set
			if hostVal == "" {
				hostVal = "localhost"
			}
			if portVal == "" {
				portVal = "7650"
			}
		}

		if passwordVal == "" && configPassword != "" {
			passwordVal = configPassword
		}
		if passwordVal == "" {
			passwordVal = "itoopie"
		}
	}

	log.WithFields(logger.Fields{
		"host":   hostVal,
		"port":   portVal,
		"method": method,
	}).Debug("Executing I2PControl method")

	// Create client configuration
	clientConfig := lib.Config{
		Host:     hostVal,
		Port:     portVal,
		Path:     path,
		Password: passwordVal,
		Verbose:  verbose,
	}

	// Create and connect client
	client := lib.New(clientConfig)
	if err := client.Connect(); err != nil {
		return fmt.Errorf("failed to connect to i2pcontrol server: %w", err)
	}

	// Execute command
	result := client.Execute(method, lib.CommandOptions{
		Block: block,
		Args:  methodArgs,
	})

	if !result.Success {
		return fmt.Errorf("i2pcontrol command failed: %s", result.Error)
	}

	if result.Output != "" {
		fmt.Println(result.Output)
	}

	// Handle shutdown if needed
	if result.IsShutdown && result.WaitShutdown {
		if _, err := client.WaitForShutdown(); err != nil {
			return fmt.Errorf("error waiting for shutdown: %w", err)
		}
	}

	return nil
}
