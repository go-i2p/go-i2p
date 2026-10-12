// Command go-i2p runs a pure Go implementation of the I2P router.
//
// # What is I2P?
//
// I2P (the Invisible Internet Project) is a private network that runs on top
// of the regular internet. Data is sent through a series of relays (routers)
// so that a sender and a receiver can talk to each other without revealing
// their real network addresses. This program is one such router: it joins the
// I2P network and helps route traffic for itself and for other routers.
//
// # What this command does
//
// Running the command with no arguments starts the router. On startup it:
//
//  1. Loads configuration from a config file and command-line flags.
//  2. Builds the router and starts its subsystems (transports, tunnels,
//     network database, and more).
//  3. Runs until it receives a stop signal (Ctrl+C or SIGTERM), then shuts
//     down gracefully.
//
// # Subcommands
//
//   - go-i2p config — print the current effective configuration.
//   - go-i2p tui — launch a terminal user interface for the router.
//
// # Usage
//
//	# Start the router.
//	go-i2p
//
//	# Show the current configuration.
//	go-i2p config
//
// # See also
//
// The router's subsystems live under the lib/ directory. The embedded router
// that this command starts is in [github.com/go-i2p/go-i2p/lib/embedded].
package main
