// Package i2pcontrol implements an I2PControl server for go-i2p routers.
//
// I2PControl is a control protocol that lets other programs talk to a
// running router over the network. You can use it to check how the router
// is doing, read statistics, or ask it to do things such as shut down.
//
// # What is I2PControl?
//
// Think of I2PControl as a small, private dashboard for your router. It
// listens on a local port (by default, localhost:7650) and answers questions
// from other programs using a simple request/response format called
// JSON-RPC 2.0.
//
// JSON-RPC 2.0 is a way to send a function call as a JSON message. A client
// sends a message that names a method and its arguments; the server runs the
// method and sends back a JSON result. This package speaks that format.
//
// The protocol was designed for the Java I2P implementation. This package
// provides a focused implementation of the most useful operations for
// monitoring and controlling a router.
//
// See [I2P Spec: I2PControl](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2cp.rst)
// for the full protocol definition.
//
// # How it works
//
// The server has three moving parts:
//
//   - A method registry that maps method names (such as "RouterInfo") to the
//     code that handles them.
//   - An authentication manager that issues short-lived tokens.
//   - An HTTP or HTTPS listener that accepts JSON-RPC requests.
//
// Every request except "Authenticate" must carry a valid token, so a client
// first authenticates with the configured password and then reuses the
// returned token for later calls.
//
// # Authentication
//
// Authentication is password-based and token-based in two steps:
//
//  1. The client sends an "Authenticate" call with the configured password.
//  2. The server replies with a token signed using HMAC-SHA256 (a way to
//     prove the token came from the server without sharing the password).
//  3. The token stays valid for a configurable time (10 minutes by default).
//  4. The client includes the token in every later request.
//
// # Methods
//
// The server implements these JSON-RPC methods:
//
//   - Authenticate: exchange the password for a token.
//   - Echo: send a value back unchanged; useful for testing the connection.
//   - GetRate: read inbound and outbound bandwidth.
//   - RouterInfo: read router status such as uptime, version, and peer counts.
//   - RouterManager: control operations such as shutdown.
//   - NetworkSetting: read network configuration values.
//   - I2PControl: manage server settings such as the password.
//
// # Available metrics
//
// The RouterInfo method supports these metrics:
//
//   - i2p.router.uptime: router uptime in milliseconds.
//   - i2p.router.version: router version string.
//   - i2p.router.net.tunnels.participating: number of participating tunnels.
//   - i2p.router.netdb.knownpeers: number of known routers in the NetDB
//     (the router's database of other routers on the network).
//   - i2p.router.netdb.activepeers: number of active peers.
//   - i2p.router.netdb.fastpeers: number of fast peers.
//
// The GetRate method supports these metrics:
//
//   - i2p.router.net.bw.inbound.15s: inbound bandwidth (bytes/sec, 15s avg).
//   - i2p.router.net.bw.outbound.15s: outbound bandwidth (bytes/sec, 15s avg).
//
// # Usage
//
// Enable I2PControl in your config.yaml:
//
//	i2pcontrol:
//	  enabled: true
//	  address: "localhost:7650"
//	  password: "your-secure-password"
//
// The server starts automatically when the router starts. To call a method,
// POST a JSON-RPC message to the /jsonrpc endpoint:
//
//	curl -X POST http://localhost:7650/jsonrpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","id":1,"method":"Authenticate","params":{"API":1,"Password":"itoopie"}}'
//
// # Configuration
//
// The server is configured through the I2PControlConfig struct in
// [lib/config](https://pkg.go.dev/github.com/go-i2p/go-i2p/lib/config):
//
//	type I2PControlConfig struct {
//	    Enabled         bool          // Enable the I2PControl server.
//	    Address         string        // Listen address (default "localhost:7650").
//	    Password        string        // Authentication password (default "itoopie").
//	    UseHTTPS        bool          // Enable HTTPS/TLS.
//	    CertFile        string        // TLS certificate path (if UseHTTPS).
//	    KeyFile         string        // TLS key path (if UseHTTPS).
//	    TokenExpiration time.Duration // Token validity (default 10 minutes).
//	}
//
// Configuration can be set via a config.yaml file, command-line flags
// (such as --i2pcontrol.enabled), or environment variables.
//
// # Error codes
//
// The server returns standard JSON-RPC 2.0 error codes, plus a few
// application-specific ones:
//
//   - -32700: parse error (invalid JSON).
//   - -32600: invalid request (malformed JSON-RPC).
//   - -32601: method not found.
//   - -32602: invalid params.
//   - -32603: internal error.
//   - -32000: authentication required (missing or invalid token).
//   - -32001: authentication failed (wrong password).
//   - -32002: not implemented (method planned but not yet available).
//
// # Security
//
// The defaults are tuned for local development, not for public networks: the
// server binds to localhost, uses plain HTTP, and ships with a default
// password. Before exposing it beyond your machine, change the password,
// enable HTTPS, and restrict access with a firewall.
//
// # Thread safety
//
// All public types and methods are safe for concurrent use from multiple
// goroutines. The Server is immutable after construction; the AuthManager
// and MethodRegistry guard their state with read/write mutexes.
//
// # See also
//
//   - [docs/i2pcontrol.md](https://github.com/go-i2p/go-i2p/blob/main/docs/i2pcontrol.md)
//     for a full user guide with worked examples.
//   - [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification).
package i2pcontrol
