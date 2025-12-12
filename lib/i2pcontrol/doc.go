// Package i2pcontrol implements a JSON-RPC 2.0 server for monitoring and
// controlling go-i2p routers. It provides a standardized interface for
// querying router statistics, network status, and operational metrics.
//
// # Overview
//
// I2PControl is a monitoring protocol originally designed for the Java I2P
// implementation. This package provides a minimal, development-focused
// implementation supporting read-only operations for router monitoring.
//
// # Features
//
//   - JSON-RPC 2.0 compliant API
//   - Token-based authentication with HMAC-SHA256
//   - HTTP and HTTPS transport
//   - Thread-safe concurrent access
//   - No external dependencies beyond stdlib
//
// # Quick Start
//
// Enable I2PControl in your config.yaml:
//
//	i2pcontrol:
//	  enabled: true
//	  address: "localhost:7650"
//	  password: "your-secure-password"
//	  use_https: false
//	  token_expiration: 10m
//
// Or use command-line flags:
//
//	./go-i2p --i2pcontrol.enabled=true --i2pcontrol.password="your-password"
//
// The server integrates automatically with the router lifecycle and starts
// when the router starts (if enabled).
//
// # Usage Example
//
// Programmatic usage:
//
//	import (
//	    "github.com/go-i2p/go-i2p/lib/config"
//	    "github.com/go-i2p/go-i2p/lib/i2pcontrol"
//	    "time"
//	)
//
//	// Create configuration
//	cfg := &config.I2PControlConfig{
//	    Enabled:         true,
//	    Address:         "localhost:7650",
//	    Password:        "my-password",
//	    UseHTTPS:        false,
//	    TokenExpiration: 10 * time.Minute,
//	}
//
//	// Create statistics provider (typically your Router instance)
//	stats := i2pcontrol.NewRouterStatsProvider(router, "0.1.0-go")
//
//	// Create and start server
//	server, err := i2pcontrol.NewServer(cfg, stats)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := server.Start(); err != nil {
//	    log.Fatal(err)
//	}
//	defer server.Stop()
//
// # Authentication
//
// Authentication uses a simple password-based token system:
//
//  1. Client authenticates with configured password
//  2. Server generates HMAC-SHA256 signed token
//  3. Token valid for configurable duration (default 10 minutes)
//  4. Client includes token in subsequent RPC requests
//
// Example authentication flow:
//
//	// Request
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "method": "Authenticate",
//	  "params": {"API": 1, "Password": "itoopie"}
//	}
//
//	// Response
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "result": {"API": 1, "Token": "abc123..."}
//	}
//
// # API Methods
//
// Authenticate - Generate authentication token:
//
//	curl -X POST http://localhost:7650/jsonrpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","id":1,"method":"Authenticate",
//	       "params":{"API":1,"Password":"itoopie"}}'
//
// Echo - Test connectivity (returns {"Result": value}):
//
//	curl -X POST http://localhost:7650/jsonrpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","id":2,"method":"Echo",
//	       "params":{"Token":"abc123","Echo":"test"}}'
//	# Response: {"jsonrpc":"2.0","id":2,"result":{"Result":"test"}}
//
// RouterInfo - Query router status:
//
//	curl -X POST http://localhost:7650/jsonrpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","id":3,"method":"RouterInfo",
//	       "params":{"Token":"abc123",
//	                 "i2p.router.uptime":null,
//	                 "i2p.router.version":null,
//	                 "i2p.router.net.tunnels.participating":null,
//	                 "i2p.router.netdb.knownpeers":null}}'
//
// GetRate - Query bandwidth statistics:
//
//	curl -X POST http://localhost:7650/jsonrpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","id":4,"method":"GetRate",
//	       "params":{"Token":"abc123",
//	                 "i2p.router.net.bw.inbound.15s":null,
//	                 "i2p.router.net.bw.outbound.15s":null}}'
//
// # Supported Methods
//
// The following JSON-RPC methods are implemented:
//
//   - Authenticate: Generate authentication token (no token required)
//   - Echo: Connection test (returns input value)
//   - GetRate: Bandwidth statistics (in/out rates)
//   - RouterInfo: Router status (uptime, version, tunnels, peers)
//
// Planned for future implementation:
//
//   - RouterManager: Control operations (shutdown, restart)
//   - NetworkSetting: Configuration queries and updates
//
// # Available Router Metrics
//
// RouterInfo method supports these metrics:
//
//   - i2p.router.uptime: Router uptime in milliseconds
//   - i2p.router.version: Router version string
//   - i2p.router.net.tunnels.participating: Number of participating tunnels
//   - i2p.router.netdb.knownpeers: Number of known routers in NetDB
//   - i2p.router.netdb.activepeers: Number of active peers
//   - i2p.router.netdb.fastpeers: Number of fast peers
//
// GetRate method supports these metrics:
//
//   - i2p.router.net.bw.inbound.15s: Inbound bandwidth (bytes/sec, 15s avg)
//   - i2p.router.net.bw.outbound.15s: Outbound bandwidth (bytes/sec, 15s avg)
//
// # Configuration
//
// The server is configured via the I2PControlConfig struct in lib/config:
//
//	type I2PControlConfig struct {
//	    Enabled         bool          // Enable I2PControl server
//	    Address         string        // Listen address (default: "localhost:7650")
//	    Password        string        // Authentication password (default: "itoopie")
//	    UseHTTPS        bool          // Enable HTTPS/TLS (default: false)
//	    CertFile        string        // TLS certificate path (if UseHTTPS)
//	    KeyFile         string        // TLS key path (if UseHTTPS)
//	    TokenExpiration time.Duration // Token validity (default: 10 minutes)
//	}
//
// Configuration can be set via:
//   - config.yaml file
//   - Command-line flags (--i2pcontrol.enabled, --i2pcontrol.address, etc.)
//   - Environment variables (via Viper)
//
// # Error Codes
//
// JSON-RPC 2.0 error codes:
//
//   - -32700: Parse error (invalid JSON)
//   - -32600: Invalid Request (malformed JSON-RPC)
//   - -32601: Method not found
//   - -32602: Invalid params
//   - -32603: Internal error
//   - -32000: Authentication required (missing/invalid token)
//   - -32001: Authentication failed (wrong password)
//   - -32002: Not implemented (method planned but not yet available)
//
// # Security Considerations
//
// Default configuration (development-focused):
//   - Binds to localhost only (not exposed to network)
//   - HTTP only (no encryption)
//   - Standard default password "itoopie"
//   - 10-minute token expiration
//   - No rate limiting
//   - No audit logging
//
// Production recommendations:
//   - Change default password to strong, unique value
//   - Enable HTTPS with valid TLS certificates
//   - Use specific IP binding or firewall rules
//   - Monitor logs for suspicious activity
//   - Keep token expiration short (5-15 minutes)
//   - Never expose HTTP endpoint to untrusted networks
//
// Example HTTPS configuration:
//
//	i2pcontrol:
//	  enabled: true
//	  address: "0.0.0.0:7650"  # Network accessible
//	  password: "strong-unique-password"
//	  use_https: true
//	  cert_file: "/etc/ssl/certs/i2pcontrol.pem"
//	  key_file: "/etc/ssl/private/i2pcontrol-key.pem"
//	  token_expiration: 5m
//
// Generate self-signed certificate (testing only):
//
//	openssl req -x509 -newkey rsa:4096 -keyout key.pem \
//	  -out cert.pem -days 365 -nodes -subj "/CN=localhost"
//
// # Testing
//
// Run unit tests:
//
//	go test ./lib/i2pcontrol/...
//
// Run with coverage:
//
//	go test -cover ./lib/i2pcontrol
//
// Run with race detector:
//
//	go test -race ./lib/i2pcontrol
//
// Run benchmarks:
//
//	go test -bench=. -benchmem ./lib/i2pcontrol
//
// # Development Status
//
// This implementation prioritizes development convenience over production
// robustness. Current status:
//
//   - ✅ JSON-RPC 2.0 compliance
//   - ✅ Token authentication
//   - ✅ HTTP/HTTPS transport
//   - ✅ Echo, GetRate, RouterInfo methods
//   - ✅ Thread-safe concurrent access
//   - ✅ Graceful shutdown
//   - ✅ 87%+ test coverage
//   - ⚠️  No rate limiting
//   - ⚠️  No audit logging
//   - 🚧 RouterManager method (planned)
//   - 🚧 NetworkSetting method (planned)
//
// # References
//
//   - I2PControl Specification: https://geti2p.net/spec/i2pcontrol
//   - JSON-RPC 2.0 Specification: https://www.jsonrpc.org/specification
//   - User Guide: docs/i2pcontrol.md
//
// # Thread Safety
//
// All public types and methods are safe for concurrent access from multiple
// goroutines:
//
//   - **Server**: Immutable after construction (fields set only in NewServer and never modified). Uses sync.WaitGroup for shutdown coordination.
//   - **AuthManager**: Protected by sync.RWMutex for token management.
//   - **MethodRegistry**: Protected by sync.RWMutex for handler registration/lookup.
//   - **RouterStatsProvider**: Interface implementations must be thread-safe.
package i2pcontrol
