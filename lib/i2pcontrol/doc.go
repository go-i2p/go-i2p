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
//	  "params": {"Password": "itoopie"}
//	}
//
//	// Response
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "result": {"Token": "abc123..."}
//	}
//
// # Supported Methods
//
// The following JSON-RPC methods are planned for implementation:
//
//   - Echo: Connection test (returns input value)
//   - GetRate: Bandwidth statistics (in/out rates)
//   - RouterInfo: Router status (uptime, version, tunnels, peers)
//   - RouterManager: Control operations (shutdown only, restart not supported)
//   - NetworkSetting: Configuration queries (read-only)
//
// # Configuration
//
// The server is configured via the I2PControlConfig struct:
//
//	config := config.I2PControlConfig{
//	    Enabled:         true,
//	    Address:         "localhost:7650",
//	    Password:        "itoopie",
//	    UseHTTPS:        false,
//	    TokenExpiration: 10 * time.Minute,
//	}
//
// For production deployments, always change the default password and
// enable HTTPS with valid TLS certificates.
//
// # Security Considerations
//
//   - Default configuration binds to localhost only
//   - Passwords transmitted in plaintext over HTTP (use HTTPS in production)
//   - Tokens use cryptographic signing to prevent forgery
//   - No rate limiting implemented (single-user development focus)
//   - No audit logging of access attempts
//
// # Development Status
//
// This implementation prioritizes development convenience over production
// robustness. For production use, additional hardening is recommended:
//
//   - Enable HTTPS with valid certificates
//   - Change default password
//   - Implement rate limiting
//   - Add IP-based access control
//   - Enable audit logging
//   - Consider firewall rules for network exposure
//
// # References
//
//   - I2PControl Specification: https://geti2p.net/spec/i2pcontrol
//   - JSON-RPC 2.0 Specification: https://www.jsonrpc.org/specification
//
// # Thread Safety
//
// All public types and methods are safe for concurrent access from
// multiple goroutines.
package i2pcontrol
