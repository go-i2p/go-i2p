package config

import "time"

// DefaultI2PControlPort is the standard I2PControl RPC port
// As defined in the I2PControl specification
const DefaultI2PControlPort = 7650

// I2PControlConfig holds configuration for the I2PControl JSON-RPC server.
// I2PControl is a monitoring and control interface for I2P routers, providing
// a standardized JSON-RPC 2.0 API for querying router statistics and status.
//
// This implementation provides a minimal monitoring server for development use,
// supporting basic statistics queries without write operations to router configuration.
type I2PControlConfig struct {
	// Enabled determines if the I2PControl server should start
	// Default: true (enabled for development and monitoring)
	Enabled bool

	// Address is the listen address for the I2PControl server
	// Format: "host:port" (e.g., "localhost:7650", "0.0.0.0:7650")
	// Default: "localhost:7650"
	// Security: Binding to 0.0.0.0 exposes the server to all network interfaces
	Address string

	// Password is used for token-based authentication
	// Clients must authenticate with this password to receive an access token
	// Default: "itoopie" (I2PControl standard default)
	// IMPORTANT: Change this in production environments!
	Password string

	// UseHTTPS enables TLS/HTTPS for encrypted communication
	// Default: false (HTTP only)
	// Recommended: true for any non-localhost deployment
	UseHTTPS bool

	// CertFile is the path to the TLS certificate file
	// Required when UseHTTPS is true
	// Format: PEM-encoded X.509 certificate
	CertFile string

	// KeyFile is the path to the TLS private key file
	// Required when UseHTTPS is true
	// Format: PEM-encoded private key
	KeyFile string

	// TokenExpiration is how long authentication tokens remain valid
	// Default: 10 minutes
	// Expired tokens must re-authenticate to get a new token
	TokenExpiration time.Duration
}

// DefaultI2PControlConfig provides sensible defaults for I2PControl server.
// These defaults prioritize development convenience:
// - Enabled by default for development and monitoring
// - Localhost-only binding (not exposed to network)
// - HTTP only (HTTPS requires explicit cert configuration)
// - Standard I2PControl port (7650)
// - Standard default password (should be changed in production)
var DefaultI2PControlConfig = I2PControlConfig{
	Enabled:         true,
	Address:         "localhost:7650",
	Password:        "itoopie",
	UseHTTPS:        false,
	CertFile:        "",
	KeyFile:         "",
	TokenExpiration: 10 * time.Minute,
}
