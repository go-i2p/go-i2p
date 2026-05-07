package reseed

import (
	"net"
	"time"
)

const (
	// DefaultDialTimeout is the default timeout for reseed HTTP connection attempts.
	DefaultDialTimeout = 30 * time.Second // 30 seconds for HTTP requests
	DefaultKeepAlive   = 30 * time.Second // 30 seconds keep-alive
)

// NewReseed creates a new Reseed instance with default dial timeout, keep-alive settings,
// and a persistent HTTP client with connection pooling enabled.
func NewReseed() *Reseed {
	dialer := net.Dialer{
		Timeout:   DefaultDialTimeout,
		KeepAlive: DefaultKeepAlive,
	}

	// Create httpClient with connection pooling
	// If client creation fails (e.g., system cert pool unavailable), the Reseed
	// will still be created but will fail on actual reseed attempts.
	httpClient, err := createReseedHTTPClient(dialer.DialContext)
	if err != nil {
		log.WithError(err).Warn("Failed to create HTTP client during NewReseed; reseed operations will fail")
	}

	return &Reseed{
		Dialer:     dialer,
		httpClient: httpClient,
	}
}
