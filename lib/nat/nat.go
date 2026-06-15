package nat

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	nattraversal "github.com/go-i2p/go-nat-listener"
	"github.com/samber/oops"
)

// NATAddr is a re-export of nattraversal.NATAddr for architectural consistency.
// This allows transport packages to use nat.NATAddr without directly importing
// the go-nat-listener package, centralizing all NAT-related types.
type NATAddr = nattraversal.NATAddr

// BindConfig contains all parameters for NAT-aware binding.
type BindConfig struct {
	// Network type ("tcp", "udp", "tcp4", "udp6", etc.)
	Network string

	// ListenerAddress is the host:port to bind (":9002", "127.0.0.1:42069", etc.)
	// Empty host means wildcard binding ("::" or "0.0.0.0" depending on network).
	ListenerAddress string

	// RequestedPort specifies the port to bind. If 0, an OS-assigned port is probed
	// and then rebound with NAT traversal (see ProbeAndBindWithNATTraversal).
	RequestedPort int

	// NATTimeout is the maximum time to wait for UPnP/NAT-PMP discovery and mapping.
	// Default: 3 seconds. Loopback addresses bypass NAT traversal regardless of timeout.
	NATTimeout time.Duration

	// MaxRetries is the number of TOCTOU retry attempts when binding OS-assigned port.
	// Only used by ProbeAndBindWithNATTraversal. Default: 5.
	MaxRetries int

	// RetryBaseDelay is the base delay between TOCTOU retries, before jitter.
	// Jitter: ±25% using crypto/rand. Default: 50ms.
	RetryBaseDelay time.Duration
}

// DefaultBindConfig returns a BindConfig with sensible defaults.
func DefaultBindConfig(network, listenerAddress string) *BindConfig {
	return &BindConfig{
		Network:         network,
		ListenerAddress: listenerAddress,
		NATTimeout:      3 * time.Second,
		MaxRetries:      5,
		RetryBaseDelay:  50 * time.Millisecond,
	}
}

// BindResult contains the result of a successful bind operation.
type BindResult struct {
	// Listener is the bound TCP listener (non-nil for "tcp" network).
	// Exactly one of Listener or PacketConn will be non-nil.
	Listener net.Listener

	// PacketConn is the bound UDP connection (non-nil for "udp" network).
	// Exactly one of Listener or PacketConn will be non-nil.
	PacketConn net.PacketConn

	// BoundAddress is the actual local address string (e.g., "192.168.1.5:9002").
	// For NAT-traversed bindings, this may contain the external IP discovered via
	// UPnP/NAT-PMP. Callers should use this value for config updates (R-2/P-2 pattern).
	BoundAddress string
}

// BindWithNATTraversal binds the specified port with NAT traversal.
//
// Loopback addresses (127.x.x.x, ::1, "localhost") bypass NAT traversal entirely.
// For all other addresses, UPnP/NAT-PMP discovery runs with cfg.NATTimeout,
// then falls back to plain bind if NAT mapping fails.
//
// SO_REUSEADDR is set on the socket to allow immediate rebind after probe close
// (reduces TOCTOU window in ProbeAndBindWithNATTraversal).
//
// Returns:
//   - BindResult with bound listener/connection and local/external address
//   - Error if bind fails
//
// Thread-safe: Multiple goroutines may call concurrently.
func BindWithNATTraversal(cfg *BindConfig) (*BindResult, error) {
	// Parse host from ListenerAddress
	host, _, err := net.SplitHostPort(cfg.ListenerAddress)
	if err != nil {
		// If parsing fails, try to determine if it's just a port (":8080")
		if strings.HasPrefix(cfg.ListenerAddress, ":") {
			host = "" // Wildcard binding
		} else {
			return nil, oops.Wrapf(err, "invalid listener address: %s", cfg.ListenerAddress)
		}
	}

	// Determine if network is TCP or UDP
	isTCP := strings.HasPrefix(strings.ToLower(cfg.Network), "tcp")
	isUDP := strings.HasPrefix(strings.ToLower(cfg.Network), "udp")
	if !isTCP && !isUDP {
		return nil, oops.Errorf("unsupported network type: %s (must be tcp or udp)", cfg.Network)
	}

	// Check if address is loopback
	if IsLoopbackAddress(host) {
		// Loopback — bind without NAT traversal
		listenCfg := net.ListenConfig{
			Control: createReuseAddrControl("loopback listener"),
		}

		// Reconstruct the bind address, adding brackets for IPv6 addresses
		bindAddr := cfg.ListenerAddress
		if cfg.RequestedPort != 0 {
			// If RequestedPort is set, use it instead of the port from ListenerAddress
			if strings.Contains(host, ":") {
				// IPv6 address - add brackets
				bindAddr = fmt.Sprintf("[%s]:%d", host, cfg.RequestedPort)
			} else {
				bindAddr = fmt.Sprintf("%s:%d", host, cfg.RequestedPort)
			}
		}

		if isTCP {
			listener, err := listenCfg.Listen(context.Background(), cfg.Network, bindAddr)
			if err != nil {
				return nil, oops.Wrapf(err, "failed to create TCP listener on %s", bindAddr)
			}
			return &BindResult{
				Listener:     listener,
				BoundAddress: listener.Addr().String(),
			}, nil
		} else {
			conn, err := listenCfg.ListenPacket(context.Background(), cfg.Network, bindAddr)
			if err != nil {
				return nil, oops.Wrapf(err, "failed to create UDP listener on %s", bindAddr)
			}
			return &BindResult{
				PacketConn:   conn,
				BoundAddress: conn.LocalAddr().String(),
			}, nil
		}
	}

	// Non-loopback — attempt NAT traversal with timeout
	natCtx, natCancel := context.WithTimeout(context.Background(), cfg.NATTimeout)
	defer natCancel()

	if isTCP {
		listener, err := nattraversal.ListenWithFallbackContext(natCtx, cfg.RequestedPort)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to create TCP listener with NAT traversal")
		}
		return &BindResult{
			Listener:     listener,
			BoundAddress: listener.Addr().String(),
		}, nil
	} else {
		natPL, err := nattraversal.ListenPacketWithFallbackContext(natCtx, cfg.RequestedPort)
		if err != nil {
			return nil, oops.Wrapf(err, "failed to create UDP listener with NAT traversal")
		}
		return &BindResult{
			PacketConn:   natPL.PacketConn(),
			BoundAddress: natPL.Addr().String(),
		}, nil
	}
}

// extractHostFromListenerAddress parses and returns the host from ListenerAddress.
// Handles formats like ":8080" (wildcard), "127.0.0.1:8080", and "[::1]:8080".
// Complexity: O(n) string operations only.
func extractHostFromListenerAddress(listenerAddress string) (string, error) {
	host, _, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		// If parsing fails, check if it's just a port (":8080")
		if strings.HasPrefix(listenerAddress, ":") {
			return "", nil // Wildcard
		}
		return "", oops.Wrapf(err, "invalid listener address: %s", listenerAddress)
	}
	return host, nil
}

// constructProbeAddress builds a probe address with port 0 from a host.
// Handles IPv6 formatting ([::1]:0), IPv4 (127.0.0.1:0), and wildcard (:0).
// Complexity: O(n) string operations only.
func constructProbeAddress(host string) string {
	if strings.Contains(host, ":") {
		// IPv6: wrap in brackets
		return fmt.Sprintf("[%s]:0", host)
	}
	// IPv4 or wildcard
	return fmt.Sprintf("%s:0", host)
}

// probePort discovers an OS-assigned free port for the given network type.
// Returns the assigned port or error if probe fails.
// Reduces complexity: isolates TCP/UDP branching logic. Cyclomatic: 2.
func probePort(cfg *BindConfig) (int, error) {
	isTCP := strings.HasPrefix(strings.ToLower(cfg.Network), "tcp")

	listenCfg := net.ListenConfig{
		Control: createReuseAddrControl("probe listener"),
	}

	probeAddr := constructProbeAddress("")
	// Re-construct with actual host
	host, err := extractHostFromListenerAddress(cfg.ListenerAddress)
	if err != nil {
		return 0, err
	}
	probeAddr = constructProbeAddress(host)

	if isTCP {
		temp, err := listenCfg.Listen(context.Background(), cfg.Network, probeAddr)
		if err != nil {
			return 0, oops.Wrapf(err, "failed to probe available port")
		}
		port := temp.Addr().(*net.TCPAddr).Port
		if closeErr := temp.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("failed to close probe TCP listener")
		}
		return port, nil
	}

	// UDP
	temp, err := listenCfg.ListenPacket(context.Background(), cfg.Network, probeAddr)
	if err != nil {
		return 0, oops.Wrapf(err, "failed to probe available UDP port")
	}
	port := temp.LocalAddr().(*net.UDPAddr).Port
	if closeErr := temp.Close(); closeErr != nil {
		log.WithError(closeErr).Warn("failed to close probe UDP listener")
	}
	return port, nil
}

// isTOCTOURace checks if an error is due to a TOCTOU race (address already in use).
// Complexity: O(n) string search only.
func isTOCTOURace(err error) bool {
	errMsg := err.Error()
	return strings.Contains(errMsg, "address already in use") || strings.Contains(errMsg, "Address already in use")
}

// rebindWithRetry attempts to rebind with BindWithNATTraversal after probing a port,
// with retry-on-TOCTOU-race logic. Isolated complexity: ~6 (one loop, one condition, one sleep).
func rebindWithRetry(cfg *BindConfig, assignedPort int) (*BindResult, error) {
	for attempt := 0; attempt < cfg.MaxRetries; attempt++ {
		rebindCfg := *cfg
		rebindCfg.RequestedPort = assignedPort

		result, err := BindWithNATTraversal(&rebindCfg)
		if err == nil {
			return result, nil
		}

		// If not a TOCTOU race, fail immediately
		if !isTOCTOURace(err) {
			return nil, err
		}

		// Retry with jitter if not last attempt
		if attempt < cfg.MaxRetries-1 {
			log.WithFields(map[string]interface{}{
				"port":    assignedPort,
				"attempt": attempt + 1,
				"error":   err,
			}).Warn("TOCTOU race: probed port claimed by another process; retrying")

			jitteredDelay := applyJitter(cfg.RetryBaseDelay)
			time.Sleep(jitteredDelay)
		} else {
			// Last attempt
			return nil, oops.Wrapf(err, "failed to rebind after %d attempts (TOCTOU race)", cfg.MaxRetries)
		}
	}

	return nil, oops.New("unexpected: rebindWithRetry exhausted without error")
}

// ProbeAndBindWithNATTraversal discovers an OS-assigned free port, then rebinds
// it with NAT traversal (UPnP/NAT-PMP with fallback to plain bind).
//
// This function implements the P-1 TOCTOU mitigation: probe port → close → rebind
// with SO_REUSEADDR and retry-with-jitter on "address already in use".
//
// Network type must be "tcp", "udp", or variants ("tcp4", "udp6", etc.).
//
// Returns:
//   - BindResult with bound listener/connection and external address
//   - Error if all retries exhausted or non-recoverable error encountered
//
// Thread-safe: Multiple goroutines may call concurrently (each probes independently).
// Refactored for H-11: complexity reduced from ~15 to ~5 via helper functions.
func ProbeAndBindWithNATTraversal(cfg *BindConfig) (*BindResult, error) {
	// Validate network type
	isTCP := strings.HasPrefix(strings.ToLower(cfg.Network), "tcp")
	isUDP := strings.HasPrefix(strings.ToLower(cfg.Network), "udp")
	if !isTCP && !isUDP {
		return nil, oops.Errorf("unsupported network type: %s (must be tcp or udp)", cfg.Network)
	}

	// Probe for OS-assigned port
	assignedPort, err := probePort(cfg)
	if err != nil {
		return nil, err
	}

	log.WithField("port", assignedPort).Info("probed OS-assigned port; attempting NAT traversal")

	// Rebind with retry logic
	return rebindWithRetry(cfg, assignedPort)
}
