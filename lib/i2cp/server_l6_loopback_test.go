package i2cp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsLoopbackAddr verifies the loopback detection logic for L-6 FIX.
func TestIsLoopbackAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addr     string
		network  string
		expected bool
	}{
		// Unix sockets (always loopback)
		{"unix_socket_default", "/tmp/i2cp.sock", "unix", true},
		{"unix_socket_custom", "/var/run/i2cp.sock", "unix", true},

		// TCP loopback addresses
		{"tcp_localhost_with_port", "localhost:7654", "tcp", true},
		{"tcp_localhost_no_port", "localhost", "tcp", true},
		{"tcp_127_0_0_1", "127.0.0.1:7654", "tcp", true},
		{"tcp_127_0_0_1_no_port", "127.0.0.1", "tcp", true},
		{"tcp_ipv6_loopback", "::1", "tcp", true},
		{"tcp_ipv6_loopback_with_port", "[::1]:7654", "tcp", true},
		{"tcp_empty_addr", "", "tcp", true}, // Empty addr defaults to loopback

		// TCP non-loopback addresses (should warn)
		{"tcp_0_0_0_0", "0.0.0.0:7654", "tcp", false},
		{"tcp_0_0_0_0_no_port", "0.0.0.0", "tcp", false},
		{"tcp_all_interfaces_ipv6", "[::]:7654", "tcp", false},
		{"tcp_external_ip", "192.168.1.1:7654", "tcp", false},
		{"tcp_external_ip_no_port", "192.168.1.1", "tcp", false},
		{"tcp_hostname", "example.com:7654", "tcp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLoopbackAddr(tt.addr, tt.network)
			assert.Equal(t, tt.expected, result,
				"isLoopbackAddr(%q, %q) should return %v", tt.addr, tt.network, tt.expected)
		})
	}
}
