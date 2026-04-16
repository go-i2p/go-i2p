package i2pcontrol

import (
	"strings"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
)

// TestValidateServerConfig_RejectsNonLoopbackPlaintext asserts that binding to
// a non-loopback interface without HTTPS fails fast unless the operator
// explicitly opts in via AllowPlaintextNonLoopback. See AUDIT.md HIGH —
// "Plain-HTTP default for I2PControl..." (2026-04-16).
func TestValidateServerConfig_RejectsNonLoopbackPlaintext(t *testing.T) {
	stats := &mockServerStatsProvider{}

	t.Run("loopback_plaintext_default_allowed", func(t *testing.T) {
		cfg := &config.I2PControlConfig{
			Enabled:         true,
			Address:         "localhost:7650",
			Password:        "itoopie",
			UseHTTPS:        false,
			TokenExpiration: 10 * time.Minute,
		}
		if _, err := NewServer(cfg, stats); err != nil {
			t.Fatalf("expected loopback default to succeed, got %v", err)
		}
	})

	t.Run("loopback_ipv4_plaintext_default_allowed", func(t *testing.T) {
		cfg := &config.I2PControlConfig{
			Enabled:         true,
			Address:         "127.0.0.1:7650",
			Password:        "itoopie",
			UseHTTPS:        false,
			TokenExpiration: 10 * time.Minute,
		}
		if _, err := NewServer(cfg, stats); err != nil {
			t.Fatalf("expected 127.0.0.1 default to succeed, got %v", err)
		}
	})

	t.Run("non_loopback_plaintext_rejected", func(t *testing.T) {
		cfg := &config.I2PControlConfig{
			Enabled:         true,
			Address:         "0.0.0.0:7650",
			Password:        "strong-password",
			UseHTTPS:        false,
			TokenExpiration: 10 * time.Minute,
		}
		_, err := NewServer(cfg, stats)
		if err == nil {
			t.Fatal("expected error for non-loopback plaintext bind")
		}
		if !strings.Contains(err.Error(), "use_https") {
			t.Fatalf("expected error to mention use_https, got %q", err.Error())
		}
	})

	t.Run("non_loopback_default_password_rejected", func(t *testing.T) {
		cfg := &config.I2PControlConfig{
			Enabled:         true,
			Address:         "0.0.0.0:7650",
			Password:        "itoopie",
			UseHTTPS:        true,
			CertFile:        "/tmp/cert.pem",
			KeyFile:         "/tmp/key.pem",
			TokenExpiration: 10 * time.Minute,
		}
		_, err := NewServer(cfg, stats)
		if err == nil {
			t.Fatal("expected error for non-loopback bind with default password")
		}
		if !strings.Contains(err.Error(), "default password") {
			t.Fatalf("expected error to mention default password, got %q", err.Error())
		}
	})

	t.Run("non_loopback_plaintext_opt_in_allowed", func(t *testing.T) {
		cfg := &config.I2PControlConfig{
			Enabled:                   true,
			Address:                   "0.0.0.0:7650",
			Password:                  "strong-password",
			UseHTTPS:                  false,
			AllowPlaintextNonLoopback: true,
			TokenExpiration:           10 * time.Minute,
		}
		if _, err := NewServer(cfg, stats); err != nil {
			t.Fatalf("expected opt-in plaintext to succeed, got %v", err)
		}
	})

	t.Run("strict_auth_rejects_default_password", func(t *testing.T) {
		cfg := &config.I2PControlConfig{
			Enabled:         true,
			Address:         "localhost:7650",
			Password:        "itoopie",
			UseHTTPS:        false,
			StrictAuth:      true,
			TokenExpiration: 10 * time.Minute,
		}
		_, err := NewServer(cfg, stats)
		if err == nil {
			t.Fatal("expected error for strict_auth with default password")
		}
		if !strings.Contains(err.Error(), "strict_auth") {
			t.Fatalf("expected error to mention strict_auth, got %q", err.Error())
		}
	})
}
