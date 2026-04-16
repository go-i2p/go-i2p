package i2pcontrol

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/spf13/viper"
)

// seedValidConfigDefaults populates viper with the project defaults so the
// global Validate(CurrentConfig()) check inside applySettingChange has a
// consistent baseline to check against. Tests restore prior viper state in
// their own Cleanup hooks.
func seedValidConfigDefaults(t *testing.T) {
	t.Helper()
	defaults := config.Defaults()
	viper.Set("router.max_concurrent_sessions", defaults.Router.MaxConcurrentSessions)
	viper.Set("router.max_bandwidth", 0)
	viper.Set("router.router_info_refresh_interval", defaults.Router.RouterInfoRefreshInterval)
	viper.Set("router.message_expiration_time", defaults.Router.MessageExpirationTime)
	viper.Set("netdb.max_router_infos", defaults.NetDB.MaxRouterInfos)
	viper.Set("netdb.max_lease_sets", defaults.NetDB.MaxLeaseSets)
	viper.Set("netdb.expiration_check_interval", defaults.NetDB.ExpirationCheckInterval)
	viper.Set("netdb.lease_set_refresh_threshold", defaults.NetDB.LeaseSetRefreshThreshold)
	viper.Set("netdb.exploration_interval", defaults.NetDB.ExplorationInterval)
	viper.Set("bootstrap.low_peer_threshold", defaults.Bootstrap.LowPeerThreshold)
	viper.Set("bootstrap.reseed_timeout", defaults.Bootstrap.ReseedTimeout)
	viper.Set("bootstrap.minimum_reseed_peers", defaults.Bootstrap.MinimumReseedPeers)
	viper.Set("bootstrap.reseed_retry_interval", defaults.Bootstrap.ReseedRetryInterval)
	viper.Set("transport.ntcp2_port", 7654)
	viper.Set("transport.ntcp2_hostname", "example.i2p")
	viper.Set("tunnel.length", defaults.Tunnel.TunnelLength)
	viper.Set("tunnel.lifetime", defaults.Tunnel.TunnelLifetime)
	viper.Set("tunnel.min_pool_size", defaults.Tunnel.MinPoolSize)
	viper.Set("tunnel.max_pool_size", defaults.Tunnel.MaxPoolSize)
	viper.Set("tunnel.test_interval", defaults.Tunnel.TunnelTestInterval)
	viper.Set("i2pcontrol.address", defaults.I2PControl.Address)
	viper.Set("i2pcontrol.password", defaults.I2PControl.Password)
	viper.Set("i2pcontrol.token_expiration", defaults.I2PControl.TokenExpiration)
}

// TestApplySettingChange_InvalidPort asserts the NetworkSetting handler
// rejects out-of-range / non-integer port values before they are persisted
// through viper. See AUDIT.md MEDIUM — "Unvalidated types written through
// viper.Set + viper.WriteConfig...".
func TestApplySettingChange_InvalidPort(t *testing.T) {
	seedValidConfigDefaults(t)
	// Preserve global viper state for other tests.
	prev := viper.Get("transport.ntcp2_port")
	t.Cleanup(func() { viper.Set("transport.ntcp2_port", prev) })

	viper.Set("transport.ntcp2_port", 7654)

	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

	cases := []struct {
		name   string
		params string
	}{
		{"negative_port", `{"i2p.router.net.ntcp.port": -1}`},
		{"too_large_port", `{"i2p.router.net.ntcp.port": 99999}`},
		{"string_port", `{"i2p.router.net.ntcp.port": "abcd"}`},
		{"fractional_port", `{"i2p.router.net.ntcp.port": 3.5}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.Handle(context.Background(), json.RawMessage(tc.params))
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			// Value must not have been persisted.
			if got := viper.GetInt("transport.ntcp2_port"); got != 7654 {
				t.Fatalf("port mutated on rejected input: %d", got)
			}
		})
	}

	// Sanity check: a valid port is accepted.
	_, err := handler.Handle(context.Background(), json.RawMessage(`{"i2p.router.net.ntcp.port": 9000}`))
	if err != nil {
		t.Fatalf("expected valid port to succeed, got %v", err)
	}
	if got := viper.GetInt("transport.ntcp2_port"); got != 9000 {
		t.Fatalf("expected port 9000, got %d", got)
	}
}

// TestApplySettingChange_InvalidHostname asserts hostname inputs with invalid
// characters are rejected before being written through viper.
func TestApplySettingChange_InvalidHostname(t *testing.T) {
	seedValidConfigDefaults(t)
	prev := viper.Get("transport.ntcp2_hostname")
	t.Cleanup(func() { viper.Set("transport.ntcp2_hostname", prev) })

	viper.Set("transport.ntcp2_hostname", "example.i2p")

	stats := &mockServerStatsProvider{}
	handler := NewNetworkSettingHandler(stats)

	params := json.RawMessage(`{"i2p.router.net.ntcp.hostname": "bad host;drop"}`)
	if _, err := handler.Handle(context.Background(), params); err == nil {
		t.Fatal("expected error for invalid hostname characters")
	}
	if got := viper.GetString("transport.ntcp2_hostname"); got != "example.i2p" {
		t.Fatalf("hostname mutated on rejected input: %q", got)
	}
}
