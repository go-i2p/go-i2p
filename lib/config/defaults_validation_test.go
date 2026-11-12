package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Validation Tests for defaults.go — Validate function
// =============================================================================

// requireValidationError calls Validate on cfg, asserts it returns a non-nil
// *validationError, and returns the error for further inspection if needed.
func requireValidationError(t *testing.T, cfg ConfigDefaults, msg string) error {
	t.Helper()
	err := Validate(cfg)
	require.Error(t, err, msg)
	assert.IsType(t, &validationError{}, err, "Validate() should return *validationError")
	return err
}

// requireValidationFails calls Validate on cfg and asserts it returns a non-nil error.
func requireValidationFails(t *testing.T, cfg ConfigDefaults, msgAndArgs ...interface{}) {
	t.Helper()
	require.Error(t, Validate(cfg), msgAndArgs...)
}

// TestValidate_ValidConfig verifies that valid configurations pass validation
func TestValidate_ValidConfig(t *testing.T) {
	cfg := Defaults()
	require.NoError(t, Validate(cfg), "Validate() failed for default config")
}

// TestValidate_RouterInvalidMaxSessions verifies validation catches invalid max sessions
func TestValidate_RouterInvalidMaxSessions(t *testing.T) {
	cfg := Defaults()
	cfg.Router.MaxConcurrentSessions = 0
	requireValidationError(t, cfg, "Validate() should fail when MaxConcurrentSessions is 0")
}

// TestValidate_RouterInvalidMessageExpiration verifies validation catches invalid expiration
func TestValidate_RouterInvalidMessageExpiration(t *testing.T) {
	cfg := Defaults()
	cfg.Router.MessageExpirationTime = 500 * time.Millisecond
	requireValidationFails(t, cfg, "Validate() should fail when MessageExpirationTime < 1s")
}

// TestValidate_NetDBInvalidMaxRouterInfos verifies validation catches invalid max RouterInfos
func TestValidate_NetDBInvalidMaxRouterInfos(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.MaxRouterInfos = 5
	requireValidationFails(t, cfg, "Validate() should fail when MaxRouterInfos < 10")
}

// TestValidate_NetDBInvalidMaxLeaseSets verifies validation catches invalid max LeaseSets
func TestValidate_NetDBInvalidMaxLeaseSets(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.MaxLeaseSets = 0
	requireValidationFails(t, cfg, "Validate() should fail when MaxLeaseSets < 1")
}

func TestValidate_NetDBInvalidRouterInfoPressureThresholdLow(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.RouterInfoAdmissionPressureThresholdPct = 0
	requireValidationFails(t, cfg, "Validate() should fail when RouterInfoAdmissionPressureThresholdPct < 1")
}

func TestValidate_NetDBInvalidRouterInfoPressureThresholdHigh(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.RouterInfoAdmissionPressureThresholdPct = 100
	requireValidationFails(t, cfg, "Validate() should fail when RouterInfoAdmissionPressureThresholdPct > 99")
}

// TestValidate_NetDBEmptyPath verifies validation catches empty NetDB path
func TestValidate_NetDBEmptyPath(t *testing.T) {
	cfg := Defaults()
	cfg.NetDB.Path = ""
	requireValidationError(t, cfg, "Validate() should fail when NetDB.Path is empty")
}

// TestValidate_BootstrapInvalidThreshold verifies validation catches invalid peer threshold
func TestValidate_BootstrapInvalidThreshold(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.LowPeerThreshold = 0
	requireValidationFails(t, cfg, "Validate() should fail when LowPeerThreshold < 1")
}

// TestValidate_BootstrapInvalidMinPeers verifies validation catches invalid minimum peers
func TestValidate_BootstrapInvalidMinPeers(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.MinimumReseedPeers = 0
	requireValidationFails(t, cfg, "Validate() should fail when MinimumReseedPeers < 1")
}

// TestValidate_BootstrapInvalidType verifies validation catches invalid bootstrap type
func TestValidate_BootstrapInvalidType(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.BootstrapType = "foobar"
	requireValidationError(t, cfg, "Validate() should fail when BootstrapType is invalid")
}

// TestValidate_BootstrapValidTypes verifies all valid bootstrap types pass
func TestValidate_BootstrapValidTypes(t *testing.T) {
	for _, bt := range []string{"auto", "file", "reseed", "local"} {
		t.Run(bt, func(t *testing.T) {
			cfg := Defaults()
			cfg.Bootstrap.BootstrapType = bt
			require.NoError(t, Validate(cfg), "Validate() should pass for BootstrapType %q", bt)
		})
	}
}

// TestValidate_BootstrapInvalidReseedStrategy verifies validation catches invalid reseed strategy
func TestValidate_BootstrapInvalidReseedStrategy(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.ReseedStrategy = "invalid_strategy"
	requireValidationError(t, cfg, "Validate() should fail when ReseedStrategy is invalid")
}

// TestValidate_BootstrapValidReseedStrategies verifies all valid strategies pass
func TestValidate_BootstrapValidReseedStrategies(t *testing.T) {
	for _, strategy := range ValidReseedStrategies() {
		t.Run(strategy, func(t *testing.T) {
			cfg := Defaults()
			cfg.Bootstrap.ReseedStrategy = strategy
			require.NoError(t, Validate(cfg), "Validate() should pass for ReseedStrategy %q", strategy)
		})
	}
}

// TestValidate_BootstrapEmptyReseedStrategy verifies empty strategy passes
// (empty is valid in BootstrapDefaults when not explicitly configured)
func TestValidate_BootstrapEmptyReseedStrategy(t *testing.T) {
	cfg := Defaults()
	cfg.Bootstrap.ReseedStrategy = ""
	require.NoError(t, Validate(cfg), "Validate() should pass for empty ReseedStrategy")
}

// TestValidate_I2CPInvalidMaxSessions verifies validation catches invalid max sessions
func TestValidate_I2CPInvalidMaxSessions(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.MaxSessions = 0
	requireValidationFails(t, cfg, "Validate() should fail when I2CP.MaxSessions < 1")
}

// TestValidate_I2CPInvalidMaxSessionsTooHigh verifies validation catches
// values above the defensively allowed I2CP session ceiling.
func TestValidate_I2CPInvalidMaxSessionsTooHigh(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.MaxSessions = MaxI2CPSessions + 1
	requireValidationFails(t, cfg, "Validate() should fail when I2CP.MaxSessions > %d", MaxI2CPSessions)
}

// TestValidate_I2CPMaxSessionsUpperBoundAccepted verifies the documented
// maximum value is still accepted.
func TestValidate_I2CPMaxSessionsUpperBoundAccepted(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.MaxSessions = MaxI2CPSessions
	require.NoError(t, Validate(cfg), "Validate() should pass when I2CP.MaxSessions == %d", MaxI2CPSessions)
}

// TestValidate_I2CPInvalidQueueSize verifies validation catches invalid queue size
func TestValidate_I2CPInvalidQueueSize(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.MessageQueueSize = 0
	requireValidationFails(t, cfg, "Validate() should fail when MessageQueueSize < 1")
}

// TestValidate_I2CPInvalidNetworkType verifies validation catches invalid network type
func TestValidate_I2CPInvalidNetworkType(t *testing.T) {
	cfg := Defaults()
	cfg.I2CP.Network = "udp"
	requireValidationError(t, cfg, "Validate() should fail when I2CP.Network is 'udp'")
}

// TestValidate_I2CPValidNetworkTypes verifies all valid network types pass
func TestValidate_I2CPValidNetworkTypes(t *testing.T) {
	for _, net := range []string{"tcp", "unix"} {
		t.Run(net, func(t *testing.T) {
			cfg := Defaults()
			cfg.I2CP.Network = net
			require.NoError(t, Validate(cfg), "Validate() should pass for I2CP.Network %q", net)
		})
	}
}

// TestValidate_I2PControlHTTPSNoCertsAutoGenerates verifies that enabling HTTPS
// with neither path set is valid: the router generates and persists a
// self-signed pair, so a testnet gets TLS without manual certificate prep.
func TestValidate_I2PControlHTTPSNoCertsAutoGenerates(t *testing.T) {
	cfg := Defaults()
	cfg.I2PControl.UseHTTPS = true
	cfg.I2PControl.CertFile = ""
	cfg.I2PControl.KeyFile = ""
	cfg.I2PControl.TokenExpiration = 10 * time.Minute
	require.NoError(t, Validate(cfg),
		"Validate() should accept UseHTTPS with no cert/key so the router can self-generate")
}

// TestValidate_I2PControlHTTPSMissingCert verifies validation catches missing cert file
func TestValidate_I2PControlHTTPSMissingCert(t *testing.T) {
	cfg := Defaults()
	cfg.I2PControl.UseHTTPS = true
	cfg.I2PControl.CertFile = ""
	cfg.I2PControl.KeyFile = "/path/to/key.pem"
	requireValidationError(t, cfg, "Validate() should fail when UseHTTPS is true but CertFile is empty")
}

// TestValidate_I2PControlHTTPSMissingKey verifies validation catches missing key file
func TestValidate_I2PControlHTTPSMissingKey(t *testing.T) {
	cfg := Defaults()
	cfg.I2PControl.UseHTTPS = true
	cfg.I2PControl.CertFile = "/path/to/cert.pem"
	cfg.I2PControl.KeyFile = ""
	requireValidationError(t, cfg, "Validate() should fail when UseHTTPS is true but KeyFile is empty")
}

// TestValidate_I2PControlInvalidTokenExpiration verifies validation catches invalid token expiration
func TestValidate_I2PControlInvalidTokenExpiration(t *testing.T) {
	cfg := Defaults()
	cfg.I2PControl.TokenExpiration = 30 * time.Second
	requireValidationError(t, cfg, "Validate() should fail when TokenExpiration < 1 minute")
}

// TestValidate_I2PControlValidConfig verifies valid I2PControl config passes
func TestValidate_I2PControlValidConfig(t *testing.T) {
	cfg := Defaults()
	cfg.I2PControl.Enabled = true
	cfg.I2PControl.UseHTTPS = true
	cfg.I2PControl.CertFile = "/path/to/cert.pem"
	cfg.I2PControl.KeyFile = "/path/to/key.pem"
	cfg.I2PControl.TokenExpiration = 10 * time.Minute
	require.NoError(t, Validate(cfg), "Validate() should pass for valid I2PControl config")
}

// TestValidate_TunnelInvalidMinPoolSize verifies validation catches invalid min pool size
func TestValidate_TunnelInvalidMinPoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnel.MinPoolSize = 0
	requireValidationFails(t, cfg, "Validate() should fail when MinPoolSize < 1")
}

// TestValidate_TunnelInvalidMaxPoolSize verifies validation catches invalid max pool size
func TestValidate_TunnelInvalidMaxPoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnel.MinPoolSize = 6
	cfg.Tunnel.MaxPoolSize = 4
	requireValidationFails(t, cfg, "Validate() should fail when MaxPoolSize < MinPoolSize")
}

// TestValidate_TunnelInvalidLength verifies validation catches invalid tunnel length
func TestValidate_TunnelInvalidLength(t *testing.T) {
	testCases := []struct {
		length int
		name   string
	}{
		{0, "zero"},
		{9, "too long"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Tunnel.TunnelLength = tc.length
			requireValidationFails(t, cfg, "Validate() should fail when TunnelLength = %d", tc.length)
		})
	}
}

// TestValidate_TunnelInvalidBuildRetries verifies validation catches invalid build retries
func TestValidate_TunnelInvalidBuildRetries(t *testing.T) {
	cfg := Defaults()
	cfg.Tunnel.BuildRetries = 0
	requireValidationFails(t, cfg, "Validate() should fail when BuildRetries < 1")
}

// TestValidate_TransportInvalidMaxMessageSize verifies validation catches invalid max message size
func TestValidate_TransportInvalidMaxMessageSize(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.MaxMessageSize = 512
	requireValidationFails(t, cfg, "Validate() should fail when MaxMessageSize < 1024")
}

// TestValidate_TransportInvalidMaxConnections verifies validation catches invalid max connections
func TestValidate_TransportInvalidMaxConnections(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.NTCP2MaxConnections = 0
	requireValidationFails(t, cfg, "Validate() should fail when NTCP2MaxConnections < 1")
}

// TestValidate_HandshakeBoundsInverted verifies validation rejects a per-source
// handshake cap that exceeds the transport-wide cap. Either bound may be 0
// (transport default) or negative (disabled), so their relative size is the only
// thing that can be wrong — and an inverted pair means the per-source limit the
// operator asked for silently never binds.
func TestValidate_HandshakeBoundsInverted(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.NTCP2MaxInflightHandshakes = 10
	cfg.Transport.NTCP2MaxHandshakesPerSource = 50
	requireValidationFails(t, cfg, "Validate() should fail when per-source exceeds the transport-wide handshake cap")
}

// TestValidate_HandshakeBoundsAllowDefaultAndDisabled verifies the two accepted
// spellings are not rejected: 0 defers to the transport's own default and a
// negative value explicitly disables the bound.
func TestValidate_HandshakeBoundsAllowDefaultAndDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.NTCP2MaxInflightHandshakes = 0
	cfg.Transport.NTCP2MaxHandshakesPerSource = 0
	require.NoError(t, Validate(cfg), "Validate() should accept the zero (transport default) spelling")

	cfg.Transport.NTCP2MaxInflightHandshakes = -1
	cfg.Transport.NTCP2MaxHandshakesPerSource = -1
	require.NoError(t, Validate(cfg), "Validate() should accept negative (bound disabled)")

	cfg.Transport.NTCP2MaxInflightHandshakes = 64
	cfg.Transport.NTCP2MaxHandshakesPerSource = 8
	require.NoError(t, Validate(cfg), "Validate() should accept a per-source cap below the global cap")

	// A disabled global cap cannot be exceeded by any per-source value.
	cfg.Transport.NTCP2MaxInflightHandshakes = -1
	cfg.Transport.NTCP2MaxHandshakesPerSource = 500
	require.NoError(t, Validate(cfg), "Validate() should not compare bounds when the global cap is disabled")
}

// TestValidate_SSU2MaxConnectionsNegative verifies a negative SSU2 session-pool
// size is rejected. Unlike NTCP2MaxConnections (whose default is an explicit
// number), SSU2MaxConnections may be 0 to defer to the transport default, so only
// a negative pool size is nonsense.
func TestValidate_SSU2MaxConnectionsNegative(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.SSU2MaxConnections = -1
	requireValidationFails(t, cfg, "Validate() should fail when SSU2MaxConnections < 0")

	cfg.Transport.SSU2MaxConnections = 0
	require.NoError(t, Validate(cfg), "Validate() should accept SSU2MaxConnections == 0 (transport default)")
}

// TestValidate_SSU2HandshakeBoundsInverted mirrors the NTCP2 check: an SSU2
// per-source handshake cap above the transport-wide cap silently never binds, so
// validation must reject it.
func TestValidate_SSU2HandshakeBoundsInverted(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.SSU2MaxInflightHandshakes = 10
	cfg.Transport.SSU2MaxHandshakesPerSource = 50
	requireValidationFails(t, cfg, "Validate() should fail when SSU2 per-source exceeds the transport-wide handshake cap")
}

// TestValidate_SSU2HandshakeBoundsAllowDefaultAndDisabled verifies the accepted
// spellings for the SSU2 handshake bounds are not rejected.
func TestValidate_SSU2HandshakeBoundsAllowDefaultAndDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.SSU2MaxInflightHandshakes = 0
	cfg.Transport.SSU2MaxHandshakesPerSource = 0
	require.NoError(t, Validate(cfg), "Validate() should accept the zero (transport default) spelling")

	cfg.Transport.SSU2MaxInflightHandshakes = -1
	cfg.Transport.SSU2MaxHandshakesPerSource = -1
	require.NoError(t, Validate(cfg), "Validate() should accept negative (bound disabled)")

	cfg.Transport.SSU2MaxInflightHandshakes = 64
	cfg.Transport.SSU2MaxHandshakesPerSource = 8
	require.NoError(t, Validate(cfg), "Validate() should accept a per-source cap below the global cap")

	cfg.Transport.SSU2MaxInflightHandshakes = -1
	cfg.Transport.SSU2MaxHandshakesPerSource = 500
	require.NoError(t, Validate(cfg), "Validate() should not compare SSU2 bounds when the global cap is disabled")
}

// TestValidate_DefaultsPass pins that the shipped defaults — including the new
// SSU2 knobs — are internally consistent, so a fresh config validates cleanly.
func TestValidate_SSU2DefaultsPass(t *testing.T) {
	require.NoError(t, Validate(Defaults()), "the built-in defaults must validate")
}

// TestValidate_TransportInvalidNTCP2Port verifies validation catches out-of-range ports
func TestValidate_TransportInvalidNTCP2Port(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.NTCP2Port = 70000
	requireValidationFails(t, cfg, "Validate() should fail when NTCP2Port > 65535")
}

// TestValidate_TransportInvalidSSU2Port verifies validation catches out-of-range SSU2 ports
func TestValidate_TransportInvalidSSU2Port(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.SSU2Port = -1
	requireValidationFails(t, cfg, "Validate() should fail when SSU2Port < 0")
}

// TestValidate_TransportInvalidConnectionTimeout verifies validation catches too-short timeouts
func TestValidate_TransportInvalidConnectionTimeout(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.ConnectionTimeout = 0
	requireValidationFails(t, cfg, "Validate() should fail when ConnectionTimeout < 1 second")
}

// TestValidate_TransportInvalidIdleTimeout verifies validation catches too-short idle timeouts
func TestValidate_TransportInvalidIdleTimeout(t *testing.T) {
	cfg := Defaults()
	cfg.Transport.IdleTimeout = 0
	requireValidationFails(t, cfg, "Validate() should fail when IdleTimeout < 1 second")
}

// TestValidate_PerformanceInvalidWorkerPoolSize verifies validation catches invalid worker pool size
func TestValidate_PerformanceInvalidWorkerPoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Performance.WorkerPoolSize = 0
	requireValidationFails(t, cfg, "Validate() should fail when WorkerPoolSize < 1")
}

// TestValidate_PerformanceInvalidMessageQueueSize verifies validation catches invalid message queue size
func TestValidate_PerformanceInvalidMessageQueueSize(t *testing.T) {
	cfg := Defaults()
	cfg.Performance.MessageQueueSize = 0
	requireValidationFails(t, cfg, "Validate() should fail when MessageQueueSize < 1")
}

// TestValidationError_Error verifies validationError implements error interface correctly
func TestValidationError_Error(t *testing.T) {
	err := newValidationError("test message")
	assert.Equal(t, "configuration validation failed: test message", err.Error())
}
