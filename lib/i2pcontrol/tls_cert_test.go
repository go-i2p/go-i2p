// Tests for self-signed I2PControl TLS certificate handling.
//
// The dashboard pins i2pd's I2PControl certificate byte-for-byte; go-i2p needs
// the same trust model, which requires a certificate that exists at a stable
// path and survives a restart unchanged.
package i2pcontrol

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureTLSCertificatesGeneratesWhenUnset verifies use_https with no
// configured paths produces a loadable certificate pair at the documented
// file names.
func TestEnsureTLSCertificatesGeneratesWhenUnset(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(7650)
	cfg.UseHTTPS = true

	require.NoError(t, EnsureTLSCertificates(cfg, dir))

	assert.Equal(t, filepath.Join(dir, defaultCertFileName), cfg.CertFile)
	assert.Equal(t, filepath.Join(dir, defaultKeyFileName), cfg.KeyFile)
	require.FileExists(t, cfg.CertFile)
	require.FileExists(t, cfg.KeyFile)

	_, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	require.NoError(t, err, "the generated pair must load as a TLS certificate")
}

// TestEnsureTLSCertificatesIsStableAcrossRestarts pins the property that makes
// certificate pinning possible: a second startup reuses the same bytes rather
// than minting a new identity.
func TestEnsureTLSCertificatesIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	first := testConfig(7650)
	first.UseHTTPS = true
	require.NoError(t, EnsureTLSCertificates(first, dir))
	firstBytes, err := os.ReadFile(first.CertFile)
	require.NoError(t, err)

	second := testConfig(7650)
	second.UseHTTPS = true
	require.NoError(t, EnsureTLSCertificates(second, dir))
	secondBytes, err := os.ReadFile(second.CertFile)
	require.NoError(t, err)

	assert.Equal(t, firstBytes, secondBytes,
		"a pinned certificate must not change when the router restarts")
}

// TestEnsureTLSCertificatesKeyPermissions verifies the private key stays
// owner-only while the certificate is world-readable, so a dashboard running
// as another user can still pin it.
func TestEnsureTLSCertificatesKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(7650)
	cfg.UseHTTPS = true

	require.NoError(t, EnsureTLSCertificates(cfg, dir))

	keyInfo, err := os.Stat(cfg.KeyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm(), "the key must be owner-only")

	certInfo, err := os.Stat(cfg.CertFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), certInfo.Mode().Perm(), "the certificate must be readable")
}

// TestEnsureTLSCertificatesSANCoversBindHost verifies hostname verification
// still works for a client that checks the name in addition to pinning.
func TestEnsureTLSCertificatesSANCoversBindHost(t *testing.T) {
	tests := []struct {
		name    string
		address string
		dnsName string
		ipName  string
	}{
		{"loopback hostname", "localhost:7650", "localhost", ""},
		{"explicit IPv4 bind", "10.1.2.3:7650", "", "10.1.2.3"},
		{"wildcard bind adds no extra SAN", "0.0.0.0:7650", "localhost", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := testConfig(7650)
			cfg.UseHTTPS = true
			cfg.Address = tt.address

			require.NoError(t, EnsureTLSCertificates(cfg, dir))

			leaf := leafCertFrom(t, cfg.CertFile)
			if tt.dnsName != "" {
				assert.Contains(t, leaf.DNSNames, tt.dnsName)
			}
			if tt.ipName != "" {
				found := false
				for _, ip := range leaf.IPAddresses {
					if ip.String() == tt.ipName {
						found = true
					}
				}
				assert.True(t, found, "expected %s in certificate IP SANs", tt.ipName)
			}
			assert.True(t, leaf.NotAfter.After(time.Now().Add(selfSignedCertRenewBefore)),
				"the certificate must not be near expiry at creation")
		})
	}
}

// TestEnsureTLSCertificatesRegeneratesExpired verifies an expired certificate
// on disk is replaced rather than served, so a router that sat idle past its
// validity does not come back with a dead TLS listener.
func TestEnsureTLSCertificatesRegeneratesExpired(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, defaultCertFileName)
	keyPath := filepath.Join(dir, defaultKeyFileName)

	// Seed a loadable certificate whose validity has already lapsed.
	require.NoError(t, generateSelfSignedCertValidity(certPath, keyPath, "localhost:7650", -time.Hour))

	cfg := testConfig(7650)
	cfg.UseHTTPS = true
	require.NoError(t, EnsureTLSCertificates(cfg, dir))

	leaf := leafCertFrom(t, cfg.CertFile)
	assert.True(t, leaf.NotAfter.After(time.Now()), "an expired certificate must be regenerated")
}

// TestEnsureTLSCertificatesRegeneratesNearExpiry verifies a certificate inside
// the renewal window is replaced at startup.
func TestEnsureTLSCertificatesRegeneratesNearExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, defaultCertFileName)
	keyPath := filepath.Join(dir, defaultKeyFileName)

	require.NoError(t, generateSelfSignedCertValidity(certPath, keyPath, "localhost:7650", time.Hour))

	cfg := testConfig(7650)
	cfg.UseHTTPS = true
	require.NoError(t, EnsureTLSCertificates(cfg, dir))

	leaf := leafCertFrom(t, cfg.CertFile)
	assert.Greater(t, time.Until(leaf.NotAfter), selfSignedCertRenewBefore,
		"a certificate inside the renewal window must be regenerated")
}

// TestEnsureTLSCertificatesExplicitPathsRequired verifies an operator who sets
// one of cert_file/key_file must set both.
func TestEnsureTLSCertificatesExplicitPathsRequired(t *testing.T) {
	cfg := testConfig(7650)
	cfg.UseHTTPS = true
	cfg.CertFile = filepath.Join(t.TempDir(), "cert.pem")
	cfg.KeyFile = ""

	err := EnsureTLSCertificates(cfg, t.TempDir())
	require.Error(t, err, "a half-specified explicit pair must fail")
}

// TestEnsureTLSCertificatesExplicitMissingIsError verifies go-i2p does not
// silently generate over an operator-managed path that does not exist.
func TestEnsureTLSCertificatesExplicitMissingIsError(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(7650)
	cfg.UseHTTPS = true
	cfg.CertFile = filepath.Join(dir, "missing.pem")
	cfg.KeyFile = filepath.Join(dir, "missing-key.pem")

	err := EnsureTLSCertificates(cfg, dir)
	require.Error(t, err, "a configured-but-missing certificate must be an error")
}

// TestEnsureTLSCertificatesNoWorkingDirStillServes verifies the server stays
// functional without a working directory, at the cost of a per-process cert.
func TestEnsureTLSCertificatesNoWorkingDirStillServes(t *testing.T) {
	cfg := testConfig(7650)
	cfg.UseHTTPS = true

	require.NoError(t, EnsureTLSCertificates(cfg, ""))

	_, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(cfg.CertFile)) })
}

// TestEnsureTLSCertificatesSkippedWhenPlaintext verifies plaintext deployments
// are untouched: no certificate is generated when use_https is false.
func TestEnsureTLSCertificatesSkippedWhenPlaintext(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(7650)
	cfg.UseHTTPS = false

	require.NoError(t, EnsureTLSCertificates(cfg, dir))
	assert.Empty(t, cfg.CertFile)
	assert.NoFileExists(t, filepath.Join(dir, defaultCertFileName))
}

// TestGeneratedCertServesHTTPS end-to-end: start the server with an
// auto-generated certificate and verify a client that pins the leaf
// certificate byte-for-byte gets a valid response over TLS.
func TestGeneratedCertServesHTTPS(t *testing.T) {
	dir := t.TempDir()
	port, err := getFreePort()
	require.NoError(t, err)

	cfg := testConfig(port)
	cfg.UseHTTPS = true
	require.NoError(t, EnsureTLSCertificates(cfg, dir))

	stats := &mockServerStatsProvider{running: true}
	server, err := NewServer(cfg, stats)
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(server.Stop)

	leaf := leafCertFrom(t, cfg.CertFile)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
		},
	}
	t.Cleanup(func() { client.CloseIdleConnections() })

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/", port))
	require.NoError(t, err, "a pinned client must be able to connect")
	defer resp.Body.Close()

	require.NotNil(t, resp.TLS, "the connection must be TLS")
	require.NotEmpty(t, resp.TLS.PeerCertificates, "the server must present a certificate")

	// The pinned bytes are exactly what the server presented: this is the
	// byte-for-byte pin the dashboard performs against i2pd.
	assert.Equal(t, leaf.Raw, resp.TLS.PeerCertificates[0].Raw,
		"the presented leaf must match the certificate on disk byte-for-byte")
}

// leafCertFrom parses the leaf certificate out of a PEM file.
func leafCertFrom(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block, "the certificate file must contain a PEM block")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return leaf
}
