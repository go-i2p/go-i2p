package i2pcontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Default certificate file names used when i2pcontrol.use_https is enabled and
// no explicit cert_file/key_file is configured. Named to match i2pd's
// convention so operators and monitoring tooling can find them in the same
// place across implementations.
const (
	defaultCertFileName = "i2pcontrol.crt.pem"
	defaultKeyFileName  = "i2pcontrol.key.pem"
)

const (
	// selfSignedCertValidity is how long a generated certificate stays valid.
	// Long enough that a long-lived testnet router does not need a renewal
	// path, short enough that a stale cert is eventually replaced.
	selfSignedCertValidity = 10 * 365 * 24 * time.Hour

	// selfSignedCertRenewBefore is how close to expiry a certificate may be
	// before the next startup regenerates it, so a router that restarts
	// regularly does not serve an expired certificate.
	selfSignedCertRenewBefore = 30 * 24 * time.Hour

	// certFileMode and keyFileMode follow the i2pd layout: the certificate is
	// public (clients pin it byte-for-byte) while the key stays owner-only.
	certFileMode os.FileMode = 0o644
	keyFileMode  os.FileMode = 0o600
)

// EnsureTLSCertificates resolves the certificate and key the I2PControl server
// should serve when i2pcontrol.use_https is true, updating cfg in place.
//
// Behaviour:
//   - Explicit cert_file/key_file: used as-is. A missing file is an error —
//     an explicit path signals operator-managed material, and silently
//     generating over it would discard that intent.
//   - Unset paths: defaulted to <workingDir>/i2pcontrol.crt.pem and
//     i2pcontrol.key.pem. If either is missing, a self-signed certificate is
//     generated and persisted there, then reused on later startups so the
//     certificate stays byte-for-byte stable and clients can pin it — the same
//     trust model i2pd offers for its own I2PControl interface.
//
// workingDir may be empty, in which case the certificate is generated into a
// temporary directory and lives only for this process.
func EnsureTLSCertificates(cfg *config.I2PControlConfig, workingDir string) error {
	if cfg == nil || !cfg.UseHTTPS {
		return nil
	}

	explicit := cfg.CertFile != "" || cfg.KeyFile != ""
	if explicit {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return oops.Errorf("i2pcontrol: cert_file and key_file must both be set when use_https is true")
		}
		if err := filesExist(cfg.CertFile, cfg.KeyFile); err != nil {
			return oops.Wrapf(err, "i2pcontrol: failed to load TLS certificate/key (configured paths are missing)")
		}
		return nil
	}

	certPath, keyPath, err := resolveDefaultCertPaths(workingDir)
	if err != nil {
		return err
	}

	if certPairUsable(certPath, keyPath) {
		cfg.CertFile, cfg.KeyFile = certPath, keyPath
		log.WithFields(logger.Fields{
			"at":       "EnsureTLSCertificates",
			"certFile": certPath,
			"keyFile":  keyPath,
		}).Info("reusing existing self-signed I2PControl certificate")
		return nil
	}

	if err := generateSelfSignedCert(certPath, keyPath, cfg.Address); err != nil {
		return err
	}
	cfg.CertFile, cfg.KeyFile = certPath, keyPath

	log.WithFields(logger.Fields{
		"at":       "EnsureTLSCertificates",
		"certFile": certPath,
		"keyFile":  keyPath,
		"reason":   "use_https enabled with no cert_file/key_file configured",
	}).Info("generated self-signed I2PControl certificate; clients may pin it")

	return nil
}

// resolveDefaultCertPaths picks where to place the generated certificate. With
// no working directory, a temp directory keeps the server functional (the
// dashboard can still connect over TLS) at the cost of a fresh cert per run.
func resolveDefaultCertPaths(workingDir string) (certPath, keyPath string, err error) {
	if workingDir == "" {
		dir, err := os.MkdirTemp("", "go-i2p-i2pcontrol-")
		if err != nil {
			return "", "", oops.Wrapf(err, "i2pcontrol: no working directory and temp dir creation failed")
		}
		return filepath.Join(dir, defaultCertFileName), filepath.Join(dir, defaultKeyFileName), nil
	}
	if err := os.MkdirAll(workingDir, 0o755); err != nil {
		return "", "", oops.Wrapf(err, "i2pcontrol: failed to create certificate directory %s", workingDir)
	}
	return filepath.Join(workingDir, defaultCertFileName), filepath.Join(workingDir, defaultKeyFileName), nil
}

// certPairUsable reports whether an existing cert/key pair loads and is not
// close to expiry. A pair that fails any of those checks is regenerated.
func certPairUsable(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return false
	}
	return time.Until(leaf.NotAfter) > selfSignedCertRenewBefore
}

// filesExist errors when any listed path is missing, naming the first one.
func filesExist(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return oops.Wrapf(err, "file %s not found", p)
		}
	}
	return nil
}

// generateSelfSignedCert writes a fresh self-signed certificate and its key to
// disk. The certificate carries the bind host as SAN (plus loopback entries)
// so clients that verify hostname in addition to pinning still succeed.
func generateSelfSignedCert(certPath, keyPath, address string) error {
	return generateSelfSignedCertValidity(certPath, keyPath, address, selfSignedCertValidity)
}

// generateSelfSignedCertValidity is generateSelfSignedCert with an explicit
// validity window, so tests can seed an already-expired certificate.
func generateSelfSignedCertValidity(certPath, keyPath, address string, validity time.Duration) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return oops.Wrapf(err, "i2pcontrol: failed to generate certificate key")
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return oops.Wrapf(err, "i2pcontrol: failed to generate certificate serial")
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "go-i2p I2PControl"},
		NotBefore:    now.Add(-time.Hour), // tolerate clock skew at creation
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// IsCA lets the self-signed cert stand alone. MaxPathLenZero marks the
		// explicit 0 constraint so the cert cannot sign anything downstream.
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host := bindHostFromAddress(address); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		return oops.Wrapf(err, "i2pcontrol: failed to create self-signed certificate")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return oops.Wrapf(err, "i2pcontrol: failed to marshal certificate key")
	}

	if err := writePEM(certPath, pem.Block{Type: "CERTIFICATE", Bytes: der}, certFileMode); err != nil {
		return err
	}
	if err := writePEM(keyPath, pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}, keyFileMode); err != nil {
		return err
	}
	return nil
}

// bindHostFromAddress extracts the host from a "host:port" bind address.
// Returns "" for a wildcard or unparseable address, where no useful SAN can be
// derived.
func bindHostFromAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		return ""
	}
	return host
}

// writePEM atomically writes a PEM block to path with the given mode.
func writePEM(path string, block pem.Block, mode os.FileMode) error {
	f, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return oops.Wrapf(err, "i2pcontrol: failed to open %s", path)
	}
	if err := pem.Encode(f, &block); err != nil {
		f.Close()
		os.Remove(path + ".tmp")
		return oops.Wrapf(err, "i2pcontrol: failed to encode PEM into %s", path)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path + ".tmp")
		return oops.Wrapf(err, "i2pcontrol: failed to sync %s", path)
	}
	if err := f.Close(); err != nil {
		os.Remove(path + ".tmp")
		return oops.Wrapf(err, "i2pcontrol: failed to close %s", path)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		os.Remove(path + ".tmp")
		return oops.Wrapf(err, "i2pcontrol: failed to move %s into place", path)
	}
	return nil
}
