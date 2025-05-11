package ntcp

import (
	"io"
	"net"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/crypto/curve25519"
	"github.com/go-i2p/go-i2p/lib/transport/ntcp/handshake"
	"github.com/samber/oops"
)

// DecryptOptionsBlock decrypts the options block from a SessionRequest message
func (c *NTCP2Session) DecryptOptionsBlock(encryptedOptions []byte, obfuscatedX []byte, deobfuscatedX []byte) ([]byte, error) {
	return c.PerformAEADOperation(
		deobfuscatedX,    // Key material
		encryptedOptions, // Data to decrypt
		obfuscatedX,      // Associated data
		0,                // Nonce counter (0 for first message)
		false,            // Decrypt operation
	)
}

// addDelayForSecurity adds a small random delay to resist probing
func (c *NTCP2Session) addDelayForSecurity() {
	// Sleep between 50-250ms to make timing attacks harder
	// delay := time.Duration(50+mrand.Intn(200)) * time.Millisecond
	delay := time.Duration(0)
	time.Sleep(delay)
}

// validateTimestamp checks if the timestamp is within acceptable range
func (c *NTCP2Session) validateTimestamp(timestamp data.Date) error {
	timestampTime := timestamp.Time()

	now := c.GetCurrentTime()
	diff := now.Sub(timestampTime)

	// Allow ±60 seconds clock skew
	if diff < -60*time.Second || diff > 60*time.Second {
		log.Warnf("NTCP2: Rejecting SessionRequest - clock skew too large: %v", diff)
		return oops.Errorf("clock skew too large: %v", diff)
	}

	return nil
}

// readEphemeralKey reads the ephemeral key (X) from the connection
func (c *NTCP2Session) readEphemeralKey(conn net.Conn) ([]byte, error) {
	ephemeralKey := make([]byte, 32)
	if _, err := io.ReadFull(conn, ephemeralKey); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, oops.Errorf("incomplete ephemeral key: connection closed prematurely")
		}
		return nil, oops.Errorf("failed to read ephemeral key: %w", err)
	}
	return ephemeralKey, nil
}

// processEphemeralKey deobfuscates and validates the ephemeral key
func (c *NTCP2Session) processEphemeralKey(obfuscatedX []byte, hs *handshake.HandshakeState) ([]byte, error) {
	deobfuscatedX, err := c.DeobfuscateEphemeral(obfuscatedX)
	if err != nil {
		c.addDelayForSecurity()
		return nil, oops.Errorf("failed to deobfuscate ephemeral key: %w", err)
	}

	// Validate key for curve25519 (MSB must be cleared)
	if deobfuscatedX[31]&0x80 != 0 {
		log.Warnf("NTCP2: Rejecting SessionRequest - invalid ephemeral key format")
		c.addDelayForSecurity()
		return nil, oops.Errorf("invalid ephemeral key format")
	}

	// Store in handshake state
	pubKey := curve25519.Curve25519PublicKey(deobfuscatedX)
	hs.RemoteEphemeral = pubKey

	return deobfuscatedX, nil
}

// readAndValidatePadding reads the padding from the connection
func (c *NTCP2Session) readAndValidatePadding(conn net.Conn, paddingLen int) error {
	// Check reasonable padding size to prevent DoS
	if paddingLen > 64 {
		return oops.Errorf("excessive padding size: %d bytes", paddingLen)
	}

	padding := make([]byte, paddingLen)
	n, err := io.ReadFull(conn, padding)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return oops.Errorf("incomplete padding: got %d bytes, expected %d", n, paddingLen)
		}
		return oops.Errorf("failed to read padding: %w", err)
	}

	// No need to validate padding content - it's random data
	return nil
}
