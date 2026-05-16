package i2np

import (
	"golang.org/x/crypto/chacha20"

	"github.com/samber/oops"
)

// GetBuildSuccessCount returns the number of successful tunnel builds within windowMs milliseconds.
// Maps to the Java I2P stat "tunnel.buildExploratorySuccess".
func (tm *TunnelManager) GetBuildSuccessCount(windowMs int64) float64 {
	return tm.buildSuccessWindow.countInWindow(windowMs)
}

// GetBuildRejectCount returns the number of explicitly rejected tunnel builds within windowMs milliseconds.
// Maps to the Java I2P stat "tunnel.buildExploratoryReject".
func (tm *TunnelManager) GetBuildRejectCount(windowMs int64) float64 {
	return tm.buildRejectWindow.countInWindow(windowMs)
}

// GetBuildExpireCount returns the number of timed-out tunnel builds within windowMs milliseconds.
// Maps to the Java I2P stat "tunnel.buildExploratoryExpire".
func (tm *TunnelManager) GetBuildExpireCount(windowMs int64) float64 {
	return tm.buildExpireWindow.countInWindow(windowMs)
}

// GetBuildAvgTimeMs returns the average tunnel build time in milliseconds for builds completed
// within windowMs milliseconds. Maps to the Java I2P stat "tunnel.buildRequestTime".
// Returns 0 if no successful builds have been recorded in the window.
func (tm *TunnelManager) GetBuildAvgTimeMs(windowMs int64) float64 {
	return tm.buildTimeWindow.avgInWindow(windowMs)
}

// GetClientBuildSuccessCount returns the number of successful I2CP client session tunnel builds
// within windowMs milliseconds. Maps to the Java I2P stat "tunnel.buildClientSuccess".
func (tm *TunnelManager) GetClientBuildSuccessCount(windowMs int64) float64 {
	return tm.clientBuildSuccessWindow.countInWindow(windowMs)
}

// GetClientBuildRejectCount returns the number of explicitly rejected I2CP client session
// tunnel builds within windowMs milliseconds.
func (tm *TunnelManager) GetClientBuildRejectCount(windowMs int64) float64 {
	return tm.clientBuildRejectWindow.countInWindow(windowMs)
}

// GetClientBuildExpireCount returns the number of timed-out I2CP client session tunnel
// builds within windowMs milliseconds.
func (tm *TunnelManager) GetClientBuildExpireCount(windowMs int64) float64 {
	return tm.clientBuildExpireWindow.countInWindow(windowMs)
}

// chacha20XORRecord applies the I2P short-tunnel-build chained layer
// obfuscation to a single 218-byte STBM record using ChaCha20 as a raw
// stream cipher (no Poly1305). The nonce is 12 zero bytes with nonce[4]
// set to the record's index in the message — matching i2pd's
// ShortECIESTunnelHopConfig::DecryptRecord. Because ChaCha20 is a stream
// cipher, the same operation both applies and removes the layer.
func chacha20XORRecord(record *[ShortBuildRecordSize]byte, key [32]byte, index int) error {
	var nonce [12]byte
	nonce[4] = byte(index)
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return oops.Wrapf(err, "ChaCha20 init failed")
	}
	c.XORKeyStream(record[:], record[:])
	return nil
}
