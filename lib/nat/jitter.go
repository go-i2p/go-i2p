package nat

import (
	"crypto/rand"
	"time"

	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// applyJitter applies ±25% jitter to baseDelay using crypto/rand.
// Returns baseDelay unchanged if crypto/rand fails (logs warning).
//
// Jitter calculation: [0.75, 1.25] * baseDelay
// Example: 50ms base → [37.5ms, 62.5ms]
//
// Thread-safe: crypto/rand is goroutine-safe.
func applyJitter(baseDelay time.Duration) time.Duration {
	jitterBytes := make([]byte, 2)
	if _, randErr := rand.Read(jitterBytes); randErr == nil {
		// Convert 2 random bytes to float64 in [0, 1)
		randVal := float64(uint16(jitterBytes[0])<<8|uint16(jitterBytes[1])) / 65536.0
		jitterFactor := 0.75 + (randVal * 0.5) // [0.75, 1.25]
		return time.Duration(float64(baseDelay) * jitterFactor)
	} else {
		log.WithError(randErr).Warn("Failed to generate jitter; using base delay")
	}
	return baseDelay
}
