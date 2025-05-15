package ntcp

import (
	"time"

	"github.com/samber/oops"
)

// Add this method to NTCP2Session
// ValidateTimestamp validates a timestamp is within acceptable range
func (s *NTCP2Session) ValidateTimestamp(timestamp time.Time) error {
	if timestamp.IsZero() {
		return oops.Errorf("missing timestamp in options")
	}

	now := time.Now()
	if s.RouterTimestamper != nil {
		now = s.RouterTimestamper.GetCurrentTime()
	}

	delta := timestamp.Sub(now)
	if delta < -60*time.Second || delta > 60*time.Second {
		return oops.Errorf("timestamp out of acceptable range: %v (delta: %v)", timestamp, delta)
	}

	return nil
}
