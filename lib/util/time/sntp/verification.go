package sntp

import (
	"github.com/go-i2p/go-i2p/lib/util/logger"
	"time"

	"github.com/beevik/ntp"
)

var log = logger.GetGoI2PLogger()

func (rt *RouterTimestamper) validateResponse(response *ntp.Response) bool {
	// Check Leap Indicator
	if response.Leap == ntp.LeapNotInSync {
		log.Error("Invalid response: Server clock not synchronized (Leap Indicator)")
		return false
	}

	// Check Stratum Level
	if response.Stratum == 0 || response.Stratum > 15 {
		log.Errorf("Invalid response: Stratum level %d is out of valid range\n", response.Stratum)
		return false
	}

	// Round-Trip Delay and Clock Offset Sanity Checks
	if response.RTT < 0 || response.RTT > maxRTT {
		log.Errorf("Invalid response: Round-trip delay %v is out of bounds\n", response.RTT)
		return false
	}
	if absDuration(response.ClockOffset) > maxClockOffset {
		log.Errorf("Invalid response: Clock offset %v is out of bounds\n", response.ClockOffset)
		return false
	}

	// Non-zero Time
	if response.Time.IsZero() {
		log.Error("Invalid response: Received zero time")
		return false
	}

	// Root Dispersion and Root Delay
	if response.RootDispersion > maxRootDispersion {
		log.Errorf("Invalid response: Root dispersion %v is too high\n", response.RootDispersion)
		return false
	}
	if response.RootDelay > maxRootDelay {
		log.Errorf("Invalid response: Root delay %v is too high\n", response.RootDelay)
		return false
	}

	return true
}

const (
	maxRTT            = 2 * time.Second  // Max acceptable round-trip time
	maxClockOffset    = 10 * time.Second // Max acceptable clock offset
	maxRootDispersion = 1 * time.Second  // Max acceptable root dispersion
	maxRootDelay      = 1 * time.Second  // Maxi acceptable root delay
)
