package sntp

import (
	"fmt"
	"time"

	"github.com/beevik/ntp"
)

// validateResponse validates the SNTP response against multiple criteria including
// leap indicator, stratum level, timing metrics, time value, and root metrics.
func (rt *RouterTimestamper) validateResponse(response *ntp.Response) bool {
	if !validateLeapAndStratum(response) {
		return false
	}
	if !validateTimingMetrics(response) {
		return false
	}
	if !validateTimeValue(response) {
		return false
	}
	if !validateRootMetrics(response) {
		return false
	}
	return true
}

// validateLeapAndStratum checks the leap indicator and stratum level of the response.
func validateLeapAndStratum(response *ntp.Response) bool {
	if response.Leap == ntp.LeapNotInSync {
		fmt.Println("Invalid response: Server clock not synchronized (Leap Indicator)")
		return false
	}
	if response.Stratum == 0 || response.Stratum > 15 {
		fmt.Printf("Invalid response: Stratum level %d is out of valid range\n", response.Stratum)
		return false
	}
	return true
}

// validateTimingMetrics checks round-trip delay and clock offset against acceptable bounds.
func validateTimingMetrics(response *ntp.Response) bool {
	if response.RTT < 0 || response.RTT > maxRTT {
		fmt.Printf("Invalid response: Round-trip delay %v is out of bounds\n", response.RTT)
		return false
	}
	if absDuration(response.ClockOffset) > maxClockOffset {
		fmt.Printf("Invalid response: Clock offset %v is out of bounds\n", response.ClockOffset)
		return false
	}
	return true
}

// validateTimeValue ensures the response time is not zero.
func validateTimeValue(response *ntp.Response) bool {
	if response.Time.IsZero() {
		fmt.Println("Invalid response: Received zero time")
		return false
	}
	return true
}

// validateRootMetrics checks root dispersion and root delay against maximum thresholds.
func validateRootMetrics(response *ntp.Response) bool {
	if response.RootDispersion > maxRootDispersion {
		fmt.Printf("Invalid response: Root dispersion %v is too high\n", response.RootDispersion)
		return false
	}
	if response.RootDelay > maxRootDelay {
		fmt.Printf("Invalid response: Root delay %v is too high\n", response.RootDelay)
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
