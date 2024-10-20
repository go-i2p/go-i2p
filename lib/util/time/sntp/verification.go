package sntp

import (
	"fmt"
	"github.com/beevik/ntp"
	"time"
)

func (rt *RouterTimestamper) validateResponse(response *ntp.Response) bool {
	// Check Leap Indicator
	if response.Leap == ntp.LeapNotInSync {
		fmt.Println("Invalid response: Server clock not synchronized (Leap Indicator)")
		return false
	}

	// Check Stratum Level
	if response.Stratum == 0 || response.Stratum > 15 {
		fmt.Printf("Invalid response: Stratum level %d is out of valid range\n", response.Stratum)
		return false
	}

	// Round-Trip Delay and Clock Offset Sanity Checks
	if response.RTT < 0 || response.RTT > maxRTT {
		fmt.Printf("Invalid response: Round-trip delay %v is out of bounds\n", response.RTT)
		return false
	}
	if absDuration(response.ClockOffset) > maxClockOffset {
		fmt.Printf("Invalid response: Clock offset %v is out of bounds\n", response.ClockOffset)
		return false
	}

	// Non-zero Time
	if response.Time.IsZero() {
		fmt.Println("Invalid response: Received zero time")
		return false
	}

	// Root Dispersion and Root Delay
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
