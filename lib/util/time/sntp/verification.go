package sntp

import (
	"time"

	"github.com/beevik/ntp"
	"github.com/go-i2p/logger"
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
		log.WithField("leap_indicator", response.Leap).Warn("Invalid NTP response: Server clock not synchronized")
		return false
	}
	if response.Stratum == 0 || response.Stratum > 15 {
		log.WithFields(logger.Fields{
			"stratum":     response.Stratum,
			"valid_range": "1-15",
		}).Warn("Invalid NTP response: Stratum level out of valid range")
		return false
	}
	return true
}

// validateTimingMetrics checks round-trip delay and clock offset against acceptable bounds.
func validateTimingMetrics(response *ntp.Response) bool {
	if response.RTT < 0 || response.RTT > maxRTT {
		log.WithFields(logger.Fields{
			"rtt":         response.RTT,
			"max_allowed": maxRTT,
		}).Warn("Invalid NTP response: Round-trip delay out of bounds")
		return false
	}
	if absDuration(response.ClockOffset) > maxClockOffset {
		log.WithFields(logger.Fields{
			"clock_offset": response.ClockOffset,
			"max_allowed":  maxClockOffset,
		}).Warn("Invalid NTP response: Clock offset out of bounds")
		return false
	}
	return true
}

// validateTimeValue ensures the response time is not zero.
func validateTimeValue(response *ntp.Response) bool {
	if response.Time.IsZero() {
		log.Warn("Invalid NTP response: Received zero time")
		return false
	}
	return true
}

// validateRootMetrics checks root dispersion and root delay against maximum thresholds.
func validateRootMetrics(response *ntp.Response) bool {
	if response.RootDispersion > maxRootDispersion {
		log.WithFields(logger.Fields{
			"root_dispersion": response.RootDispersion,
			"max_allowed":     maxRootDispersion,
		}).Warn("Invalid NTP response: Root dispersion too high")
		return false
	}
	if response.RootDelay > maxRootDelay {
		log.WithFields(logger.Fields{
			"root_delay":  response.RootDelay,
			"max_allowed": maxRootDelay,
		}).Warn("Invalid NTP response: Root delay too high")
		return false
	}
	return true
}

const (
	maxRTT            = 2 * time.Second  // Max acceptable round-trip time
	maxClockOffset    = 10 * time.Second // Max acceptable clock offset
	maxRootDispersion = 1 * time.Second  // Max acceptable root dispersion
	maxRootDelay      = 1 * time.Second  // Max acceptable root delay
)
