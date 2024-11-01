package sntp

import (
	"github.com/beevik/ntp"
	"testing"
	"time"
)

func TestValidateResponse(t *testing.T) {
	rt := &RouterTimestamper{}

	// Valid response
	validResponse := &ntp.Response{
		Leap:           ntp.LeapNoWarning,
		Stratum:        2,
		RTT:            50 * time.Millisecond,
		ClockOffset:    100 * time.Millisecond,
		Time:           time.Now(),
		RootDispersion: 500 * time.Millisecond,
		RootDelay:      10 * time.Millisecond,
		KissCode:       "",
	}

	if !rt.validateResponse(validResponse) {
		t.Error("Expected valid response to pass validation")
	}

	// Invalid Leap Indicator
	invalidLeapResponse := *validResponse
	invalidLeapResponse.Leap = ntp.LeapNotInSync
	if rt.validateResponse(&invalidLeapResponse) {
		t.Error("Expected response with invalid leap indicator to fail validation")
	}

	// Invalid Stratum
	invalidStratumResponse := *validResponse
	invalidStratumResponse.Stratum = 0
	if rt.validateResponse(&invalidStratumResponse) {
		t.Error("Expected response with invalid stratum to fail validation")
	}

	// High Root Dispersion
	highRootDispersionResponse := *validResponse
	highRootDispersionResponse.RootDispersion = 2 * time.Second
	if rt.validateResponse(&highRootDispersionResponse) {
		t.Error("Expected response with high root dispersion to fail validation")
	}
}
