package netdb

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
)

func admissionTestHash(v byte) common.Hash {
	var h common.Hash
	h[0] = v
	return h
}

func TestAdmissionController_AllowsBelowCriticalPressure(t *testing.T) {
	controller := newAdmissionController(100, admissionConfig{
		window:      time.Hour,
		perSource:   2,
		trackedMax:  10,
		pressurePct: 80,
	})

	source := admissionTestHash(1)
	if !controller.AllowIntroduction(&source, admissionTestHash(2), 90) {
		t.Fatalf("expected first introduction to be allowed below critical pressure")
	}
	if !controller.AllowIntroduction(&source, admissionTestHash(3), 90) {
		t.Fatalf("expected second introduction to be allowed below critical pressure")
	}
	if !controller.AllowIntroduction(&source, admissionTestHash(4), 90) {
		t.Fatalf("expected per-source limit to stay relaxed below critical pressure")
	}
}

func TestAdmissionController_EnforcesPerSourceAtCriticalPressure(t *testing.T) {
	controller := newAdmissionController(100, admissionConfig{
		window:      time.Hour,
		perSource:   2,
		trackedMax:  10,
		pressurePct: 80,
	})

	source := admissionTestHash(11)
	if !controller.AllowIntroduction(&source, admissionTestHash(12), 95) {
		t.Fatalf("expected first introduction to be allowed at critical pressure")
	}
	if !controller.AllowIntroduction(&source, admissionTestHash(13), 95) {
		t.Fatalf("expected second introduction to be allowed at critical pressure")
	}
	if controller.AllowIntroduction(&source, admissionTestHash(14), 95) {
		t.Fatalf("expected third introduction to be rate limited at critical pressure")
	}
}

func TestAdmissionController_RejectsUnknownSourceAtCriticalPressure(t *testing.T) {
	controller := newAdmissionController(100, admissionConfig{
		window:      time.Hour,
		perSource:   2,
		trackedMax:  10,
		pressurePct: 80,
	})

	if controller.AllowIntroduction(nil, admissionTestHash(42), 95) {
		t.Fatalf("expected unknown source to be rejected at critical pressure")
	}
}
