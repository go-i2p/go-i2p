package netdb

import (
	"testing"

	common "github.com/go-i2p/common/data"
)

func TestRouterInfoAdmissionController_NilSourceAllowedUntilPressure(t *testing.T) {
	c := newRouterInfoAdmissionController(100)
	var key common.Hash
	key[0] = 0x01

	if !c.AllowIntroduction(nil, key, 79) {
		t.Fatal("expected nil-source introduction to be allowed below pressure threshold")
	}
	if c.AllowIntroduction(nil, key, 80) {
		t.Fatal("expected nil-source introduction to be rejected at pressure threshold")
	}
}

func TestRouterInfoAdmissionController_PerSourceDistinctLimit(t *testing.T) {
	c := newRouterInfoAdmissionController(100)
	var source common.Hash
	source[0] = 0xCC

	for i := 0; i < routerInfoPerSourceIntroduced; i++ {
		var key common.Hash
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		if !c.AllowIntroduction(&source, key, 95) {
			t.Fatalf("unexpected reject at introduction %d", i)
		}
	}

	var overflow common.Hash
	overflow[0] = 0xFE
	overflow[1] = 0xED
	if c.AllowIntroduction(&source, overflow, 95) {
		t.Fatal("expected rejection after per-source distinct-introduction limit")
	}
}
