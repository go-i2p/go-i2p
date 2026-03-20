package ssu2

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestNewDefaultHandler_NotNil(t *testing.T) {
	h := NewDefaultHandler()
	if h == nil {
		t.Fatal("NewDefaultHandler returned nil")
	}
}

func TestDefaultHandler_CheckReplay_First(t *testing.T) {
	h := NewDefaultHandler()
	var key [32]byte
	key[0] = 0xAB
	if h.CheckReplay(key) {
		t.Error("first occurrence should not be flagged as replay")
	}
}

func TestDefaultHandler_CheckReplay_Duplicate(t *testing.T) {
	h := NewDefaultHandler()
	var key [32]byte
	key[0] = 0xCD
	h.CheckReplay(key)
	if !h.CheckReplay(key) {
		t.Error("second occurrence of same key should be flagged as replay")
	}
}

func TestDefaultHandler_CheckReplay_DifferentKeys(t *testing.T) {
	h := NewDefaultHandler()
	var key1, key2 [32]byte
	key1[0] = 0x01
	key2[0] = 0x02
	h.CheckReplay(key1)
	if h.CheckReplay(key2) {
		t.Error("different key should not be flagged as replay")
	}
}

func TestDefaultHandler_ValidateTimestamp_Within60s(t *testing.T) {
	h := NewDefaultHandler()
	now := uint32(time.Now().Unix())
	if err := h.ValidateTimestamp(now); err != nil {
		t.Errorf("current timestamp should be valid: %v", err)
	}
}

func TestDefaultHandler_ValidateTimestamp_SlightSkew(t *testing.T) {
	h := NewDefaultHandler()
	past := uint32(time.Now().Unix()) - 30
	if err := h.ValidateTimestamp(past); err != nil {
		t.Errorf("30s skew should be within tolerance: %v", err)
	}
}

func TestDefaultHandler_ValidateTimestamp_TooOld(t *testing.T) {
	h := NewDefaultHandler()
	old := uint32(time.Now().Unix()) - uint32(math.Round(61))
	if err := h.ValidateTimestamp(old); err == nil {
		t.Error("61s skew should fail validation")
	}
}

func TestDefaultHandler_ValidateTimestamp_TooFar_Future(t *testing.T) {
	h := NewDefaultHandler()
	future := uint32(time.Now().Unix()) + 61
	if err := h.ValidateTimestamp(future); err == nil {
		t.Error("timestamp 61s in the future should fail validation")
	}
}

// TestDefaultHandler_Close verifies that Close resets the replay cache.
func TestDefaultHandler_Close(t *testing.T) {
	h := NewDefaultHandler()
	var key [32]byte
	key[0] = 0xAA
	h.CheckReplay(key)
	h.Close()
	// After Close, the map is reset so the same key is no longer seen.
	if h.CheckReplay(key) {
		t.Error("after Close, key should not be flagged as replay")
	}
}

// TestDefaultHandler_SendTermination sends a termination block over a loopback
// conn pair and verifies no error is returned.
func TestDefaultHandler_SendTermination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping loopback test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverConn, _ := loopbackPair(t, ctx)
	h := NewDefaultHandler()
	err := h.SendTermination(serverConn, 0x00)
	if err != nil {
		t.Errorf("SendTermination returned error: %v", err)
	}
}
