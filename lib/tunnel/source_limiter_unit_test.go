package tunnel

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/config"
)

// createTestSourceLimiter creates a SourceLimiter with specified test parameters.
func createTestSourceLimiter(maxPerMin, burstSize int, banDuration time.Duration) *SourceLimiter {
	cfg := config.TunnelDefaults{
		MaxBuildRequestsPerMinute: maxPerMin,
		BuildRequestBurstSize:     burstSize,
		SourceBanDuration:         banDuration,
	}
	return NewSourceLimiterWithConfig(cfg)
}

// createTestHash creates a test hash from an integer for testing.
func createTestHash(id int) common.Hash {
	var h common.Hash
	h[0] = byte(id)
	h[1] = byte(id >> 8)
	return h
}

// TestNewSourceLimiter verifies source limiter creation.
func TestNewSourceLimiter(t *testing.T) {
	sl := NewSourceLimiter()
	defer sl.Stop()

	if sl == nil {
		t.Fatal("NewSourceLimiter returned nil")
	}

	if sl.sources == nil {
		t.Error("sources map not initialized")
	}

	stats := sl.GetStats()
	if stats.TrackedSources != 0 {
		t.Errorf("expected 0 tracked sources, got %d", stats.TrackedSources)
	}
}

// TestNewSourceLimiterWithConfig verifies custom configuration.
func TestNewSourceLimiterWithConfig(t *testing.T) {
	sl := createTestSourceLimiter(20, 5, 10*time.Minute)
	defer sl.Stop()

	if sl.maxRequestsPerMinute != 20 {
		t.Errorf("expected maxRequestsPerMinute=20, got %d", sl.maxRequestsPerMinute)
	}
	if sl.burstSize != 5 {
		t.Errorf("expected burstSize=5, got %d", sl.burstSize)
	}
	if sl.banDuration != 10*time.Minute {
		t.Errorf("expected banDuration=10m, got %v", sl.banDuration)
	}
}

// TestSourceLimiter_AllowRequest_InitialBurst verifies initial burst is allowed.
func TestSourceLimiter_AllowRequest_InitialBurst(t *testing.T) {
	// Create limiter with burst size of 3
	sl := createTestSourceLimiter(10, 3, 5*time.Minute)
	defer sl.Stop()

	hash := createTestHash(1)

	// First 3 requests should be allowed (burst)
	for i := 0; i < 3; i++ {
		allowed, reason := sl.AllowRequest(hash)
		if !allowed {
			t.Errorf("request %d should be allowed, got rejected with reason: %s", i+1, reason)
		}
	}

	// 4th request should be rejected (burst exhausted, no time to replenish)
	allowed, reason := sl.AllowRequest(hash)
	if allowed {
		t.Error("4th request should be rejected after burst exhausted")
	}
	if reason != "rate_limit_exceeded" {
		t.Errorf("expected reason 'rate_limit_exceeded', got '%s'", reason)
	}
}

// TestSourceLimiter_AllowRequest_TokenReplenishment verifies tokens replenish over time.
func TestSourceLimiter_AllowRequest_TokenReplenishment(t *testing.T) {
	// 60 requests per minute = 1 per second
	sl := createTestSourceLimiter(60, 1, 5*time.Minute)
	defer sl.Stop()

	hash := createTestHash(2)

	// First request uses the burst token
	allowed, _ := sl.AllowRequest(hash)
	if !allowed {
		t.Error("first request should be allowed")
	}

	// Immediate second request should be rejected
	allowed, _ = sl.AllowRequest(hash)
	if allowed {
		t.Error("immediate second request should be rejected")
	}

	// Manually update the lastUpdate time to simulate time passing
	sl.mu.Lock()
	state := sl.sources[hash]
	state.lastUpdate = time.Now().Add(-2 * time.Second) // 2 seconds ago
	sl.mu.Unlock()

	// Now request should be allowed (2 seconds = 2 tokens at 60/min)
	allowed, _ = sl.AllowRequest(hash)
	if !allowed {
		t.Error("request after token replenishment should be allowed")
	}
}

// TestSourceLimiter_AllowRequest_MultipleSources verifies independent tracking per source.
func TestSourceLimiter_AllowRequest_MultipleSources(t *testing.T) {
	sl := createTestSourceLimiter(10, 2, 5*time.Minute)
	defer sl.Stop()

	hash1 := createTestHash(1)
	hash2 := createTestHash(2)

	// Exhaust hash1's burst
	sl.AllowRequest(hash1)
	sl.AllowRequest(hash1)
	allowed, _ := sl.AllowRequest(hash1)
	if allowed {
		t.Error("hash1's 3rd request should be rejected")
	}

	// hash2 should still have its full burst
	allowed, _ = sl.AllowRequest(hash2)
	if !allowed {
		t.Error("hash2's 1st request should be allowed")
	}
	allowed, _ = sl.AllowRequest(hash2)
	if !allowed {
		t.Error("hash2's 2nd request should be allowed")
	}

	stats := sl.GetStats()
	if stats.TrackedSources != 2 {
		t.Errorf("expected 2 tracked sources, got %d", stats.TrackedSources)
	}
}

// TestSourceLimiter_AutoBan verifies automatic banning after excessive rejections.
func TestSourceLimiter_AutoBan(t *testing.T) {
	sl := createTestSourceLimiter(10, 1, 5*time.Minute)
	defer sl.Stop()

	hash := createTestHash(3)

	// Use the single burst token
	sl.AllowRequest(hash)

	// Generate more than 10 rejections to trigger auto-ban
	for i := 0; i < 11; i++ {
		sl.AllowRequest(hash)
	}

	// Check that source is now banned
	if !sl.IsBanned(hash) {
		t.Error("source should be banned after >10 rejections")
	}

	// Next request should fail with "source_banned"
	allowed, reason := sl.AllowRequest(hash)
	if allowed {
		t.Error("request from banned source should be rejected")
	}
	if reason != "source_banned" {
		t.Errorf("expected reason 'source_banned', got '%s'", reason)
	}

	stats := sl.GetStats()
	if stats.BannedSources != 1 {
		t.Errorf("expected 1 banned source, got %d", stats.BannedSources)
	}
}

// TestSourceLimiter_BanExpiry verifies ban expires after duration.
func TestSourceLimiter_BanExpiry(t *testing.T) {
	sl := createTestSourceLimiter(10, 1, 1*time.Minute)
	defer sl.Stop()

	hash := createTestHash(4)

	// Use burst and trigger auto-ban
	sl.AllowRequest(hash)
	for i := 0; i < 11; i++ {
		sl.AllowRequest(hash)
	}

	if !sl.IsBanned(hash) {
		t.Error("source should be banned")
	}

	// Manually expire the ban
	sl.mu.Lock()
	state := sl.sources[hash]
	state.bannedUntil = time.Now().Add(-1 * time.Second) // Expired 1 second ago
	state.tokens = float64(sl.burstSize)                 // Reset tokens for test
	state.rejectCount = 0                                // Reset reject count
	sl.mu.Unlock()

	// Now requests should be allowed again
	if sl.IsBanned(hash) {
		t.Error("source ban should have expired")
	}

	allowed, reason := sl.AllowRequest(hash)
	if !allowed {
		t.Errorf("request after ban expiry should be allowed, got: %s", reason)
	}
}

// TestSourceLimiter_GetSourceStats verifies per-source statistics.
func TestSourceLimiter_GetSourceStats(t *testing.T) {
	sl := createTestSourceLimiter(10, 3, 5*time.Minute)
	defer sl.Stop()

	hash := createTestHash(5)

	// Unknown source should return nil
	stats := sl.GetSourceStats(hash)
	if stats != nil {
		t.Error("unknown source should return nil stats")
	}

	// Make some requests
	sl.AllowRequest(hash) // 1st allowed
	sl.AllowRequest(hash) // 2nd allowed
	sl.AllowRequest(hash) // 3rd allowed
	sl.AllowRequest(hash) // 4th rejected

	stats = sl.GetSourceStats(hash)
	if stats == nil {
		t.Fatal("expected stats for known source")
	}

	if stats.RequestCount != 4 {
		t.Errorf("expected RequestCount=4, got %d", stats.RequestCount)
	}
	if stats.RejectCount != 1 {
		t.Errorf("expected RejectCount=1, got %d", stats.RejectCount)
	}
	if stats.IsBanned {
		t.Error("source should not be banned yet")
	}
}

// TestSourceLimiter_Cleanup verifies stale entry cleanup.
func TestSourceLimiter_Cleanup(t *testing.T) {
	sl := createTestSourceLimiter(10, 3, 5*time.Minute)
	defer sl.Stop()

	hash1 := createTestHash(1)
	hash2 := createTestHash(2)

	// Create entries
	sl.AllowRequest(hash1)
	sl.AllowRequest(hash2)

	if sl.GetStats().TrackedSources != 2 {
		t.Error("expected 2 tracked sources")
	}

	// Make hash1 stale (last update > 10 minutes ago)
	sl.mu.Lock()
	sl.sources[hash1].lastUpdate = time.Now().Add(-15 * time.Minute)
	sl.mu.Unlock()

	// Trigger cleanup
	sl.cleanup()

	stats := sl.GetStats()
	if stats.TrackedSources != 1 {
		t.Errorf("expected 1 tracked source after cleanup, got %d", stats.TrackedSources)
	}

	// hash2 should still exist
	if sl.GetSourceStats(hash2) == nil {
		t.Error("hash2 should still be tracked")
	}
	// hash1 should be removed
	if sl.GetSourceStats(hash1) != nil {
		t.Error("hash1 should have been cleaned up")
	}
}

// TestSourceLimiter_CleanupPreservesBanned verifies banned sources aren't cleaned up.
func TestSourceLimiter_CleanupPreservesBanned(t *testing.T) {
	sl := createTestSourceLimiter(10, 1, 30*time.Minute)
	defer sl.Stop()

	hash := createTestHash(6)

	// Trigger ban
	sl.AllowRequest(hash)
	for i := 0; i < 11; i++ {
		sl.AllowRequest(hash)
	}

	// Make entry stale but still banned
	sl.mu.Lock()
	sl.sources[hash].lastUpdate = time.Now().Add(-15 * time.Minute)
	// Ban is still active (30 min duration)
	sl.mu.Unlock()

	// Trigger cleanup
	sl.cleanup()

	// Should still be tracked because it's banned
	if sl.GetSourceStats(hash) == nil {
		t.Error("banned source should not be cleaned up")
	}
}

// TestSourceLimiter_Stats verifies overall statistics.
func TestSourceLimiter_Stats(t *testing.T) {
	sl := createTestSourceLimiter(10, 2, 5*time.Minute)
	defer sl.Stop()

	hash1 := createTestHash(1)
	hash2 := createTestHash(2)

	// hash1: 2 allowed, 1 rejected
	sl.AllowRequest(hash1)
	sl.AllowRequest(hash1)
	sl.AllowRequest(hash1) // rejected

	// hash2: 2 allowed
	sl.AllowRequest(hash2)
	sl.AllowRequest(hash2)

	stats := sl.GetStats()
	if stats.TrackedSources != 2 {
		t.Errorf("expected 2 tracked sources, got %d", stats.TrackedSources)
	}
	if stats.TotalRequests != 5 {
		t.Errorf("expected 5 total requests, got %d", stats.TotalRequests)
	}
	if stats.TotalRejections != 1 {
		t.Errorf("expected 1 total rejection, got %d", stats.TotalRejections)
	}
	if stats.BannedSources != 0 {
		t.Errorf("expected 0 banned sources, got %d", stats.BannedSources)
	}
}

// TestSourceLimiter_Stop verifies graceful shutdown.
func TestSourceLimiter_Stop(t *testing.T) {
	sl := createTestSourceLimiter(10, 3, 5*time.Minute)

	hash := createTestHash(1)
	sl.AllowRequest(hash)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		sl.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Error("Stop() took too long")
	}
}

// TestProcessBuildRequest_Integration verifies ProcessBuildRequest with source limiting.
func TestProcessBuildRequest_Integration(t *testing.T) {
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    100,
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  true,
		MaxBuildRequestsPerMinute:  10,
		BuildRequestBurstSize:      2,
		SourceBanDuration:          5 * time.Minute,
	}

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	hash := createTestHash(1)

	// First 2 requests should be accepted (burst)
	for i := 0; i < 2; i++ {
		accepted, code, reason := m.ProcessBuildRequest(hash)
		if !accepted {
			t.Errorf("request %d should be accepted, got rejected: code=%d, reason=%s", i+1, code, reason)
		}
		if code != 0 {
			t.Errorf("expected code 0 for accepted request, got %d", code)
		}
	}

	// 3rd request should be rejected due to rate limit
	accepted, code, reason := m.ProcessBuildRequest(hash)
	if accepted {
		t.Error("3rd request should be rejected due to rate limit")
	}
	if code != BuildReplyCodeBandwidth {
		t.Errorf("expected code %d (bandwidth), got %d", BuildReplyCodeBandwidth, code)
	}
	if reason != "rate_limit_exceeded" {
		t.Errorf("expected reason 'rate_limit_exceeded', got '%s'", reason)
	}
}

// TestProcessBuildRequest_GlobalLimitFirst verifies global limit checked before source limit.
func TestProcessBuildRequest_GlobalLimitFirst(t *testing.T) {
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    1, // Very low limit
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  true,
		MaxBuildRequestsPerMinute:  10,
		BuildRequestBurstSize:      5,
		SourceBanDuration:          5 * time.Minute,
	}

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add a participant to hit the limit
	p, _ := NewParticipant(12345, &mockTunnelEncryptor{})
	m.AddParticipant(p)

	hash := createTestHash(1)

	// Request should be rejected due to global limit (not rate limit)
	accepted, code, reason := m.ProcessBuildRequest(hash)
	if accepted {
		t.Error("request should be rejected due to global limit")
	}
	if code != BuildReplyCodeBandwidth {
		t.Errorf("expected code %d (bandwidth), got %d", BuildReplyCodeBandwidth, code)
	}
	if reason != "hard_limit_reached" {
		t.Errorf("expected reason 'hard_limit_reached', got '%s'", reason)
	}
}

// TestGetLimitStats_WithSourceLimiter verifies comprehensive stats.
func TestGetLimitStats_WithSourceLimiter(t *testing.T) {
	cfg := config.TunnelDefaults{
		MaxParticipatingTunnels:    100,
		ParticipatingLimitsEnabled: true,
		PerSourceRateLimitEnabled:  true,
		MaxBuildRequestsPerMinute:  10,
		BuildRequestBurstSize:      2,
		SourceBanDuration:          5 * time.Minute,
	}

	m := NewManagerWithConfig(cfg)
	defer m.Stop()

	// Add a participant
	p, _ := NewParticipant(12345, &mockTunnelEncryptor{})
	m.AddParticipant(p)

	// Make some build requests
	hash := createTestHash(1)
	m.ProcessBuildRequest(hash)
	m.ProcessBuildRequest(hash)
	m.ProcessBuildRequest(hash) // This one gets rejected

	stats := m.GetLimitStats()

	if stats.CurrentParticipants != 1 {
		t.Errorf("expected 1 participant, got %d", stats.CurrentParticipants)
	}
	if stats.MaxParticipants != 100 {
		t.Errorf("expected max 100, got %d", stats.MaxParticipants)
	}
	if stats.SoftLimitParticipants != 50 {
		t.Errorf("expected soft limit 50, got %d", stats.SoftLimitParticipants)
	}
	if stats.AtSoftLimit {
		t.Error("should not be at soft limit with 1 participant")
	}
	if stats.AtHardLimit {
		t.Error("should not be at hard limit with 1 participant")
	}
	if stats.SourceLimiter == nil {
		t.Fatal("expected source limiter stats")
	}
	if stats.SourceLimiter.TrackedSources != 1 {
		t.Errorf("expected 1 tracked source, got %d", stats.SourceLimiter.TrackedSources)
	}
	if stats.SourceLimiter.TotalRequests != 3 {
		t.Errorf("expected 3 total requests, got %d", stats.SourceLimiter.TotalRequests)
	}
	if stats.SourceLimiter.TotalRejections != 1 {
		t.Errorf("expected 1 rejection, got %d", stats.SourceLimiter.TotalRejections)
	}
}
