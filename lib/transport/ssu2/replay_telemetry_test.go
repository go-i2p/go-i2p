package ssu2

import (
	"testing"

	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
)

func newReplayTestTransport() *SSU2Transport {
	return &SSU2Transport{
		handler: NewDefaultHandler(),
		logger:  logger.WithField("component", "ssu2_test"),
	}
}

func TestCheckReplayToken_NilTokenDefersAndIncrementsTelemetry(t *testing.T) {
	tr := newReplayTestTransport()
	defer tr.handler.Close()

	assert.False(t, tr.checkReplayToken(nil, "127.0.0.1:12345"))
	assert.Equal(t, uint64(1), tr.GetReachabilityCounters().ReplayChecksDeferred)

	assert.False(t, tr.checkReplayToken(nil, "127.0.0.1:12345"))
	assert.Equal(t, uint64(2), tr.GetReachabilityCounters().ReplayChecksDeferred)
}

func TestCheckReplayToken_DuplicateTokenDetected(t *testing.T) {
	tr := newReplayTestTransport()
	defer tr.handler.Close()

	replayToken := []byte("duplicate-session-request-token")

	assert.False(t, tr.checkReplayToken(replayToken, "127.0.0.1:12345"), "first validated replay token should pass")
	assert.True(t, tr.checkReplayToken(replayToken, "127.0.0.1:12345"), "duplicate validated replay token should be rejected")
	assert.Equal(t, uint64(0), tr.GetReachabilityCounters().ReplayChecksDeferred, "validated replay tokens should not increment deferred counter")
}

func TestCheckReplayToken_DeferredThenValidated(t *testing.T) {
	tr := newReplayTestTransport()
	defer tr.handler.Close()

	assert.False(t, tr.checkReplayToken(nil, "127.0.0.1:12345"), "pre-validation path should defer replay check")

	replayToken := []byte("validated-after-deferral")
	assert.False(t, tr.checkReplayToken(replayToken, "127.0.0.1:12345"), "first validated token should pass")
	assert.True(t, tr.checkReplayToken(replayToken, "127.0.0.1:12345"), "second validated token should be detected as duplicate")
	assert.Equal(t, uint64(1), tr.GetReachabilityCounters().ReplayChecksDeferred)
}
