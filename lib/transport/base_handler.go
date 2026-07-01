package transport

import (
	"fmt"

	gonoise "github.com/go-i2p/go-noise/ntcp2"
)

// BaseHandler provides shared replay cache functionality for NTCP2 and SSU2 handlers.
// It encapsulates the common logic for checking replayed ephemeral keys, closing the
// cache, and querying cache size. Protocol-specific handlers embed this struct and
// implement their own ValidateTimestamp and SendTermination methods.
type BaseHandler struct {
	replayCache *gonoise.ReplayCache
}

// NewBaseHandler creates a new BaseHandler with a fresh replay cache.
// It is used by both NTCP2 and SSU2 DefaultHandlers.
func NewBaseHandler() *BaseHandler {
	return &BaseHandler{
		replayCache: gonoise.NewReplayCache(),
	}
}

// CheckReplay checks whether an ephemeral key has been seen before using the
// shared replay cache. Returns true if the key is a duplicate (replay attack).
func (h *BaseHandler) CheckReplay(ephemeralKey [32]byte) bool {
	if h.replayCache.CheckAndAdd(ephemeralKey) {
		logAt("(BaseHandler) CheckReplay").WithFields(map[string]interface{}{
			"reason":        "replay_detected",
			"phase":         "handshake",
			"key_prefix":    fmt.Sprintf("%x", ephemeralKey[:4]),
			"cache_size":    h.replayCache.Size(),
			"session_state": "pre_auth",
		}).Warn("replay attack detected: duplicate ephemeral key")
		return true
	}
	return false
}

// Close releases resources held by the handler (stops replay cache cleanup).
func (h *BaseHandler) Close() {
	if h.replayCache != nil {
		h.replayCache.Close()
	}
}

// ReplayCacheSize returns the current number of entries in the replay cache.
// Useful for monitoring and diagnostics.
func (h *BaseHandler) ReplayCacheSize() int {
	if h.replayCache == nil {
		return 0
	}
	return h.replayCache.Size()
}
