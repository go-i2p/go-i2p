// Tests for replay key derivation. Verifies that replayTokenToReplayKey
// derives a stable 32-byte key from a replay token, as required for
// replay protection of SSU2 messages.

package ssu2

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A 32-byte replay token is used directly as the replay key.
func TestReplayTokenToReplayKey_UsesDirectBytesFor32ByteToken(t *testing.T) {
	token := make([]byte, 32)
	token[0] = 0xAB
	token[31] = 0xCD

	got := replayTokenToReplayKey(token)

	var want [32]byte
	copy(want[:], token)
	assert.Equal(t, want, got, "32-byte replay token should map directly")
}

// A token that is not 32 bytes is hashed with SHA-256 to form the replay key.
func TestReplayTokenToReplayKey_HashesNon32ByteToken(t *testing.T) {
	token := []byte("short-token")

	got := replayTokenToReplayKey(token)
	want := sha256.Sum256(token)

	assert.Equal(t, want, got, "non-32-byte replay token should be hashed")
}
