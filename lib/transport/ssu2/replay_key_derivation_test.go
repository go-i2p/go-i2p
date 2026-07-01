package ssu2

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplayTokenToReplayKey_UsesDirectBytesFor32ByteToken(t *testing.T) {
	token := make([]byte, 32)
	token[0] = 0xAB
	token[31] = 0xCD

	got := replayTokenToReplayKey(token)

	var want [32]byte
	copy(want[:], token)
	assert.Equal(t, want, got, "32-byte replay token should map directly")
}

func TestReplayTokenToReplayKey_HashesNon32ByteToken(t *testing.T) {
	token := []byte("short-token")

	got := replayTokenToReplayKey(token)
	want := sha256.Sum256(token)

	assert.Equal(t, want, got, "non-32-byte replay token should be hashed")
}
