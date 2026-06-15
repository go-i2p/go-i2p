package i2np

import (
	"errors"
	"testing"
	"time"

	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

type uncorrelatedReplyHandlerStub struct {
	err error
}

func (s *uncorrelatedReplyHandlerStub) GetReplyRecords() []BuildResponseRecord {
	return []BuildResponseRecord{{Reply: TunnelBuildReplyReject}}
}

func (s *uncorrelatedReplyHandlerStub) GetRawReplyRecords() [][]byte {
	return nil
}

func (s *uncorrelatedReplyHandlerStub) ProcessReply() error {
	return s.err
}

func TestProcessUncorrelatedReply_NonLatePreservesError(t *testing.T) {
	tm := NewTunnelManager(&SimpleMockPeerSelector{})
	h := &uncorrelatedReplyHandlerStub{err: errors.New("rejected")}

	err := tm.processUncorrelatedReply(h, 1001, h.GetReplyRecords())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rejected")
}

func TestProcessUncorrelatedReply_LateVTBReclassifiesExpireToReject(t *testing.T) {
	tm := NewTunnelManager(&SimpleMockPeerSelector{})
	windowMs := int64((10 * time.Minute).Milliseconds())

	// Simulate previously-accounted expiration for this message.
	tm.buildExpireWindow.recordEvent()
	tm.buildMutex.Lock()
	tm.expiredBuilds[2002] = expiredBuild{
		req:       &buildRequest{tunnelID: tunnel.TunnelID(42), isClientTunnel: false, useShortBuild: false},
		expiredAt: time.Now(),
	}
	tm.buildMutex.Unlock()

	h := &uncorrelatedReplyHandlerStub{err: errors.New("late reject")}
	err := tm.processUncorrelatedReply(h, 2002, h.GetReplyRecords())
	assert.NoError(t, err, "late-reply path should account and not bubble errors")

	assert.Equal(t, float64(0), tm.GetBuildExpireCount(windowMs))
	assert.Equal(t, float64(1), tm.GetBuildRejectCount(windowMs))
}

func TestProcessUncorrelatedReply_LateShortBuildSkipped(t *testing.T) {
	tm := NewTunnelManager(&SimpleMockPeerSelector{})
	windowMs := int64((10 * time.Minute).Milliseconds())
	before := SnapshotExploratoryReplyStages()["late_reply_short_build_skipped"]

	// Simulate previously-accounted expiration for a short build.
	tm.buildExpireWindow.recordEvent()
	tm.buildMutex.Lock()
	tm.expiredBuilds[3003] = expiredBuild{
		req:       &buildRequest{tunnelID: tunnel.TunnelID(99), isClientTunnel: false, useShortBuild: true},
		expiredAt: time.Now(),
	}
	tm.buildMutex.Unlock()

	h := &uncorrelatedReplyHandlerStub{err: errors.New("would fail if processed")}
	err := tm.processUncorrelatedReply(h, 3003, h.GetReplyRecords())
	assert.NoError(t, err)

	// Expiration remains unchanged for skipped late STBM classification.
	assert.Equal(t, float64(1), tm.GetBuildExpireCount(windowMs))
	assert.Equal(t, before+1, SnapshotExploratoryReplyStages()["late_reply_short_build_skipped"])
}

func TestProcessUncorrelatedReply_LateShortBuildBestEffortDecryptReclassifies(t *testing.T) {
	tm := NewTunnelManager(&SimpleMockPeerSelector{})
	windowMs := int64((10 * time.Minute).Milliseconds())
	before := SnapshotExploratoryReplyStages()["late_reply_reclassified_success"]

	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	var noiseHash [32]byte
	for i := range noiseHash {
		noiseHash[i] = byte(100 + i)
	}

	encrypted := makeEncryptedSTBMReplySlotForTest(t, key, noiseHash, 0, TunnelBuildReplySuccess)
	handler := &ShortTunnelBuildReply{
		Count:                1,
		BuildResponseRecords: []BuildResponseRecord{{Reply: TunnelBuildReplyReject}},
		RawRecordData:        [][]byte{encrypted},
	}

	// Simulate previously-accounted expiration for this short build.
	tm.buildExpireWindow.recordEvent()
	tm.buildMutex.Lock()
	tm.expiredBuilds[4004] = expiredBuild{
		req: &buildRequest{
			tunnelID:       tunnel.TunnelID(77),
			isClientTunnel: false,
			useShortBuild:  true,
			hopCount:       1,
			replyKeys:      []session_key.SessionKey{session_key.SessionKey(key)},
			replyIVs:       [][16]byte{{}},
			noiseHashes:    [][32]byte{noiseHash},
		},
		expiredAt: time.Now(),
	}
	tm.buildMutex.Unlock()

	err := tm.processUncorrelatedReply(handler, 4004, handler.GetReplyRecords())
	assert.NoError(t, err)

	assert.Equal(t, float64(0), tm.GetBuildExpireCount(windowMs))
	assert.Equal(t, float64(1), tm.GetBuildSuccessCount(windowMs))
	assert.Equal(t, before+1, SnapshotExploratoryReplyStages()["late_reply_reclassified_success"])
}

func makeEncryptedSTBMReplySlotForTest(t *testing.T, key, noiseHash [32]byte, index int, reply byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatalf("failed to init AEAD: %v", err)
	}
	var cleartext [ShortBuildRecordSize - chacha20poly1305.Overhead]byte
	cleartext[201] = reply
	var nonce [12]byte
	nonce[4] = byte(index)
	encrypted := aead.Seal(nil, nonce[:], cleartext[:], noiseHash[:])
	if len(encrypted) != ShortBuildRecordSize {
		t.Fatalf("unexpected encrypted slot size: got %d want %d", len(encrypted), ShortBuildRecordSize)
	}
	return encrypted
}
