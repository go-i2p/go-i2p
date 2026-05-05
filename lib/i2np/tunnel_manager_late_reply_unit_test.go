package i2np

import (
	"errors"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
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
	before := SnapshotExploratoryReplyStages()[ExploratoryReplyStageLateReplyShortSkipped]

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
	assert.Equal(t, before+1, SnapshotExploratoryReplyStages()[ExploratoryReplyStageLateReplyShortSkipped])
}
