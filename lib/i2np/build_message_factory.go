package i2np

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel/build"
	"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"
	"github.com/samber/oops"
)

// buildMessageFactory implements build.BuildMessageFactory for creating
// serialized I2NP tunnel build messages. This allows lib/tunnel/build
// to create messages without importing lib/i2np.
type buildMessageFactory struct{}

// NewBuildMessageFactory creates a new factory for tunnel build messages.
func NewBuildMessageFactory() build.BuildMessageFactory {
	return &buildMessageFactory{}
}

// createVariableBuildMessage is a generic helper for creating count-prefixed
// tunnel build messages. It computes total message size, marshals records, and
// creates an I2NP message of the given type. Used by CreateShortTunnelBuildMessage.
func (f *buildMessageFactory) createVariableBuildMessage(msgType int, typeName string, encryptedRecords [][]byte, messageID int) ([]byte, error) {
	// Calculate total size: 1 byte for count + all encrypted records
	totalSize := 1
	for _, rec := range encryptedRecords {
		totalSize += len(rec)
	}

	data := make([]byte, totalSize)
	data[0] = byte(len(encryptedRecords))

	// Copy encrypted records into the message
	offset := 1
	for _, rec := range encryptedRecords {
		copy(data[offset:], rec)
		offset += len(rec)
	}

	msg := NewBaseI2NPMessage(msgType)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	serialized, err := msg.MarshalBinary()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to marshal %s message (msgID %d)", typeName, messageID)
	}
	return serialized, nil
}

// CreateShortTunnelBuildMessage creates a serialized Short Tunnel Build message (type 25).
// Refactored for M-1: now delegates to createVariableBuildMessage.
func (f *buildMessageFactory) CreateShortTunnelBuildMessage(encryptedRecords [][]byte, messageID int) ([]byte, error) {
	return f.createVariableBuildMessage(I2NPMessageTypeShortTunnelBuild, "Short Tunnel Build (type 25)", encryptedRecords, messageID)
}

// buildSessionAdapter adapts I2NPTransportSession to build.BuildSession interface.
type buildSessionAdapter struct {
	session I2NPTransportSession
}

// newBuildSessionAdapter wraps an I2NPTransportSession to implement build.BuildSession.
func newBuildSessionAdapter(session I2NPTransportSession) build.BuildSession {
	return &buildSessionAdapter{session: session}
}

// Send implements build.BuildSession by unmarshaling bytes and calling QueueSendI2NP.
func (a *buildSessionAdapter) Send(data []byte) error {
	// Unmarshal the serialized message
	msg := &BaseI2NPMessage{}
	if err := msg.UnmarshalBinary(data); err != nil {
		return err
	}
	return a.session.QueueSendI2NP(msg)
}

// buildSessionProvider implements build.SessionProvider by wrapping SessionProvider.
type buildSessionProvider struct {
	sessionProvider SessionProvider
}

// NewBuildSessionProvider creates a build.BuildSessionProvider that wraps a SessionProvider.
func NewBuildSessionProvider(sp SessionProvider) build.BuildSessionProvider {
	return &buildSessionProvider{sessionProvider: sp}
}

// GetSessionByHash implements build.BuildSessionProvider by getting an I2NPTransportSession
// and wrapping it as a build.BuildSession.
func (p *buildSessionProvider) GetSessionByHash(hash common.Hash) (build.BuildSession, error) {
	session, err := p.sessionProvider.GetSessionByHash(hash)
	if err != nil {
		return nil, err
	}
	return newBuildSessionAdapter(session), nil
}

// replyProcessorAdapter adapts *ReplyProcessor to build.TunnelReplyProcessor interface.
type replyProcessorAdapter struct {
	replyProcessor *ReplyProcessor
}

// NewReplyProcessorAdapter wraps a ReplyProcessor to implement build.TunnelReplyProcessor.
func NewReplyProcessorAdapter(rp *ReplyProcessor) build.TunnelReplyProcessor {
	return &replyProcessorAdapter{replyProcessor: rp}
}

// RegisterPendingBuild implements build.TunnelReplyProcessor.
func (a *replyProcessorAdapter) RegisterPendingBuild(
	tunnelID buildrecord.TunnelID,
	replyKeys []session_key.SessionKey,
	replyIVs [][16]byte,
	isInbound bool,
	hopCount int,
) error {
	return a.replyProcessor.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, isInbound, hopCount)
}

// SetPendingBuildNoiseHashes implements build.TunnelReplyProcessor.
func (a *replyProcessorAdapter) SetPendingBuildNoiseHashes(tunnelID buildrecord.TunnelID, noiseHashes [][32]byte) error {
	return a.replyProcessor.SetPendingBuildNoiseHashes(tunnelID, noiseHashes)
}

// ProcessBuildReply implements build.TunnelReplyProcessor.
func (a *replyProcessorAdapter) ProcessBuildReply(handler build.TunnelReplyHandler, tunnelID buildrecord.TunnelID) error {
	return a.replyProcessor.ProcessBuildReply(handler, tunnelID)
}
