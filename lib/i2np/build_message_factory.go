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

// NewBuildMessageFactory creates a new factory for serialized I2NP tunnel
// build messages. The factory lets the lib/tunnel/build package create
// wire-format messages without importing lib/i2p directly, keeping the
// build logic decoupled from the transport layer.
// See also [I2NPMessageTypeShortTunnelBuild].
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

// CreateShortTunnelBuildMessage creates a serialized Short Tunnel Build
// message (type 25). The message carries a count-prefixed list of encrypted
// build records, one per hop in the tunnel chain.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the wire format.
// See also [ShortTunnelBuild].
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

// Send implements build.BuildSession by unmarshaling the serialized I2NP
// message and queuing it on the underlying transport session. This is the
// bridge that lets the tunnel build package send messages without knowing
// about I2NP framing.
// See also [I2NPTransportSession].
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

// NewBuildSessionProvider creates a build.BuildSessionProvider that wraps
// an I2NP SessionProvider. This adapter lets the tunnel build package look
// up transport sessions by router hash without importing lib/i2np.
// See also [SessionProvider].
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

// NewReplyProcessorAdapter wraps a ReplyProcessor to implement the
// build.TunnelReplyProcessor interface. This lets the tunnel build package
// register pending builds and process replies without importing lib/i2np.
// See also [ReplyProcessor].
func NewReplyProcessorAdapter(rp *ReplyProcessor) build.TunnelReplyProcessor {
	return &replyProcessorAdapter{replyProcessor: rp}
}

// RegisterPendingBuild implements build.TunnelReplyProcessor by delegating
// to the wrapped ReplyProcessor. It records the reply keys and IVs for a
// tunnel build so that incoming replies can be decrypted and matched.
func (a *replyProcessorAdapter) RegisterPendingBuild(
	tunnelID buildrecord.TunnelID,
	replyKeys []session_key.SessionKey,
	replyIVs [][16]byte,
	isInbound bool,
	hopCount int,
) error {
	return a.replyProcessor.RegisterPendingBuild(tunnelID, replyKeys, replyIVs, isInbound, hopCount)
}

// SetPendingBuildNoiseHashes implements build.TunnelReplyProcessor by
// delegating to the wrapped ReplyProcessor. It stores the Noise protocol
// hash values for a pending build so that STBM replies can be verified.
func (a *replyProcessorAdapter) SetPendingBuildNoiseHashes(tunnelID buildrecord.TunnelID, noiseHashes [][32]byte) error {
	return a.replyProcessor.SetPendingBuildNoiseHashes(tunnelID, noiseHashes)
}

// ProcessBuildReply implements build.TunnelReplyProcessor by delegating to
// the wrapped ReplyProcessor. It decrypts and dispatches a tunnel build
// reply to the given handler.
func (a *replyProcessorAdapter) ProcessBuildReply(handler build.TunnelReplyHandler, tunnelID buildrecord.TunnelID) error {
	return a.replyProcessor.ProcessBuildReply(handler, tunnelID)
}
