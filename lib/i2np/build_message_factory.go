package i2np

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel/build"
)

// buildMessageFactory implements build.BuildMessageFactory for creating
// serialized I2NP tunnel build messages. This allows lib/tunnel/build
// to create messages without importing lib/i2np.
type buildMessageFactory struct{}

// NewBuildMessageFactory creates a new factory for tunnel build messages.
func NewBuildMessageFactory() build.BuildMessageFactory {
	return &buildMessageFactory{}
}

// CreateShortTunnelBuildMessage creates a serialized Short Tunnel Build message (type 25).
func (f *buildMessageFactory) CreateShortTunnelBuildMessage(encryptedRecords [][]byte, messageID int) []byte {
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

	msg := NewBaseI2NPMessage(I2NPMessageTypeShortTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	serialized, _ := msg.MarshalBinary()
	return serialized
}

// CreateVariableTunnelBuildMessage creates a serialized Variable Tunnel Build message (type 23).
func (f *buildMessageFactory) CreateVariableTunnelBuildMessage(encryptedRecords [][]byte, messageID int) []byte {
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

	msg := NewBaseI2NPMessage(I2NPMessageTypeVariableTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	serialized, _ := msg.MarshalBinary()
	return serialized
}

// CreateTunnelBuildMessage creates a serialized Tunnel Build message (type 21).
// Must have exactly 8 records of 528 bytes each, with NO count prefix byte.
func (f *buildMessageFactory) CreateTunnelBuildMessage(encryptedRecords [][]byte, messageID int) []byte {
	// Type 21 has exactly 8 records at 528 bytes each with NO count prefix
	const expectedRecordSize = 528
	totalSize := len(encryptedRecords) * expectedRecordSize

	data := make([]byte, totalSize)

	// Copy encrypted records into the message (no count prefix for type 21)
	offset := 0
	for _, rec := range encryptedRecords {
		copy(data[offset:], rec)
		offset += len(rec)
	}

	msg := NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(data)

	serialized, _ := msg.MarshalBinary()
	return serialized
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
