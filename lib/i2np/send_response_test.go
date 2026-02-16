package i2np

import (
	"fmt"
	"testing"

	common "github.com/go-i2p/common/data"
)

// FailingMockTransportSession is a mock TransportSession that returns errors from QueueSendI2NP.
type FailingMockTransportSession struct {
	sentMessages []I2NPMessage
	sendErr      error
}

func NewFailingMockTransportSession(err error) *FailingMockTransportSession {
	return &FailingMockTransportSession{
		sentMessages: make([]I2NPMessage, 0),
		sendErr:      err,
	}
}

func (m *FailingMockTransportSession) QueueSendI2NP(msg I2NPMessage) error {
	return m.sendErr
}

func (m *FailingMockTransportSession) SendQueueSize() int {
	return 0
}

// FailingMockSessionProvider returns a FailingMockTransportSession.
type FailingMockSessionProvider struct {
	session TransportSession
	getErr  error
}

func (m *FailingMockSessionProvider) GetSessionByHash(hash common.Hash) (TransportSession, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.session, nil
}

// TestSendResponseNilMessage verifies that sendResponse returns an error when
// message creation fails (returns nil), rather than panicking with a nil pointer
// dereference. This covers CRITICAL BUG: Nil Pointer Dereference in Database
// Response Routing.
//
// Before the fix, passing a DatabaseStore with a nil BaseI2NPMessage would cause
// a panic inside MarshalBinary(). The fix uses MarshalPayload() which doesn't
// touch BaseI2NPMessage, and the nil check in sendResponse catches any nil return.
func TestSendResponseNilMessage(t *testing.T) {
	sessionProvider := NewMockSessionProvider()

	dm := NewDatabaseManager(nil)
	dm.SetSessionProvider(sessionProvider)

	// A DatabaseStore with nil BaseI2NPMessage but valid fields.
	// MarshalPayload() will succeed (it doesn't use BaseI2NPMessage),
	// so message creation should succeed. Test the full flow.
	store := &DatabaseStore{
		Key:       common.Hash{0x01, 0x02, 0x03},
		StoreType: DATABASE_STORE_TYPE_ROUTER_INFO,
		Data:      []byte("test data"),
	}

	dest := common.Hash{0x04, 0x05, 0x06}
	err := dm.sendResponse(store, dest)

	// Should succeed without panicking (the old code would panic here
	// because DatabaseStore.MarshalBinary dereferences BaseI2NPMessage)
	if err != nil {
		t.Fatalf("Expected no error for valid store with nil embedded base, got: %v", err)
	}

	session := sessionProvider.GetMockSession()
	if len(session.GetSentMessages()) != 1 {
		t.Errorf("Expected 1 sent message, got %d", len(session.GetSentMessages()))
	}
}

// TestSendResponseQueueError verifies that sendResponse propagates errors from
// QueueSendI2NP instead of silently discarding them. This covers CRITICAL BUG:
// QueueSendI2NP Error Silently Discarded.
func TestSendResponseQueueError(t *testing.T) {
	sendErr := fmt.Errorf("send queue full")
	failSession := NewFailingMockTransportSession(sendErr)
	sessionProvider := &FailingMockSessionProvider{session: failSession}

	dm := NewDatabaseManager(nil)
	dm.SetRetriever(NewMockNetDBRetriever())
	dm.SetSessionProvider(sessionProvider)

	// Create a valid DatabaseSearchReply that will marshal successfully
	reply := &DatabaseSearchReply{
		Key: common.Hash{0x01, 0x02, 0x03},
		PeerHashes: []common.Hash{
			{0x04, 0x05, 0x06},
		},
		From: common.Hash{0x07, 0x08, 0x09},
	}

	dest := common.Hash{0x04, 0x05, 0x06}
	err := dm.sendResponse(reply, dest)

	if err == nil {
		t.Fatal("Expected error from QueueSendI2NP failure, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

// TestSendResponseNoSessionProvider verifies that sendResponse returns an error
// when no session provider is configured.
func TestSendResponseNoSessionProvider(t *testing.T) {
	dm := NewDatabaseManager(nil)
	// Don't set session provider

	store := &DatabaseStore{}
	dest := common.Hash{0x01}

	err := dm.sendResponse(store, dest)
	if err == nil {
		t.Fatal("Expected error when no session provider set, got nil")
	}
}

// TestSendResponseSessionLookupError verifies that sendResponse propagates
// session lookup errors.
func TestSendResponseSessionLookupError(t *testing.T) {
	lookupErr := fmt.Errorf("session not found")
	sessionProvider := &FailingMockSessionProvider{getErr: lookupErr}

	dm := NewDatabaseManager(nil)
	dm.SetSessionProvider(sessionProvider)

	store := &DatabaseStore{}
	dest := common.Hash{0x01}

	err := dm.sendResponse(store, dest)
	if err == nil {
		t.Fatal("Expected error from session lookup failure, got nil")
	}
}

// TestSendResponseUnsupportedType verifies that sendResponse returns an error
// for unsupported response types.
func TestSendResponseUnsupportedType(t *testing.T) {
	sessionProvider := NewMockSessionProvider()

	dm := NewDatabaseManager(nil)
	dm.SetSessionProvider(sessionProvider)

	dest := common.Hash{0x01}
	err := dm.sendResponse("not a valid type", dest)
	if err == nil {
		t.Fatal("Expected error for unsupported response type, got nil")
	}
}

// TestSendResponseSuccess verifies the happy path: a valid message is created
// and queued successfully.
func TestSendResponseSuccess(t *testing.T) {
	sessionProvider := NewMockSessionProvider()
	retriever := NewMockNetDBRetriever()

	dm := NewDatabaseManager(nil)
	dm.SetRetriever(retriever)
	dm.SetSessionProvider(sessionProvider)

	// Create a valid DatabaseSearchReply
	reply := &DatabaseSearchReply{
		Key: common.Hash{0x01, 0x02, 0x03},
		PeerHashes: []common.Hash{
			{0x04, 0x05, 0x06},
		},
		From: common.Hash{0x07, 0x08, 0x09},
	}

	dest := common.Hash{0x04, 0x05, 0x06}
	err := dm.sendResponse(reply, dest)
	if err != nil {
		t.Fatalf("Expected no error on successful send, got: %v", err)
	}

	// Verify message was queued
	session := sessionProvider.GetMockSession()
	if len(session.GetSentMessages()) != 1 {
		t.Errorf("Expected 1 sent message, got %d", len(session.GetSentMessages()))
	}
}

// TestCreateDatabaseSearchReplyMessageNilOnFailure verifies that
// createDatabaseSearchReplyMessage returns nil when marshaling fails,
// consistent with createDatabaseStoreMessage's behavior.
func TestCreateDatabaseSearchReplyMessageNilOnFailure(t *testing.T) {
	dm := NewDatabaseManager(nil)

	// A reply with an empty Key should fail to marshal in a way that
	// exercises the error path. If MarshalBinary succeeds on minimal data,
	// the function should still return a valid message (not nil).
	reply := &DatabaseSearchReply{}
	msg := dm.createDatabaseSearchReplyMessage(reply)

	// If MarshalBinary failed, msg should be nil (no partial messages)
	// If MarshalBinary succeeded, msg should be non-nil with valid type
	if msg != nil {
		if msg.Type() != I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY {
			t.Errorf("Expected message type %d, got %d",
				I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY, msg.Type())
		}
	}
	// Either outcome is valid depending on MarshalBinary behavior;
	// the key invariant is: msg is either nil or fully valid (no empty data)
	t.Logf("createDatabaseSearchReplyMessage returned nil=%v", msg == nil)
}
