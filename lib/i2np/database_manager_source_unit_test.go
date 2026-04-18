package i2np

import (
	"testing"

	common "github.com/go-i2p/common/data"
)

type sourceAwareStoreMock struct {
	storedKey      common.Hash
	storedDataType byte
	storedData     []byte
	source         common.Hash
	usedSourcePath bool
}

func (m *sourceAwareStoreMock) Store(key common.Hash, data []byte, dataType byte) error {
	m.storedKey = key
	m.storedData = append([]byte(nil), data...)
	m.storedDataType = dataType
	m.usedSourcePath = false
	return nil
}

func (m *sourceAwareStoreMock) StoreFromPeer(key common.Hash, data []byte, dataType byte, source common.Hash) error {
	m.storedKey = key
	m.storedData = append([]byte(nil), data...)
	m.storedDataType = dataType
	m.source = source
	m.usedSourcePath = true
	return nil
}

func TestDatabaseManager_StoreDataFromPeer_UsesSourceAwarePath(t *testing.T) {
	mock := &sourceAwareStoreMock{}
	dm := NewDatabaseManager(mock)

	var key, source common.Hash
	key[0] = 0xAA
	source[0] = 0xBB
	writer := NewDatabaseStore(key, []byte("lease-set-data"), DatabaseStoreTypeLeaseSet2)

	if err := dm.StoreDataFromPeer(writer, source); err != nil {
		t.Fatalf("StoreDataFromPeer failed: %v", err)
	}

	if !mock.usedSourcePath {
		t.Fatal("expected source-aware store path to be used")
	}
	if mock.source != source {
		t.Fatalf("expected source %x, got %x", source[:], mock.source[:])
	}
	if mock.storedKey != key {
		t.Fatalf("expected key %x, got %x", key[:], mock.storedKey[:])
	}
	if mock.storedDataType != DatabaseStoreTypeLeaseSet2 {
		t.Fatalf("expected data type %d, got %d", DatabaseStoreTypeLeaseSet2, mock.storedDataType)
	}
}
