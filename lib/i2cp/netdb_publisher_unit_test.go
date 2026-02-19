package i2cp

import (
	"errors"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetDBLeaseSetPublisher_PublishLeaseSet(t *testing.T) {
	store := newMockNetDBStore()
	publisher := NewNetDBLeaseSetPublisher(store)

	var key common.Hash
	copy(key[:], []byte("test-destination-hash-1234567890"))
	data := []byte("test-leaseset-data")

	err := publisher.PublishLeaseSet(key, data)
	require.NoError(t, err)
	assert.Equal(t, data, store.stored[key])
	assert.Equal(t, byte(3), store.dataTypes[key]) // Default: LeaseSet2
}

func TestNetDBLeaseSetPublisher_StoreError(t *testing.T) {
	store := newMockNetDBStore()
	store.err = errors.New("store failure")
	publisher := NewNetDBLeaseSetPublisher(store)

	var key common.Hash
	err := publisher.PublishLeaseSet(key, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "store failure")
}

func TestNetDBLeaseSetPublisherWithType(t *testing.T) {
	store := newMockNetDBStore()
	publisher := NewNetDBLeaseSetPublisherWithType(store, 5) // EncryptedLeaseSet

	var key common.Hash
	copy(key[:], []byte("encrypted-leaseset-key-123456789"))
	data := []byte("encrypted-leaseset-bytes")

	err := publisher.PublishLeaseSet(key, data)
	require.NoError(t, err)
	assert.Equal(t, byte(5), store.dataTypes[key])
}

func TestNetDBLeaseSetPublisher_DefaultType(t *testing.T) {
	store := newMockNetDBStore()
	publisher := NewNetDBLeaseSetPublisher(store)
	assert.Equal(t, byte(3), publisher.dataType, "default type should be LeaseSet2 (3)")
}

func TestNetDBLeaseSetPublisher_ImplementsInterface(t *testing.T) {
	store := newMockNetDBStore()
	var publisher LeaseSetPublisher = NewNetDBLeaseSetPublisher(store)
	assert.NotNil(t, publisher)
}
