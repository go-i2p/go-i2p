package tunnel

import (
	"errors"
	"testing"

	"github.com/go-i2p/common/router_info"
	"github.com/stretchr/testify/assert"
)

func TestNewDefaultPeerSelector_NilDB(t *testing.T) {
	s, err := NewDefaultPeerSelector(nil)
	assert.Nil(t, s)
	assert.Error(t, err)
}

func TestDefaultPeerSelector_InvalidCount(t *testing.T) {
	db := &fakeDB{}
	s, err := NewDefaultPeerSelector(db)
	assert.NoError(t, err)

	peers, err := s.SelectPeers(0, nil)
	assert.Error(t, err)
	assert.Nil(t, peers)
}

func TestDefaultPeerSelector_Success(t *testing.T) {
	// create dummy router_info entries
	ri := router_info.RouterInfo{}
	// fakeDB will return the same RouterInfo for simplicity
	db := &fakeDB{peers: []router_info.RouterInfo{ri, ri, ri}}
	s, err := NewDefaultPeerSelector(db)
	assert.NoError(t, err)

	peers, err := s.SelectPeers(2, nil)
	assert.NoError(t, err)
	assert.Len(t, peers, 2)
}

func TestDefaultPeerSelector_UnderlyingError(t *testing.T) {
	db := &fakeDB{err: errors.New("db failure")}
	s, err := NewDefaultPeerSelector(db)
	assert.NoError(t, err)

	peers, err := s.SelectPeers(1, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "underlying selector error")
	assert.Nil(t, peers)
}
