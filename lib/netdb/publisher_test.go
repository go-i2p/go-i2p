package netdb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/testutil"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

type mockLookupTransportPublisher struct {
	fn func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error)
}

func (m *mockLookupTransportPublisher) SendDatabaseLookup(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
	if m.fn == nil {
		return nil, 0, errors.New("mock lookup transport not configured")
	}
	return m.fn(ctx, peerRI, lookup)
}

// TestPublisherCreation tests creating a new publisher
func TestPublisherCreation(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	publisher := NewPublisher(db, nil, nil, nil, config)

	assert.NotNil(t, publisher)
	assert.Equal(t, config.RouterInfoInterval, publisher.routerInfoInterval)
	assert.Equal(t, config.LeaseSetInterval, publisher.leaseSetInterval)
	assert.Equal(t, config.FloodfillCount, publisher.floodfillCount)
	assert.Nil(t, publisher.routerInfoProvider)
}

// TestPublisherStartWithoutTunnelPool tests that Start fails without a tunnel pool
func TestPublisherStartWithoutTunnelPool(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	publisher := NewPublisher(db, nil, nil, nil, config)
	err := publisher.Start()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel pool required")
}

// TestPublisherDefaultConfig tests the default configuration values
func TestPublisherDefaultConfig(t *testing.T) {
	config := DefaultPublisherConfig()

	assert.Equal(t, 30*time.Minute, config.RouterInfoInterval)
	assert.Equal(t, 5*time.Minute, config.LeaseSetInterval)
	assert.Equal(t, 4, config.FloodfillCount)
}

// TestPublisherGetStats tests retrieving publisher statistics
func TestPublisherGetStats(t *testing.T) {
	db := newMockNetDB()
	config := PublisherConfig{
		RouterInfoInterval: 20 * time.Minute,
		LeaseSetInterval:   3 * time.Minute,
		FloodfillCount:     6,
	}

	publisher := NewPublisher(db, nil, nil, nil, config)
	stats := publisher.GetStats()

	assert.Equal(t, 20*time.Minute, stats.RouterInfoInterval)
	assert.Equal(t, 3*time.Minute, stats.LeaseSetInterval)
	assert.Equal(t, 6, stats.FloodfillCount)
	assert.True(t, stats.IsRunning)
	assert.Equal(t, uint64(0), stats.RouterInfoPublishSuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoPublishFail)
	assert.Equal(t, uint64(0), stats.RouterInfoSendSuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoSendFail)
	assert.Equal(t, uint64(0), stats.RouterInfoVerifySuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoVerifyFail)
}

// TestPublisherStopBeforeStart tests stopping a publisher that was never started
func TestPublisherStopBeforeStart(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()

	publisher := NewPublisher(db, nil, nil, nil, config)

	// Should not panic
	publisher.Stop()

	stats := publisher.GetStats()
	assert.False(t, stats.IsRunning)
}

// TestPublisherCustomConfiguration tests creating publisher with custom config
func TestPublisherCustomConfiguration(t *testing.T) {
	db := newMockNetDB()
	config := PublisherConfig{
		RouterInfoInterval: 45 * time.Minute,
		LeaseSetInterval:   10 * time.Minute,
		FloodfillCount:     8,
	}

	publisher := NewPublisher(db, nil, nil, nil, config)

	assert.Equal(t, 45*time.Minute, publisher.routerInfoInterval)
	assert.Equal(t, 10*time.Minute, publisher.leaseSetInterval)
	assert.Equal(t, 8, publisher.floodfillCount)
}

// TestPublishLeaseSetWithNoFloodfills tests publishing when no floodfills are available
func TestPublishLeaseSetWithNoFloodfills(t *testing.T) {
	// Empty database — verifies error for invalid LeaseSet (prevents panic)
	assertPublishEmptyLeaseSetFails(t)
}

// TestPublishRouterInfoWithFloodfills tests publishing RouterInfo to floodfills
func TestPublishRouterInfoWithFloodfills(t *testing.T) {
	db := newMockNetDB()

	// Note: mockNetDB SelectFloodfillRouters returns empty list
	// In a real scenario, we would populate the database with floodfills

	config := PublisherConfig{
		RouterInfoInterval: 30 * time.Minute,
		LeaseSetInterval:   5 * time.Minute,
		FloodfillCount:     3,
	}
	publisher := NewPublisher(db, nil, nil, nil, config)

	// Create an empty test RouterInfo
	ri := router_info.RouterInfo{}

	err := publisher.PublishRouterInfo(ri)

	// Should return error for invalid RouterInfo (prevents panic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get router hash")
}

// TestPublisherSelectFloodfills tests floodfill selection for publishing
func TestPublisherSelectFloodfills(t *testing.T) {
	db := newMockNetDB()

	// Note: mockNetDB SelectFloodfillRouters returns empty list
	// In a real scenario, we would populate the database with floodfills

	config := PublisherConfig{
		RouterInfoInterval: 30 * time.Minute,
		LeaseSetInterval:   5 * time.Minute,
		FloodfillCount:     4,
	}
	publisher := NewPublisher(db, nil, nil, nil, config)

	hash := common.Hash{5, 6, 7, 8}
	floodfills, err := publisher.selectFloodfillsForPublishing(hash)

	assert.NoError(t, err)
	// Mock returns empty list since we don't have routers
	assert.LessOrEqual(t, len(floodfills), config.FloodfillCount)
}

// TestPublisherInterfaceCompliance tests that Publisher implements expected interface
func TestPublisherInterfaceCompliance(t *testing.T) {
	db := newMockNetDB()
	config := DefaultPublisherConfig()
	publisher := NewPublisher(db, nil, nil, nil, config)

	// Verify publisher has all expected methods
	var _ interface {
		Start() error
		Stop()
		PublishLeaseSet(hash common.Hash, leaseSetData []byte) error
		PublishRouterInfo(ri router_info.RouterInfo) error
		GetStats() PublisherStats
	} = publisher
}

// TestPublisherFloodfillCount tests varying floodfill count configurations
func TestPublisherFloodfillCount(t *testing.T) {
	testCases := []struct {
		name           string
		floodfillCount int
	}{
		{"Single floodfill", 1},
		{"Default count", 4},
		{"High count", 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newMockNetDB()
			config := PublisherConfig{
				RouterInfoInterval: 30 * time.Minute,
				LeaseSetInterval:   5 * time.Minute,
				FloodfillCount:     tc.floodfillCount,
			}

			publisher := NewPublisher(db, nil, nil, nil, config)
			assert.Equal(t, tc.floodfillCount, publisher.floodfillCount)
		})
	}
}

// TestPublisherIntervalConfigurations tests various time interval configurations
func TestPublisherIntervalConfigurations(t *testing.T) {
	testCases := []struct {
		name               string
		routerInfoInterval time.Duration
		leaseSetInterval   time.Duration
	}{
		{"Short intervals", 1 * time.Minute, 30 * time.Second},
		{"Default intervals", 30 * time.Minute, 5 * time.Minute},
		{"Long intervals", 2 * time.Hour, 30 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := newMockNetDB()
			config := PublisherConfig{
				RouterInfoInterval: tc.routerInfoInterval,
				LeaseSetInterval:   tc.leaseSetInterval,
				FloodfillCount:     4,
			}

			publisher := NewPublisher(db, nil, nil, nil, config)
			assert.Equal(t, tc.routerInfoInterval, publisher.routerInfoInterval)
			assert.Equal(t, tc.leaseSetInterval, publisher.leaseSetInterval)
		})
	}
}

func TestVerifyRouterInfoRetrievable_SucceedsOnMatchingDatabaseStore(t *testing.T) {
	db := newMockNetDB()
	p := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())
	p.verifyTimeout = 100 * time.Millisecond

	target := common.Hash{1, 2, 3, 4}
	floodfills := []router_info.RouterInfo{{}}

	p.SetLookupTransport(&mockLookupTransportPublisher{fn: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
		ds := i2np.NewDatabaseStore(target, []byte{0, 0}, i2np.DatabaseStoreTypeRouterInfo)
		ds.ReplyToken = [4]byte{}
		wire, err := ds.MarshalPayload()
		if err != nil {
			return nil, 0, err
		}
		return wire, i2np.I2NPMessageTypeDatabaseStore, nil
	}})

	verifyErr := p.verifyRouterInfoRetrievable(target, floodfills)
	assert.NoError(t, verifyErr)
}

func TestVerifyRouterInfoRetrievable_UsesLocalRouterIdentityWhenAvailable(t *testing.T) {
	db := newMockNetDB()
	localRI := *testutil.CreateSignedTestRouterInfo(t, nil, nil)
	p := NewPublisher(db, nil, nil, &mockRouterInfoProviderPublisher{ri: localRI}, DefaultPublisherConfig())
	p.verifyTimeout = 100 * time.Millisecond

	localHash, err := localRI.IdentHash()
	assert.NoError(t, err)
	target := common.Hash{1, 2, 3, 4}
	floodfills := []router_info.RouterInfo{{}}

	p.SetLookupTransport(&mockLookupTransportPublisher{fn: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
		assert.Equal(t, localHash, lookup.From, "verification lookup should use our local router identity as From")
		ds := i2np.NewDatabaseStore(target, []byte{0, 0}, i2np.DatabaseStoreTypeRouterInfo)
		wire, err := ds.MarshalPayload()
		if err != nil {
			return nil, 0, err
		}
		return wire, i2np.I2NPMessageTypeDatabaseStore, nil
	}})

	verifyErr := p.verifyRouterInfoRetrievable(target, floodfills)
	assert.NoError(t, verifyErr)
}

func TestVerifyRouterInfoRetrievable_FailsWhenNoMatchingStore(t *testing.T) {
	db := newMockNetDB()
	p := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())
	p.verifyTimeout = 100 * time.Millisecond

	target := common.Hash{1, 2, 3, 4}
	floodfills := []router_info.RouterInfo{{}}

	p.SetLookupTransport(&mockLookupTransportPublisher{fn: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
		wrong := common.Hash{9, 9, 9, 9}
		ds := i2np.NewDatabaseStore(wrong, []byte{0, 0}, i2np.DatabaseStoreTypeRouterInfo)
		wire, err := ds.MarshalPayload()
		if err != nil {
			return nil, 0, err
		}
		return wire, i2np.I2NPMessageTypeDatabaseStore, nil
	}})

	verifyErr := p.verifyRouterInfoRetrievable(target, floodfills)
	assert.Error(t, verifyErr)
	assert.Contains(t, verifyErr.Error(), "post-publish RouterInfo verification failed")
}

func TestVerifyRouterInfoRetrievable_SkipsWithoutLookupTransport(t *testing.T) {
	db := newMockNetDB()
	p := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	target := common.Hash{1, 2, 3, 4}
	floodfills := []router_info.RouterInfo{{}}

	err := p.verifyRouterInfoRetrievable(target, floodfills)
	assert.NoError(t, err)
}

func TestPublishRouterInfo_RetriesVerificationAndSucceeds(t *testing.T) {
	db := newPublisherVerifyStubDB()
	transport := newMockTransportManager()
	p := NewPublisher(db, nil, transport, nil, DefaultPublisherConfig())

	floodfill := createValidRouterInfo(t)
	err := db.SetFloodfills([]router_info.RouterInfo{floodfill})
	assert.NoError(t, err)

	verifyCalls := 0
	ri := createValidRouterInfo(t)
	riHash, err := ri.IdentHash()
	assert.NoError(t, err)

	p.SetLookupTransport(&mockLookupTransportPublisher{fn: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
		verifyCalls++
		if verifyCalls < 3 {
			return nil, 0, errors.New("temporary verification miss")
		}
		ds := i2np.NewDatabaseStore(riHash, []byte{0, 0}, i2np.DatabaseStoreTypeRouterInfo)
		wire, err := ds.MarshalPayload()
		if err != nil {
			return nil, 0, err
		}
		return wire, i2np.I2NPMessageTypeDatabaseStore, nil
	}})

	err = p.PublishRouterInfo(ri)
	assert.NoError(t, err)
	assert.Equal(t, 3, verifyCalls, "verification should retry until success")

	stats := p.GetStats()
	assert.Equal(t, uint64(1), stats.RouterInfoPublishSuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoPublishFail)
	assert.Equal(t, uint64(1), stats.RouterInfoSendSuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoSendFail)
	assert.Equal(t, uint64(1), stats.RouterInfoVerifySuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoVerifyFail)
}

func TestPublishRouterInfo_FailsWhenVerificationNeverSucceeds(t *testing.T) {
	db := newPublisherVerifyStubDB()
	transport := newMockTransportManager()
	p := NewPublisher(db, nil, transport, nil, DefaultPublisherConfig())

	floodfill := createValidRouterInfo(t)
	err := db.SetFloodfills([]router_info.RouterInfo{floodfill})
	assert.NoError(t, err)

	verifyCalls := 0
	p.SetLookupTransport(&mockLookupTransportPublisher{fn: func(ctx context.Context, peerRI router_info.RouterInfo, lookup *i2np.DatabaseLookup) ([]byte, int, error) {
		verifyCalls++
		return nil, 0, errors.New("verification miss")
	}})

	ri := createValidRouterInfo(t)
	err = p.PublishRouterInfo(ri)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "post-publish RouterInfo verification failed after")
	assert.Equal(t, 4, verifyCalls, "verification should retry the configured number of times")

	stats := p.GetStats()
	assert.Equal(t, uint64(0), stats.RouterInfoPublishSuccess)
	assert.Equal(t, uint64(1), stats.RouterInfoPublishFail)
	assert.Equal(t, uint64(1), stats.RouterInfoSendSuccess)
	assert.Equal(t, uint64(0), stats.RouterInfoSendFail)
	assert.Equal(t, uint64(0), stats.RouterInfoVerifySuccess)
	assert.Equal(t, uint64(1), stats.RouterInfoVerifyFail)
}

func TestCreateDatabaseStoreMessage_TracksReplyTokenAsPending(t *testing.T) {
	db := newPublisherVerifyStubDB()
	inboundPool := tunnel.NewTunnelPool(&mockPeerSelector{})
	inboundPool.AddTunnel(&tunnel.TunnelState{
		ID:        tunnel.TunnelID(0x01020304),
		Hops:      []common.Hash{{0xAA, 0xBB, 0xCC, 0xDD}},
		State:     tunnel.TunnelReady,
		CreatedAt: time.Now(),
		IsInbound: true,
	})
	p := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())
	p.SetInboundPool(inboundPool)

	hash := common.Hash{0xAA, 0xBB, 0xCC}
	msg, err := p.createDatabaseStoreMessage(hash, []byte{0x01, 0x02}, i2np.DatabaseStoreTypeRouterInfo)
	assert.NoError(t, err)

	store, ok := msg.(*i2np.DatabaseStore)
	assert.True(t, ok)
	token := binary.BigEndian.Uint32(store.ReplyToken[:])
	assert.NotZero(t, token)

	_, pending := p.pendingReplyTokens.Load(token)
	assert.True(t, pending, "reply token should be tracked as pending")
}

func TestHandleDeliveryStatus_ConsumesPendingReplyToken(t *testing.T) {
	db := newPublisherVerifyStubDB()
	p := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	token := [4]byte{0x01, 0x02, 0x03, 0x04}
	p.registerPendingReplyToken(token)

	msgID := int(binary.BigEndian.Uint32(token[:]))
	err := p.HandleDeliveryStatus(msgID, time.Now())
	assert.NoError(t, err)

	stats := p.GetStats()
	assert.Equal(t, uint64(1), stats.ReplyTokenAckReceived)
	assert.Equal(t, uint64(0), stats.ReplyTokenAckUnexpected)

	_, pending := p.pendingReplyTokens.Load(uint32(msgID))
	assert.False(t, pending, "pending token should be removed once acked")
}

func TestHandleDeliveryStatus_UnknownTokenIncrementsUnexpected(t *testing.T) {
	db := newPublisherVerifyStubDB()
	p := NewPublisher(db, nil, nil, nil, DefaultPublisherConfig())

	err := p.HandleDeliveryStatus(12345, time.Now())
	assert.NoError(t, err)

	stats := p.GetStats()
	assert.Equal(t, uint64(0), stats.ReplyTokenAckReceived)
	assert.Equal(t, uint64(1), stats.ReplyTokenAckUnexpected)
}

type publisherVerifyStubDB struct {
	routerInfos map[common.Hash]router_info.RouterInfo
	floodfills  []router_info.RouterInfo
}

func newPublisherVerifyStubDB() *publisherVerifyStubDB {
	return &publisherVerifyStubDB{routerInfos: make(map[common.Hash]router_info.RouterInfo)}
}

func (m *publisherVerifyStubDB) SetFloodfills(floodfills []router_info.RouterInfo) error {
	m.floodfills = floodfills
	for _, ff := range floodfills {
		h, err := ff.IdentHash()
		if err != nil {
			return err
		}
		m.routerInfos[h] = ff
	}
	return nil
}

func (m *publisherVerifyStubDB) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	ch := make(chan router_info.RouterInfo, 1)
	if ri, ok := m.routerInfos[hash]; ok {
		ch <- ri
	}
	close(ch)
	return ch
}

func (m *publisherVerifyStubDB) GetAllRouterInfos() []router_info.RouterInfo {
	res := make([]router_info.RouterInfo, 0, len(m.routerInfos))
	for _, ri := range m.routerInfos {
		res = append(res, ri)
	}
	return res
}

func (m *publisherVerifyStubDB) StoreRouterInfo(ri router_info.RouterInfo) {
	if h, err := ri.IdentHash(); err == nil {
		m.routerInfos[h] = ri
	}
}

func (m *publisherVerifyStubDB) Reseed(b bootstrap.Bootstrap, minRouters int) error { return nil }
func (m *publisherVerifyStubDB) Size() int                                          { return len(m.routerInfos) }
func (m *publisherVerifyStubDB) RecalculateSize() error                             { return nil }
func (m *publisherVerifyStubDB) Ensure() error                                      { return nil }

func (m *publisherVerifyStubDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	if len(m.floodfills) == 0 {
		return nil, fmt.Errorf("no floodfills")
	}
	if count >= len(m.floodfills) {
		return append([]router_info.RouterInfo(nil), m.floodfills...), nil
	}
	return append([]router_info.RouterInfo(nil), m.floodfills[:count]...), nil
}

func (m *publisherVerifyStubDB) GetLeaseSetCount() int { return 0 }

func (m *publisherVerifyStubDB) GetAllLeaseSets() []LeaseSetEntry { return nil }

func (m *publisherVerifyStubDB) GetPublicLeaseSets() []LeaseSetEntry { return nil }

func (m *publisherVerifyStubDB) IsOwnLeaseSet(hash common.Hash) bool { return false }

func (m *publisherVerifyStubDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return nil
}

func (m *publisherVerifyStubDB) StoreOwnLeaseSet(key common.Hash, data []byte, dataType byte) error {
	return nil
}

type mockRouterInfoProviderPublisher struct {
	ri router_info.RouterInfo
}

func (m *mockRouterInfoProviderPublisher) GetRouterInfo() (*router_info.RouterInfo, error) {
	return &m.ri, nil
}
