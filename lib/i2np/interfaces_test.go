package i2np

import (
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/stretchr/testify/assert"
)

func TestInterfaceSatisfaction(t *testing.T) {
	// Test that our types satisfy their interfaces

	// Test message interfaces
	var _ I2NPMessage = (*BaseI2NPMessage)(nil)
	var _ I2NPMessage = (*DataMessage)(nil)
	var _ I2NPMessage = (*DeliveryStatusMessage)(nil)
	var _ I2NPMessage = (*TunnelDataMessage)(nil)

	// Test specialized interfaces
	var _ PayloadCarrier = (*DataMessage)(nil)
	var _ TunnelCarrier = (*TunnelDataMessage)(nil)
	var _ StatusReporter = (*DeliveryStatusMessage)(nil)
	var _ DatabaseReader = (*DatabaseLookup)(nil)
	var _ DatabaseWriter = (*DatabaseStore)(nil)
	var _ TunnelBuilder = (*TunnelBuild)(nil)
	var _ TunnelBuilder = (*VariableTunnelBuild)(nil)
	var _ TunnelReplyHandler = (*TunnelBuildReply)(nil)
	var _ TunnelReplyHandler = (*VariableTunnelBuildReply)(nil)
	var _ GarlicProcessor = (*Garlic)(nil)
}

func TestMessageFactory(t *testing.T) {
	factory := NewI2NPMessageFactory()

	// Test data message creation
	payload := []byte("test data")
	dataMsg := factory.CreateDataMessage(payload)
	assert.Equal(t, I2NP_MESSAGE_TYPE_DATA, dataMsg.Type())

	// Test that it implements PayloadCarrier
	if pc, ok := dataMsg.(PayloadCarrier); ok {
		assert.Equal(t, payload, pc.GetPayload())
	} else {
		t.Fatal("DataMessage should implement PayloadCarrier")
	}

	// Test delivery status message creation
	timestamp := time.Now()
	statusMsg := factory.CreateDeliveryStatusMessage(12345, timestamp)
	assert.Equal(t, I2NP_MESSAGE_TYPE_DELIVERY_STATUS, statusMsg.Type())

	// Test that it implements StatusReporter
	if sr, ok := statusMsg.(StatusReporter); ok {
		assert.Equal(t, 12345, sr.GetStatusMessageID())
		assert.WithinDuration(t, timestamp, sr.GetTimestamp(), time.Second)
	} else {
		t.Fatal("DeliveryStatusMessage should implement StatusReporter")
	}
}

func TestMessageProcessor(t *testing.T) {
	processor := NewMessageProcessor()

	// Test processing data message
	dataMsg := NewDataMessage([]byte("test payload"))
	err := processor.ProcessMessage(dataMsg)
	assert.NoError(t, err)

	// Test processing delivery status message
	statusMsg := NewDeliveryStatusMessage(54321, time.Now())
	err = processor.ProcessMessage(statusMsg)
	assert.NoError(t, err)

	// Test processing tunnel data message
	var tunnelData [1024]byte
	copy(tunnelData[:], "tunnel test data")
	tunnelMsg := NewTunnelDataMessage(tunnelData)
	err = processor.ProcessMessage(tunnelMsg)
	assert.NoError(t, err)
}

func TestTunnelManager(t *testing.T) {
	manager := NewTunnelManager()

	// Create build request records
	records := [8]BuildRequestRecord{}
	for i := range records {
		records[i] = BuildRequestRecord{
			ReceiveTunnel: tunnel.TunnelID(i + 1),
			NextTunnel:    tunnel.TunnelID(i + 2),
		}
	}

	// Test with TunnelBuild
	builder := NewTunnelBuilder(records)
	err := manager.BuildTunnel(builder)
	assert.NoError(t, err)
	assert.Equal(t, 8, builder.GetRecordCount())

	// Test with VariableTunnelBuild
	variableRecords := []BuildRequestRecord{
		{ReceiveTunnel: 1, NextTunnel: 2},
		{ReceiveTunnel: 3, NextTunnel: 4},
		{ReceiveTunnel: 5, NextTunnel: 6},
	}
	variableBuilder := NewVariableTunnelBuilder(variableRecords)
	err = manager.BuildTunnel(variableBuilder)
	assert.NoError(t, err)
	assert.Equal(t, 3, variableBuilder.GetRecordCount())
}

func TestDatabaseManager(t *testing.T) {
	manager := NewDatabaseManager()

	// Test database lookup
	key := common.Hash{}
	from := common.Hash{}
	copy(key[:], "test key for lookup 12345678901")
	copy(from[:], "test from for lookup 123456789")

	lookup := &DatabaseLookup{
		Key:   key,
		From:  from,
		Flags: 0x01,
	}

	err := manager.PerformLookup(lookup)
	assert.NoError(t, err)
	assert.Equal(t, key, lookup.GetKey())
	assert.Equal(t, from, lookup.GetFrom())
	assert.Equal(t, byte(0x01), lookup.GetFlags())

	// Test database store
	storeData := []byte("test data to store")
	store := &DatabaseStore{
		Key:  key,
		Data: storeData,
		Type: 0x00,
	}

	err = manager.StoreData(store)
	assert.NoError(t, err)
	assert.Equal(t, key, store.GetStoreKey())
	assert.Equal(t, storeData, store.GetStoreData())
	assert.Equal(t, byte(0x00), store.GetStoreType())
}

func TestMessageRouter(t *testing.T) {
	config := MessageRouterConfig{
		MaxRetries:     3,
		DefaultTimeout: 30 * time.Second,
		EnableLogging:  true,
	}
	router := NewMessageRouter(config)

	// Test routing data message
	dataMsg := NewDataMessage([]byte("router test"))
	err := router.RouteMessage(dataMsg)
	assert.NoError(t, err)

	// Test routing database message
	key := common.Hash{}
	copy(key[:], "router test key 123456789012345")
	lookup := &DatabaseLookup{Key: key, From: key, Flags: 0x01}
	err = router.RouteDatabaseMessage(lookup)
	assert.NoError(t, err)

	// Test routing tunnel message
	records := [8]BuildRequestRecord{}
	builder := NewTunnelBuilder(records)
	err = router.RouteTunnelMessage(builder)
	assert.NoError(t, err)
}

func TestInterfaceComposition(t *testing.T) {
	// Test that a message can implement multiple interfaces
	dataMsg := NewDataMessage([]byte("composition test"))

	// Should implement I2NPMessage (base interface)
	assert.Implements(t, (*I2NPMessage)(nil), dataMsg)

	// Should implement MessageSerializer
	assert.Implements(t, (*MessageSerializer)(nil), dataMsg)

	// Should implement MessageIdentifier
	assert.Implements(t, (*MessageIdentifier)(nil), dataMsg)

	// Should implement MessageExpiration
	assert.Implements(t, (*MessageExpiration)(nil), dataMsg)

	// Should implement PayloadCarrier
	assert.Implements(t, (*PayloadCarrier)(nil), dataMsg)
}

func TestHelperFunctions(t *testing.T) {
	// Test CreateTunnelRecord
	receiveTunnel := tunnel.TunnelID(123)
	nextTunnel := tunnel.TunnelID(456)
	ourIdent := common.Hash{}
	nextIdent := common.Hash{}
	copy(ourIdent[:], "our identity hash 1234567890123")
	copy(nextIdent[:], "next identity hash 123456789012")

	tunnelRecord := CreateTunnelRecord(receiveTunnel, nextTunnel, ourIdent, nextIdent)
	assert.Equal(t, receiveTunnel, tunnelRecord.GetReceiveTunnel())
	assert.Equal(t, nextTunnel, tunnelRecord.GetNextTunnel())

	// Test that it also implements HashProvider
	if hashProvider, ok := tunnelRecord.(HashProvider); ok {
		assert.Equal(t, ourIdent, hashProvider.GetOurIdent())
		assert.Equal(t, nextIdent, hashProvider.GetNextIdent())
	}

	// Test CreateDatabaseQuery
	key := common.Hash{}
	from := common.Hash{}
	copy(key[:], "database query key 123456789012")
	copy(from[:], "database query from 12345678901")

	dbQuery := CreateDatabaseQuery(key, from, 0x02)
	assert.Equal(t, key, dbQuery.GetKey())
	assert.Equal(t, from, dbQuery.GetFrom())
	assert.Equal(t, byte(0x02), dbQuery.GetFlags())

	// Test CreateDatabaseEntry
	data := []byte("database entry test data")
	dbEntry := CreateDatabaseEntry(key, data, 0x01)
	assert.Equal(t, key, dbEntry.GetStoreKey())
	assert.Equal(t, data, dbEntry.GetStoreData())
	assert.Equal(t, byte(0x01), dbEntry.GetStoreType())
}

func TestConstructorInterfaces(t *testing.T) {
	// Test interface-returning constructors
	payload := []byte("interface test")

	// Test PayloadCarrier constructor
	pc := NewDataMessageWithPayload(payload)
	assert.Equal(t, payload, pc.GetPayload())

	// Test StatusReporter constructor
	timestamp := time.Now()
	sr := NewDeliveryStatusReporter(12345, timestamp)
	assert.Equal(t, 12345, sr.GetStatusMessageID())
	assert.WithinDuration(t, timestamp, sr.GetTimestamp(), time.Second)

	// Test TunnelCarrier constructor
	var data [1024]byte
	copy(data[:], "tunnel interface test")
	tc := NewTunnelCarrier(data)
	tunnelData := tc.GetTunnelData()
	assert.Equal(t, data[:], tunnelData)
}

// Benchmark tests to ensure interface overhead is minimal
func BenchmarkDirectCall(b *testing.B) {
	msg := NewDataMessage([]byte("benchmark test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = msg.GetPayload()
	}
}

func BenchmarkInterfaceCall(b *testing.B) {
	var pc PayloadCarrier = NewDataMessage([]byte("benchmark test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pc.GetPayload()
	}
}

func BenchmarkTypeAssertion(b *testing.B) {
	var msg I2NPMessage = NewDataMessage([]byte("benchmark test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if pc, ok := msg.(PayloadCarrier); ok {
			_ = pc.GetPayload()
		}
	}
}
