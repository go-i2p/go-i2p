package i2np

import (
	"testing"
)

func BenchmarkTunnelBuildMessage_Create(b *testing.B) {
	records := createKnownValueBuildRequestRecords()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = newTunnelBuildMessage(records)
	}
}

func BenchmarkTunnelBuildMessage_MarshalUnmarshal(b *testing.B) {
	records := createKnownValueBuildRequestRecords()
	msg := newTunnelBuildMessage(records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := msg.MarshalBinary()

		newMsg := &TunnelBuildMessage{
			BaseI2NPMessage: NewBaseI2NPMessage(I2NPMessageTypeTunnelBuild),
		}
		_ = newMsg.UnmarshalBinary(data)
	}
}

func BenchmarkTunnelBuildMessage_Serialize(b *testing.B) {
	records := createKnownValueBuildRequestRecords()
	msg := newTunnelBuildMessage(records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.MarshalBinary()
	}
}

func BenchmarkTunnelBuildMessage_Creation(b *testing.B) {
	records := createTestBuildRequestRecords()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = newTunnelBuildMessage(records)
	}
}

func BenchmarkTunnelBuildMessage_Serialization(b *testing.B) {
	records := createTestBuildRequestRecords()
	msg := newTunnelBuildMessage(records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = msg.MarshalBinary()
	}
}
