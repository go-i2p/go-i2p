package i2np

import (
	"testing"
)

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
