package i2np

import (
	"testing"
)

// BenchmarkDeserializeGarlicClove_SmallMessage benchmarks small message parsing
func BenchmarkDeserializeGarlicClove_SmallMessage(b *testing.B) {
	cloveData := buildTestGarlicCloveData(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = deserializeGarlicClove(cloveData, 0)
	}
}

// BenchmarkDeserializeGarlicClove_LargeMessage benchmarks large message parsing
func BenchmarkDeserializeGarlicClove_LargeMessage(b *testing.B) {
	cloveData := buildTestGarlicCloveData(8192)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = deserializeGarlicClove(cloveData, 0)
	}
}
