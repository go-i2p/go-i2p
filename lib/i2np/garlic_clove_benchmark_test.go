package i2np

import (
	"testing"
)

// BenchmarkParseECIESGarlicClove_SmallMessage benchmarks small message parsing
func BenchmarkParseECIESGarlicClove_SmallMessage(b *testing.B) {
	cloveData := buildTestGarlicCloveData(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseECIESGarlicClove(cloveData)
	}
}

// BenchmarkParseECIESGarlicClove_LargeMessage benchmarks large message parsing
func BenchmarkParseECIESGarlicClove_LargeMessage(b *testing.B) {
	cloveData := buildTestGarlicCloveData(8192)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseECIESGarlicClove(cloveData)
	}
}
