package bootstrap

import (
	"testing"
)

// BenchmarkValidateRouterAddress_Valid benchmarks validation of a valid address.
func BenchmarkValidateRouterAddress_Valid(b *testing.B) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": testHost,
		"port": testPort,
		"s":    "static-key-data",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRouterAddress(addr)
	}
}

// BenchmarkValidateRouterAddress_Invalid benchmarks validation of an invalid address.
func BenchmarkValidateRouterAddress_Invalid(b *testing.B) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"port": testPort,
		// Missing host
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRouterAddress(addr)
	}
}

// BenchmarkValidateRouterAddress_MultipleChecks benchmarks multiple validation calls.
func BenchmarkValidateRouterAddress_MultipleChecks(b *testing.B) {
	addr := createTestRouterAddress("ntcp2", map[string]string{
		"host": testHost,
		"port": testPort,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateRouterAddress(addr)
		_ = ValidateNTCP2Address(addr)
	}
}

// BenchmarkVerifyRouterInfoSignature benchmarks signature verification performance.
func BenchmarkVerifyRouterInfoSignature(b *testing.B) {
	ri := createSignedTestRouterInfo(b, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyRouterInfoSignature(*ri)
	}
}
