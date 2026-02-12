package netdb

import (
	"os"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/router_info"
)

// newValidRouterInfoForBench creates a valid RouterInfo for benchmarking.
// Uses modern Ed25519/X25519 cryptography as recommended by I2P.
func newValidRouterInfoForBench(b *testing.B) *router_info.RouterInfo {
	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		b.Fatalf("Failed to create key certificate: %v", err)
	}
	return router_info.OwnedRouterInfo(*keyCert)
}

// BenchmarkIdentHashValid benchmarks IdentHash() with valid RouterInfo.
// Measures the performance of the new error-returning API vs legacy approach.
func BenchmarkIdentHashValid(b *testing.B) {
	ri := newValidRouterInfoForBench(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash, err := ri.IdentHash()
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
		_ = hash // Prevent optimization
	}
}

// BenchmarkIdentHashInvalid benchmarks IdentHash() with invalid RouterInfo.
// Measures the performance cost of error handling for invalid data.
func BenchmarkIdentHashInvalid(b *testing.B) {
	emptyRI := &router_info.RouterInfo{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := emptyRI.IdentHash()
		if err == nil {
			b.Fatal("Expected error for invalid RouterInfo")
		}
	}
}

// BenchmarkBytesValid benchmarks Bytes() serialization with valid RouterInfo.
func BenchmarkBytesValid(b *testing.B) {
	ri := newValidRouterInfoForBench(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bytes, err := ri.Bytes()
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
		_ = bytes
	}
}

// BenchmarkBytesInvalid benchmarks Bytes() with invalid RouterInfo.
func BenchmarkBytesInvalid(b *testing.B) {
	emptyRI := &router_info.RouterInfo{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := emptyRI.Bytes()
		if err == nil {
			b.Fatal("Expected error for invalid RouterInfo")
		}
	}
}

// BenchmarkStoreRouterInfo benchmarks NetDB storage operations.
func BenchmarkStoreRouterInfo(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "netdb-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	db := NewStdNetDB(tmpDir)
	ri := newValidRouterInfoForBench(b)

	// Get RouterInfo hash and bytes for storage
	hash, err := ri.IdentHash()
	if err != nil {
		b.Fatalf("Failed to get hash: %v", err)
	}

	bytes, err := ri.Bytes()
	if err != nil {
		b.Fatalf("Failed to serialize: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := db.StoreRouterInfoFromMessage(hash, bytes, 0)
		if err != nil {
			b.Fatalf("Store failed: %v", err)
		}
	}
}

// BenchmarkGetRouterInfo benchmarks NetDB retrieval operations.
func BenchmarkGetRouterInfo(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "netdb-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	db := NewStdNetDB(tmpDir)
	ri := newValidRouterInfoForBench(b)

	// Store RouterInfo first
	hash, err := ri.IdentHash()
	if err != nil {
		b.Fatalf("Failed to get hash: %v", err)
	}

	bytes, err := ri.Bytes()
	if err != nil {
		b.Fatalf("Failed to serialize: %v", err)
	}

	err = db.StoreRouterInfoFromMessage(hash, bytes, 0)
	if err != nil {
		b.Fatalf("Store failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		chnl := db.GetRouterInfo(hash)
		if chnl == nil {
			b.Fatal("GetRouterInfo returned nil")
		}
		<-chnl
	}
}

// BenchmarkConcurrentReads benchmarks concurrent read operations.
func BenchmarkConcurrentReads(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "netdb-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	db := NewStdNetDB(tmpDir)

	// Pre-populate with 100 RouterInfos
	hashes := make([]common.Hash, 100)
	for i := 0; i < 100; i++ {
		ri := newValidRouterInfoForBench(b)
		hash, err := ri.IdentHash()
		if err != nil {
			b.Fatalf("Failed to get hash: %v", err)
		}
		hashes[i] = hash

		bytes, err := ri.Bytes()
		if err != nil {
			b.Fatalf("Failed to serialize: %v", err)
		}

		err = db.StoreRouterInfoFromMessage(hash, bytes, 0)
		if err != nil {
			b.Fatalf("Store failed: %v", err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			idx := i % 100
			chnl := db.GetRouterInfo(hashes[idx])
			if chnl != nil {
				<-chnl
			}
			i++
		}
	})
}

// BenchmarkConcurrentWrites benchmarks concurrent write operations.
func BenchmarkConcurrentWrites(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "netdb-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	db := NewStdNetDB(tmpDir)

	// Pre-generate RouterInfos
	type riData struct {
		hash  common.Hash
		bytes []byte
	}

	routerInfos := make([]riData, 100)
	for i := 0; i < 100; i++ {
		ri := newValidRouterInfoForBench(b)
		hash, err := ri.IdentHash()
		if err != nil {
			b.Fatalf("Failed to get hash: %v", err)
		}

		bytes, err := ri.Bytes()
		if err != nil {
			b.Fatalf("Failed to serialize: %v", err)
		}

		routerInfos[i] = riData{hash: hash, bytes: bytes}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			idx := i % 100
			_ = db.StoreRouterInfoFromMessage(routerInfos[idx].hash, routerInfos[idx].bytes, 0)
			i++
		}
	})
}

// BenchmarkMemoryAllocations measures memory allocation for error handling.
func BenchmarkMemoryAllocations(b *testing.B) {
	ri := newValidRouterInfoForBench(b)

	b.Run("IdentHash", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			hash, err := ri.IdentHash()
			if err != nil {
				b.Fatal(err)
			}
			sink = &hash // Prevent optimization
		}
	})

	b.Run("Bytes", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			bytes, err := ri.Bytes()
			if err != nil {
				b.Fatal(err)
			}
			sinkBytes = bytes
		}
	})
}

// Prevent compiler optimization of benchmark results
var (
	sink      *common.Hash
	sinkBytes []byte
)
