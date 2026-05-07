package ntcp2

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// benchmarkConn is a net.Conn that reads from a buffer repeatedly for benchmarking
type benchmarkConn struct {
	data   []byte
	offset int
}

func (c *benchmarkConn) Read(p []byte) (n int, err error) {
	if c.offset >= len(c.data) {
		c.offset = 0 // Reset to loop
	}

	n = copy(p, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *benchmarkConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (c *benchmarkConn) Close() error {
	return nil
}

func (c *benchmarkConn) LocalAddr() net.Addr {
	return &mockAddr{"benchmark-local"}
}

func (c *benchmarkConn) RemoteAddr() net.Addr {
	return &mockAddr{"benchmark-remote"}
}

func (c *benchmarkConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *benchmarkConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *benchmarkConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// createTestFramedMessage creates a properly formatted NTCP2 framed I2NP message
func createTestFramedMessage(payloadSize int) []byte {
	// Create a simple I2NP DatabaseStore message for testing
	var key [32]byte // Zero hash
	testData := make([]byte, payloadSize)
	msg := i2np.NewDatabaseStore(key, testData, 0)

	// Marshal to get actual I2NP data
	msgData, _ := msg.MarshalBinary()

	// Create NTCP2 frame: 4-byte length prefix + message data
	buf := new(bytes.Buffer)
	length := uint32(len(msgData))
	binary.Write(buf, binary.BigEndian, length)
	buf.Write(msgData)

	return buf.Bytes()
}

// BenchmarkNTCP2Unframer benchmarks the ReadNextMessage function to measure
// allocation reduction from stack-based buffer allocation
func BenchmarkNTCP2Unframer(b *testing.B) {
	// Create test message with 100-byte payload
	testData := createTestFramedMessage(100)

	// Create conn that loops the test data
	conn := &benchmarkConn{
		data:   testData,
		offset: 0,
	}

	// Create unframer
	unframer := NewI2NPUnframer(conn)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, err := unframer.ReadNextMessage()
		if err != nil && err != io.EOF {
			b.Fatalf("ReadNextMessage failed: %v", err)
		}
		if msg == nil {
			// Reset connection for next iteration
			conn.offset = 0
			msg, err = unframer.ReadNextMessage()
			if err != nil {
				b.Fatalf("ReadNextMessage failed after reset: %v", err)
			}
		}
	}
}

// BenchmarkNTCP2UnframerSmall benchmarks with small messages (32 bytes)
func BenchmarkNTCP2UnframerSmall(b *testing.B) {
	testData := createTestFramedMessage(32)
	conn := &benchmarkConn{data: testData, offset: 0}
	unframer := NewI2NPUnframer(conn)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, err := unframer.ReadNextMessage()
		if err != nil && err != io.EOF {
			b.Fatalf("ReadNextMessage failed: %v", err)
		}
		if msg == nil {
			conn.offset = 0
			msg, _ = unframer.ReadNextMessage()
		}
	}
}

// BenchmarkNTCP2UnframerLarge benchmarks with large messages (1KB)
func BenchmarkNTCP2UnframerLarge(b *testing.B) {
	testData := createTestFramedMessage(1024)
	conn := &benchmarkConn{data: testData, offset: 0}
	unframer := NewI2NPUnframer(conn)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, err := unframer.ReadNextMessage()
		if err != nil && err != io.EOF {
			b.Fatalf("ReadNextMessage failed: %v", err)
		}
		if msg == nil {
			conn.offset = 0
			msg, _ = unframer.ReadNextMessage()
		}
	}
}
