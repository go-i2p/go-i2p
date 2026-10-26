// Benchmarks for the spec-compliant NTCP2 block unframer. Measures the cost of
// decoding a data-phase frame: the 2-byte SipHash-obfuscated length is handled
// below this layer by NTCP2Conn.Read (ntcp2.rst:1314-1355), and the decrypted
// payload is a sequence of NTCP2 blocks (ntcp2.rst:1428-1447).
//
// These replace the benchmarks that used to target the non-spec I2NPUnframer,
// which read a 4-byte length prefix that appears nowhere in ntcp2.rst and was
// therefore removed.

package ntcp2

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
)

// loopConn is a net.Conn that re-serves the same frame payload forever, so a
// benchmark can decode the same frame repeatedly without a real socket. The
// unframer performs one Read per frame, which is all this needs to provide.
type loopConn struct {
	data   []byte
	offset int
}

func (c *loopConn) Read(p []byte) (n int, err error) {
	if c.offset >= len(c.data) {
		c.offset = 0 // loop
	}
	n = copy(p, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *loopConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *loopConn) Close() error                       { return nil }
func (c *loopConn) LocalAddr() net.Addr                { return &mockAddr{"loop-local"} }
func (c *loopConn) RemoteAddr() net.Addr               { return &mockAddr{"loop-remote"} }
func (c *loopConn) SetDeadline(t time.Time) error      { return nil }
func (c *loopConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *loopConn) SetWriteDeadline(t time.Time) error { return nil }

// createBlockFramedMessage returns the decrypted data-phase frame payload for
// an I2NP message carrying a payloadSize-byte body — exactly what
// BlockUnframer.readFrame hands to ParseBlocks on the live receive path.
func createBlockFramedMessage(b *testing.B, payloadSize int) []byte {
	b.Helper()
	var key [32]byte // Zero hash
	testData := make([]byte, payloadSize)
	msg := i2np.NewDatabaseStore(key, testData, 0)

	framed, err := FrameI2NPMessageAsBlock(msg)
	if err != nil {
		b.Fatalf("FrameI2NPMessageAsBlock failed: %v", err)
	}
	return framed
}

func benchmarkBlockUnframer(b *testing.B, payloadSize int) {
	conn := &loopConn{data: createBlockFramedMessage(b, payloadSize)}
	u := NewBlockUnframer(conn)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		msg, err := u.ReadNextMessage()
		if err != nil {
			b.Fatalf("ReadNextMessage failed: %v", err)
		}
		if msg == nil {
			b.Fatal("ReadNextMessage returned no message")
		}
	}
}

// BenchmarkBlockUnframer benchmarks the spec-compliant block decode path.
func BenchmarkBlockUnframer(b *testing.B) { benchmarkBlockUnframer(b, 100) }

// BenchmarkBlockUnframerSmall benchmarks with small messages (32 bytes).
func BenchmarkBlockUnframerSmall(b *testing.B) { benchmarkBlockUnframer(b, 32) }

// BenchmarkBlockUnframerLarge benchmarks with large messages (1KB).
func BenchmarkBlockUnframerLarge(b *testing.B) { benchmarkBlockUnframer(b, 1024) }
