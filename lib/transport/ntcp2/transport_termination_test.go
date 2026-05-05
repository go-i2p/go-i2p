package ntcp2

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/logger"
	"github.com/stretchr/testify/assert"
)

type terminationWriteConn struct {
	writeN   int
	writeErr error
}

func (c *terminationWriteConn) Read([]byte) (int, error)  { return 0, errors.New("not implemented") }
func (c *terminationWriteConn) Write([]byte) (int, error) { return c.writeN, c.writeErr }
func (c *terminationWriteConn) Close() error              { return nil }
func (c *terminationWriteConn) LocalAddr() net.Addr       { return &net.TCPAddr{} }
func (c *terminationWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (c *terminationWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *terminationWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *terminationWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteTerminationBlockBestEffort_DoesNotPanicOnWriteError(t *testing.T) {
	transport := &NTCP2Transport{logger: logger.WithField("component", "ntcp2-test")}
	conn := &terminationWriteConn{writeN: 0, writeErr: errors.New("write failed")}
	term := BuildTerminationBlock(TerminationAEADFailure)

	assert.NotPanics(t, func() {
		transport.writeTerminationBlockBestEffort(conn, term)
	})
}

func TestWriteTerminationBlockBestEffort_DoesNotPanicOnShortWrite(t *testing.T) {
	transport := &NTCP2Transport{logger: logger.WithField("component", "ntcp2-test")}
	term := BuildTerminationBlock(TerminationAEADFailure)
	conn := &terminationWriteConn{writeN: len(term) - 1, writeErr: nil}

	assert.NotPanics(t, func() {
		transport.writeTerminationBlockBestEffort(conn, term)
	})
}
