package ssu2

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/transport"
	ssu2noise "github.com/go-i2p/go-noise/ssu2"
	"github.com/go-i2p/logger"
)

// TestDetachConnRace_ConcurrentAccessors exercises the R-1 fix by concurrently
// calling DetachConn (writer) and all conn accessor functions (readers).
// Run with -race to detect data races.
func TestDetachConnRace_ConcurrentAccessors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := &logger.Entry{}
	session := &SSU2Session{
		SessionCore: transport.NewSessionCore(ctx, logger),
		connMu:      sync.RWMutex{},
	}
	dummyConn := &ssu2noise.SSU2Conn{}

	var wg sync.WaitGroup

	// Goroutine 1: repeatedly call DetachConn (writer).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			session.DetachConn()
			session.connMu.Lock()
			session.conn = dummyConn
			session.connMu.Unlock()
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 2: repeatedly call Conn() (reader).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = session.Conn()
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 3: repeatedly call RemoteAddr() (reader).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = session.RemoteAddr()
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 4: repeatedly call RemoteUDPAddr() (reader).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = session.RemoteUDPAddr()
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()
}

// TestDetachConnRace_extractFuncs simulates concurrent extractSenderHash,
// extractBobRouterHash, and DetachConn to exercise the R-1 fix.
func TestDetachConnRace_extractFuncs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := &logger.Entry{}
	session := &SSU2Session{
		SessionCore: transport.NewSessionCore(ctx, logger),
		connMu:      sync.RWMutex{},
	}
	dummyConn := &ssu2noise.SSU2Conn{}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = extractSenderHash(session)
			_ = extractBobRouterHash(session)
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			session.DetachConn()
			session.connMu.Lock()
			session.conn = dummyConn
			session.connMu.Unlock()
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()
}
