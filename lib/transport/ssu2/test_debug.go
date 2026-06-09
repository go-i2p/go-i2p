//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"sync/atomic"

	"github.com/go-i2p/go-i2p/lib/transport/ssu2"
)

func main() {
	transport := &ssu2.SSU2Transport{}
	hash := [32]byte{1, 2, 3}
	transport.sessions.Store(hash, &ssu2.SSU2Session{})
	atomic.StoreInt32(&transport.sessionCount, 5)

	fmt.Printf("Before: sessionCount=%d\n", atomic.LoadInt32(&transport.sessionCount))
	_, found := transport.sessions.Load(hash)
	fmt.Printf("Before: session in map=%v\n", found)

	// Call removeSession
	transport.removeSession(hash)

	fmt.Printf("After: sessionCount=%d\n", atomic.LoadInt32(&transport.sessionCount))
	_, found = transport.sessions.Load(hash)
	fmt.Printf("After: session in map=%v\n", found)
}
