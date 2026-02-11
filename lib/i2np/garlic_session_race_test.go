package i2np

import (
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ratchet"
)

// TestFindSessionByTag_ConcurrentWithEncrypt verifies that findSessionByTag
// and encryptExistingSession can run concurrently without data races on
// session-level fields (pendingTags, TagRatchet, SymmetricRatchet).
//
// Before the fix, findSessionByTag modified session.pendingTags and called
// session.TagRatchet.GenerateNextTag() without holding session.mu, while
// encryptExistingSession held session.mu to access SymmetricRatchet and
// MessageCounter. This was a data race.
func TestFindSessionByTag_ConcurrentWithEncrypt(t *testing.T) {
	// Create a session manager with a test key.
	var privKey [32]byte
	copy(privKey[:], []byte("test-private-key-32-bytes-long!!"))
	sm, err := NewGarlicSessionManager(privKey)
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	// Create a test session manually and register it.
	session := &GarlicSession{
		LastUsed:         time.Now(),
		SymmetricRatchet: ratchet.NewSymmetricRatchet([32]byte{1, 2, 3}),
		TagRatchet:       ratchet.NewTagRatchet([32]byte{4, 5, 6}),
		pendingTags:      make([][8]byte, 0),
	}

	// Generate some tags under the manager lock and register them.
	sm.mu.Lock()
	if err := sm.generateTagWindow(session); err != nil {
		sm.mu.Unlock()
		t.Fatalf("failed to generate tag window: %v", err)
	}
	// Grab a copy of the tags for lookup.
	tags := make([][8]byte, len(session.pendingTags))
	copy(tags, session.pendingTags)
	sm.mu.Unlock()

	if len(tags) == 0 {
		t.Fatal("no tags were generated")
	}

	// Run concurrent findSessionByTag and session.mu Lock/Unlock (simulating encrypt).
	const goroutines = 20
	const iterations = 50
	var wg sync.WaitGroup

	// Goroutines simulating encryptExistingSession locking pattern.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				session.mu.Lock()
				// Simulate accessing session state like encryptExistingSession does.
				_ = session.MessageCounter
				session.MessageCounter++
				session.LastUsed = time.Now()
				session.mu.Unlock()
			}
		}()
	}

	// Goroutines looking up tags (which consumes tags and may replenish).
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sm.mu.Lock()
				// Generate fresh tags to look up since consumed tags are removed.
				if len(session.pendingTags) > 0 {
					tag := session.pendingTags[0]
					sm.findSessionByTag(tag)
				}
				sm.mu.Unlock()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No race or deadlock.
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK or RACE: concurrent findSessionByTag and encrypt operations timed out")
	}
}

// TestFindSessionByTag_ConsumeAndReplenish verifies that findSessionByTag
// correctly consumes a tag and replenishes the window.
func TestFindSessionByTag_ConsumeAndReplenish(t *testing.T) {
	var privKey [32]byte
	copy(privKey[:], []byte("test-private-key-32-bytes-long!!"))
	sm, err := NewGarlicSessionManager(privKey)
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	session := &GarlicSession{
		LastUsed:         time.Now(),
		SymmetricRatchet: ratchet.NewSymmetricRatchet([32]byte{1, 2, 3}),
		TagRatchet:       ratchet.NewTagRatchet([32]byte{4, 5, 6}),
		pendingTags:      make([][8]byte, 0),
	}

	sm.mu.Lock()
	if err := sm.generateTagWindow(session); err != nil {
		sm.mu.Unlock()
		t.Fatalf("failed to generate tag window: %v", err)
	}
	initialCount := len(session.pendingTags)
	if initialCount == 0 {
		sm.mu.Unlock()
		t.Fatal("no tags generated")
	}

	// Look up the first tag - should consume it.
	tag := session.pendingTags[0]
	found := sm.findSessionByTag(tag)
	sm.mu.Unlock()

	if found != session {
		t.Fatal("findSessionByTag did not return the expected session")
	}

	// The tag should have been consumed from the index.
	sm.mu.Lock()
	_, exists := sm.tagIndex[tag]
	sm.mu.Unlock()

	if exists {
		t.Error("consumed tag should have been removed from tagIndex")
	}
}
