package i2np

import (
	"testing"
)

// FuzzGarlicDecrypt exercises the garlic/ECIES decrypt entry
// (GarlicSessionManager.DecryptGarlicMessage). Garlic cloves arrive from
// arbitrary remote destinations; the ECIES + ratchet decrypt chain parses
// remote-supplied bytes and was previously unfuzzed (C3). A panic here would
// crash the garlic router while handling an untrusted message.
//
// Scope note: a full session requires a prior NS/NSR handshake, so this target
// fuzzes the byte-level decrypt entry with a fresh (session-less) manager —
// every input is a New Session / malformed clove, which is exactly the
// untrusted-input surface the audit flagged.
func FuzzGarlicDecrypt(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 200))

	sm, err := GenerateGarlicSessionManager()
	if err != nil {
		f.Fatalf("GenerateGarlicSessionManager failed: %v", err)
	}
	defer sm.Close()

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must return an error on malformed garlic, not panic.
		_, _, _, _ = sm.DecryptGarlicMessage(data)
	})
}
