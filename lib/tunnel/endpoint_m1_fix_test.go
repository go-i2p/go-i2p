package tunnel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureAssemblerExists_ConflictingFirstFragment_RejectsWhenTypeChanges
// M-1 FIX regression test: Verifies that conflicting delivery types for the same
// message ID are rejected (not silently merged). This prevents a compromised
// gateway from altering the delivery routing mid-reassembly.
// Invariant: All fragments of one message ID share the first fragment's delivery
// instructions per I2P tunnel-message spec; a conflicting first fragment must be
// rejected, not merged.
func TestEnsureAssemblerExists_ConflictingFirstFragment_RejectsWhenTypeChanges(t *testing.T) {
	ep := &Endpoint{
		handler:         func(msgBytes []byte) error { return nil },
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
	}

	msgID := uint32(12345)

	// Scenario: First fragment arrives claiming DTLocal delivery
	ep.fragmentsMutex.Lock()
	asm1, err1 := ep.ensureAssemblerExists(msgID, byte(DTLocal))
	ep.fragmentsMutex.Unlock()
	require.NoError(t, err1, "first fragment DTLocal should succeed")
	require.NotNil(t, asm1)

	// Record that first fragment arrived
	ep.fragmentsMutex.Lock()
	asm1.firstFragmentReceived = true
	ep.fragmentsMutex.Unlock()

	// Scenario: Second conflicting "first fragment" arrives claiming DTRouter delivery
	// This should be rejected (conflicting delivery type).
	ep.fragmentsMutex.Lock()
	asm2, err2 := ep.ensureAssemblerExists(msgID, byte(DTRouter))
	ep.fragmentsMutex.Unlock()

	// Must return an error, not succeed and change the type
	assert.Error(t, err2, "conflicting delivery type should be rejected")
	assert.Nil(t, asm2, "should return nil assembler when conflict detected")

	// Verify the original delivery type was not changed
	ep.fragmentsMutex.Lock()
	originalAsm := ep.fragments[msgID]
	ep.fragmentsMutex.Unlock()
	assert.Equal(t, byte(DTLocal), originalAsm.deliveryType,
		"original delivery type (DTLocal) should not be modified by conflicting fragment")
}

// TestEnsureAssemblerExists_DuplicateFirstFragment_Rejected
// M-1 FIX regression test: Verifies that duplicate first fragments (same delivery
// type) are also rejected. The spec requires each fragment set to have exactly one
// first fragment; receiving two is an error condition.
func TestEnsureAssemblerExists_DuplicateFirstFragment_Rejected(t *testing.T) {
	ep := &Endpoint{
		handler:         func(msgBytes []byte) error { return nil },
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
	}

	msgID := uint32(54321)
	deliveryType := byte(DTRouter)

	// First fragment arrives
	ep.fragmentsMutex.Lock()
	asm1, err1 := ep.ensureAssemblerExists(msgID, deliveryType)
	ep.fragmentsMutex.Unlock()
	require.NoError(t, err1)
	require.NotNil(t, asm1)

	// Mark first fragment as received
	ep.fragmentsMutex.Lock()
	asm1.firstFragmentReceived = true
	ep.fragmentsMutex.Unlock()

	// Duplicate first fragment (same delivery type) should also be rejected
	ep.fragmentsMutex.Lock()
	asm2, err2 := ep.ensureAssemblerExists(msgID, deliveryType)
	ep.fragmentsMutex.Unlock()

	assert.Error(t, err2, "duplicate first fragment should be rejected")
	assert.Nil(t, asm2, "should return nil assembler for duplicate")
}

// TestEnsureAssemblerExists_OrphanFollowOnFragmentThenFirstFragment
// M-1 FIX regression test: Verifies correct handling of follow-on fragments
// arriving before the first fragment. When the first fragment later arrives,
// its delivery type should be properly set, and the assembler should work correctly.
func TestEnsureAssemblerExists_OrphanFollowOnFragmentThenFirstFragment(t *testing.T) {
	ep := &Endpoint{
		handler:         func(msgBytes []byte) error { return nil },
		fragments:       make(map[uint32]*fragmentAssembler),
		fragmentTimeout: 60 * time.Second,
	}

	msgID := uint32(99999)
	deliveryType := byte(DTRouter)

	// Simulate: Follow-on fragment arrives first (orphan arrival due to packet loss/reorder)
	ep.fragmentsMutex.Lock()
	asmFollowOn := ep.getOrCreateAssembler(msgID)
	ep.fragmentsMutex.Unlock()
	require.NotNil(t, asmFollowOn, "follow-on fragment should create assembler with unknown type")

	// Now the actual first fragment arrives with delivery type DTRouter
	ep.fragmentsMutex.Lock()
	asm, err := ep.ensureAssemblerExists(msgID, deliveryType)
	ep.fragmentsMutex.Unlock()

	require.NoError(t, err, "first fragment after orphan follow-on should succeed")
	require.NotNil(t, asm)

	// Verify delivery type was set correctly from the first fragment
	assert.Equal(t, deliveryType, asm.deliveryType,
		"first fragment should set the delivery type even after orphan follow-ons")

	// Verify it's the same assembler instance (not recreated)
	assert.Equal(t, asmFollowOn, asm, "should reuse assembler created by follow-on fragment")
}

// TestEnsureAssemblerExists_AllDeliveryTypesRejected
// M-1 FIX regression test: Verify that all delivery types are subject to the
// conflict-rejection logic (not just specific types).
func TestEnsureAssemblerExists_AllDeliveryTypesRejected(t *testing.T) {
	deliveryTypes := []struct {
		name string
		dt   byte
	}{
		{"DTLocal", byte(DTLocal)},
		{"DTTunnel", byte(DTTunnel)},
		{"DTRouter", byte(DTRouter)},
	}

	for _, tc := range deliveryTypes {
		t.Run(tc.name, func(t *testing.T) {
			ep := &Endpoint{
				handler:         func(msgBytes []byte) error { return nil },
				fragments:       make(map[uint32]*fragmentAssembler),
				fragmentTimeout: 60 * time.Second,
			}

			msgID := uint32(1000 + int(tc.dt))

			// First fragment of type tc.dt
			ep.fragmentsMutex.Lock()
			asm1, _ := ep.ensureAssemblerExists(msgID, byte(tc.dt))
			asm1.firstFragmentReceived = true
			ep.fragmentsMutex.Unlock()

			// Any attempt to change the type should fail
			// For DTLocal, use DTTunnel; for others, cycle back to DTLocal
			var otherType byte
			if tc.dt == byte(DTLocal) {
				otherType = byte(DTTunnel)
			} else {
				otherType = byte(DTLocal)
			}

			ep.fragmentsMutex.Lock()
			asm2, err := ep.ensureAssemblerExists(msgID, byte(otherType))
			ep.fragmentsMutex.Unlock()

			assert.Error(t, err, "delivery type %s: conflicting fragment should be rejected", tc.name)
			assert.Nil(t, asm2)
		})
	}
}
