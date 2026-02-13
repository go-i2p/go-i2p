package i2np

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestExpirationValidatorConcurrentAccess verifies that concurrent reads and
// writes to the default expiration validator do not race.
// This test is designed to trigger the race detector.
func TestExpirationValidatorConcurrentAccess(t *testing.T) {
	// Reset to a known state
	ResetDefaultExpirationValidator()

	var wg sync.WaitGroup

	// Concurrent writers: swap the validator
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				v := NewExpirationValidator().WithTolerance(int64(j))
				SetDefaultExpirationValidator(v)
			}
		}()
	}

	// Concurrent writers: reset
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ResetDefaultExpirationValidator()
			}
		}()
	}

	// Concurrent readers: check expiration
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				// IsMessageExpired reads the default validator
				expired := IsMessageExpired(&mockI2NPMessage{
					expiration: time.Now().Add(1 * time.Hour),
				})
				_ = expired
			}
		}()
	}

	wg.Wait()
}

// TestSetDefaultExpirationValidatorNil verifies that nil is rejected
func TestSetDefaultExpirationValidatorNil(t *testing.T) {
	ResetDefaultExpirationValidator()

	// Setting nil should be a no-op
	SetDefaultExpirationValidator(nil)

	// Validator should still work
	expired := IsMessageExpired(&mockI2NPMessage{
		expiration: time.Now().Add(1 * time.Hour),
	})
	assert.False(t, expired, "future message should not be expired")
}

// mockI2NPMessage is a minimal I2NPMessage implementation for testing
type mockI2NPMessage struct {
	expiration time.Time
}

func (m *mockI2NPMessage) Type() int                         { return 0 }
func (m *mockI2NPMessage) MessageID() int                    { return 0 }
func (m *mockI2NPMessage) SetMessageID(id int)               {}
func (m *mockI2NPMessage) Expiration() time.Time             { return m.expiration }
func (m *mockI2NPMessage) SetExpiration(exp time.Time)       {}
func (m *mockI2NPMessage) MarshalBinary() ([]byte, error)    { return nil, nil }
func (m *mockI2NPMessage) UnmarshalBinary(data []byte) error { return nil }
