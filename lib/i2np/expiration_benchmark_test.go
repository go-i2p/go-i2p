package i2np

import (
	"testing"
	"time"
)

func BenchmarkExpirationValidator_IsExpired(b *testing.B) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	v := NewExpirationValidator().
		WithTolerance(300).
		WithTimeSource(func() time.Time { return now })

	expiration := now.Add(5 * time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.IsExpired(expiration)
	}
}

func BenchmarkExpirationValidator_ValidateMessage(b *testing.B) {
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	v := NewExpirationValidator().
		WithTolerance(300).
		WithTimeSource(func() time.Time { return now })

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetExpiration(now.Add(5 * time.Minute))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ValidateMessage(msg)
	}
}

func BenchmarkCheckMessageExpiration(b *testing.B) {
	defer ResetDefaultExpirationValidator()

	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	SetDefaultExpirationValidator(
		NewExpirationValidator().
			WithTolerance(300).
			WithTimeSource(func() time.Time { return now }),
	)

	msg := NewBaseI2NPMessage(I2NP_MESSAGE_TYPE_DATA)
	msg.SetExpiration(now.Add(5 * time.Minute))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckMessageExpiration(msg)
	}
}
