package i2np

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ExpirationValidator provides configurable message expiration checking.
// I2NP messages have an expiration timestamp, and expired messages should
// be rejected to prevent replay attacks and resource waste.
type ExpirationValidator struct {
	// toleranceSeconds allows for clock skew between routers.
	// Messages that expired within this window are still accepted.
	// Default is 5 minutes (300 seconds) per I2P spec recommendations.
	toleranceSeconds int64

	// timeSource allows injection of time for testing.
	// If nil, uses time.Now().
	timeSource func() time.Time

	// enabled controls whether expiration checking is performed.
	// Default is true. Can be disabled for testing or special cases.
	enabled bool
}

// NewExpirationValidator creates a new validator with default settings.
// Default tolerance is 5 minutes to allow for reasonable clock skew.
func NewExpirationValidator() *ExpirationValidator {
	return &ExpirationValidator{
		toleranceSeconds: DefaultExpirationTolerance,
		timeSource:       nil, // Will use time.Now()
		enabled:          true,
	}
}

// WithTolerance sets the clock skew tolerance in seconds.
// Returns the validator for method chaining.
func (v *ExpirationValidator) WithTolerance(seconds int64) *ExpirationValidator {
	if seconds < 0 {
		seconds = 0
	}
	v.toleranceSeconds = seconds
	return v
}

// WithTimeSource sets a custom time source for testing.
// Returns the validator for method chaining.
func (v *ExpirationValidator) WithTimeSource(source func() time.Time) *ExpirationValidator {
	v.timeSource = source
	return v
}

// Disable turns off expiration checking.
// Returns the validator for method chaining.
func (v *ExpirationValidator) Disable() *ExpirationValidator {
	v.enabled = false
	return v
}

// Enable turns on expiration checking.
// Returns the validator for method chaining.
func (v *ExpirationValidator) Enable() *ExpirationValidator {
	v.enabled = true
	return v
}

// IsEnabled returns whether expiration checking is enabled.
func (v *ExpirationValidator) IsEnabled() bool {
	return v.enabled
}

// now returns the current time using the configured time source.
func (v *ExpirationValidator) now() time.Time {
	if v.timeSource != nil {
		return v.timeSource()
	}
	return time.Now()
}

// IsExpired checks if the given expiration time is in the past,
// accounting for the configured tolerance.
func (v *ExpirationValidator) IsExpired(expiration time.Time) bool {
	if !v.enabled {
		return false
	}

	now := v.now()
	// Add tolerance to expiration to allow for clock skew
	adjustedExpiration := expiration.Add(time.Duration(v.toleranceSeconds) * time.Second)
	return now.After(adjustedExpiration)
}

// ValidateExpiration checks if the message expiration is valid.
// Returns nil if valid, or an error describing the expiration issue.
func (v *ExpirationValidator) ValidateExpiration(expiration time.Time) error {
	if !v.enabled {
		return nil
	}

	if v.IsExpired(expiration) {
		now := v.now()
		age := now.Sub(expiration)
		return oops.Wrapf(ERR_I2NP_MESSAGE_EXPIRED,
			"message expired %v ago (expiration: %v, now: %v, tolerance: %ds)",
			age.Round(time.Second), expiration.UTC(), now.UTC(), v.toleranceSeconds)
	}
	return nil
}

// ValidateMessage checks if an I2NP message has expired.
// Returns nil if valid, or an error if the message has expired.
func (v *ExpirationValidator) ValidateMessage(msg I2NPMessage) error {
	if !v.enabled {
		return nil
	}

	expiration := msg.Expiration()
	if err := v.ValidateExpiration(expiration); err != nil {
		log.WithFields(logger.Fields{
			"at":         "ExpirationValidator.ValidateMessage",
			"type":       msg.Type(),
			"message_id": msg.MessageID(),
			"expiration": expiration.UTC(),
			"now":        v.now().UTC(),
		}).Warn("rejecting expired message")
		return err
	}
	return nil
}

// CheckMessageExpiration is a convenience function that validates message expiration
// using the default validator settings (5 minute tolerance).
func CheckMessageExpiration(msg I2NPMessage) error {
	defaultValidatorMu.RLock()
	v := defaultExpirationValidator
	defaultValidatorMu.RUnlock()
	return v.ValidateMessage(msg)
}

// IsMessageExpired is a convenience function that checks if a message is expired
// using the default validator settings (5 minute tolerance).
func IsMessageExpired(msg I2NPMessage) bool {
	defaultValidatorMu.RLock()
	v := defaultExpirationValidator
	defaultValidatorMu.RUnlock()
	return v.IsExpired(msg.Expiration())
}

// defaultExpirationValidator is a package-level validator with default settings.
var defaultExpirationValidator = NewExpirationValidator()

// defaultValidatorMu protects concurrent access to defaultExpirationValidator.
var defaultValidatorMu sync.RWMutex

// SetDefaultExpirationValidator replaces the default validator.
// This is primarily useful for testing.
func SetDefaultExpirationValidator(v *ExpirationValidator) {
	if v != nil {
		defaultValidatorMu.Lock()
		defaultExpirationValidator = v
		defaultValidatorMu.Unlock()
	}
}

// ResetDefaultExpirationValidator resets to a fresh default validator.
func ResetDefaultExpirationValidator() {
	defaultValidatorMu.Lock()
	defaultExpirationValidator = NewExpirationValidator()
	defaultValidatorMu.Unlock()
}
