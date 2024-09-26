package sntp

import "time"

// UpdateListener is an interface that listeners must implement to receive time updates.
type UpdateListener interface {
	SetNow(now time.Time, stratum uint8)
}
