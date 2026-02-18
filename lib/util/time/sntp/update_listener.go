package sntp

import "time"

// UpdateListener is an interface that listeners must implement to receive time updates.
type UpdateListener interface {
	SetNow(now time.Time, stratum uint8)
}

// ExtendedUpdateListener is an optional interface that listeners may implement
// to receive additional notifications about NTP synchronization state changes.
// Implementations are checked via type assertion; existing UpdateListener
// implementations continue to work without modification.
type ExtendedUpdateListener interface {
	UpdateListener
	// OnInitialized is called when the SNTP subsystem completes its first sync.
	OnInitialized()
	// OnSyncFailure is called when an NTP query cycle fails.
	OnSyncFailure(consecutiveFails int)
	// OnSyncLost is called when consecutive failures exceed the threshold.
	OnSyncLost()
}

// ListenerIdentifier is an optional interface that listeners may implement
// to provide a stable identity for removal via RemoveListener. When implemented,
// RemoveListener compares ListenerID() values instead of using pointer equality.
type ListenerIdentifier interface {
	ListenerID() string
}
