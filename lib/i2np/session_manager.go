package i2np

// SessionManager demonstrates session-related interface usage
type SessionManager struct{}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// ProcessKeys processes session keys using SessionKeyProvider interface.
// Note: This is a stub for ECIES-only routers. Key material is intentionally
// NOT logged to avoid leaking sensitive cryptographic data.
func (sm *SessionManager) ProcessKeys(provider SessionKeyProvider) error {
	// Access the keys to validate the interface, but do not log key material
	_ = provider.GetReplyKey()
	_ = provider.GetLayerKey()
	_ = provider.GetIVKey()

	log.Debug("Processing session keys (stub — ECIES-only router)")

	return nil
}

// ProcessTags processes session tags using SessionTagProvider interface.
// Note: This is a stub for ECIES-only routers. Tag data is intentionally
// NOT logged to avoid leaking sensitive cryptographic data.
func (sm *SessionManager) ProcessTags(provider SessionTagProvider) error {
	count := provider.GetTagCount()

	log.WithField("tag_count", count).Debug("Processing session tags (stub — ECIES-only router)")

	return nil
}
