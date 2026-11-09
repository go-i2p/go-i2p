package embedded

import "time"

// ──────────────────────────────────────────────────────────────────────────────
// Extracted certificate permissions
// ──────────────────────────────────────────────────────────────────────────────

// Bundled certificates are public trust material — reseed signing keys, root CA
// certificates — that the router only ever reads. They are world-readable so a
// router running under a different account than the installer can still verify a
// reseed, and the directories carry the execute bit they need to be traversed.
// Unlike the keystore files, nothing here is secret, so the permissive modes are
// deliberate rather than an oversight.
//
// Moved from: certificates.go
const (
	// certificateDirMode is the permission for extracted certificate directories.
	certificateDirMode = 0o755

	// certificateFileMode is the permission for extracted certificate files.
	certificateFileMode = 0o644
)

// ──────────────────────────────────────────────────────────────────────────────
// Shutdown deadlines
// ──────────────────────────────────────────────────────────────────────────────

// Moved from: shutdown.go
const (
	// hardStopTimeout bounds the graceful attempt HardStop makes before forcing
	// resource release. It is short on purpose: HardStop is the path taken when a
	// normal Stop has already failed or the caller wants out now, so waiting long
	// for a clean shutdown would defeat the point.
	hardStopTimeout = 5 * time.Second
)
