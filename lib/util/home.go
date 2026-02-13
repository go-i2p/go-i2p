package util

import (
	"os"
)

// UserHome returns the current user's home directory.
// Falls back to $HOME environment variable if os.UserHomeDir fails.
// Panics if no home directory can be determined, as storing I2P key material
// in a world-readable temp directory would be a critical security vulnerability.
func UserHome() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback: try $HOME directly (works on most Unix systems)
		if home := os.Getenv("HOME"); home != "" {
			log.WithError(err).Warn("os.UserHomeDir failed, falling back to $HOME")
			return home
		}
		// Last resort on Windows
		if home := os.Getenv("USERPROFILE"); home != "" {
			log.WithError(err).Warn("os.UserHomeDir failed, falling back to USERPROFILE")
			return home
		}
		// SECURITY: Do NOT fall back to os.TempDir() — it is world-readable on most
		// Linux systems, and I2P stores cryptographic key material under the home directory.
		// Storing keys in /tmp would allow any local process to steal the router's identity.
		panic("go-i2p: unable to determine home directory; set $HOME environment variable. " +
			"Refusing to fall back to temp directory for security reasons.")
	}

	return homeDir
}
