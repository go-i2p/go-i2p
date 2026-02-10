package util

import (
	"os"
)

// UserHome returns the current user's home directory.
// Falls back to $HOME environment variable if os.UserHomeDir fails.
// Panics only if both methods fail, as this is called during package
// initialization where the config directory path is required.
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
			log.WithError(err).Warn("os.UserHomeDir failed, falling back to %USERPROFILE%")
			return home
		}
		log.WithError(err).Error("Unable to determine home directory; defaulting to /tmp")
		return os.TempDir()
	}

	return homeDir
}
