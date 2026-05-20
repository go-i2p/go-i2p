package home

import (
	"os"
)

// UserHome returns the current user's home directory.
// Falls back to $HOME environment variable if os.UserHomeDir fails.
// Then falls back to os.UserConfigDir() (~/.config or %LOCALAPPDATA%).
// As a last resort, uses the current working directory rather than panicking,
// which allows operation in containerized environments where $HOME may not be set.
func UserHome() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback: try $HOME directly (works on most Unix systems)
		if home := os.Getenv("HOME"); home != "" {
			log.WithError(err).Warn("os.UserHomeDir failed, falling back to $HOME")
			return home
		}
		// Fallback on Windows: try $USERPROFILE
		if home := os.Getenv("USERPROFILE"); home != "" {
			log.WithError(err).Warn("os.UserHomeDir failed, falling back to USERPROFILE")
			return home
		}
		// Fallback: use os.UserConfigDir() which is usually more reliable than home dir
		// (returns ~/.config on Unix, %LOCALAPPDATA% on Windows)
		if configDir, configErr := os.UserConfigDir(); configErr == nil {
			log.WithError(err).Warn("os.UserHomeDir failed, falling back to os.UserConfigDir")
			return configDir
		}
		// Final fallback: use the current working directory. This is less secure
		// than a proper home/config directory but preferable to panicking during package
		// initialization (which crashes the process before it can even start).
		// SECURITY NOTE: Callers should verify directory permissions before
		// storing key material; this is handled by the keystore's 0700 mkdir.
		if wd, wdErr := os.Getwd(); wdErr == nil {
			log.WithError(err).Warn("os.UserHomeDir and os.UserConfigDir unavailable; falling back to working directory")
			return wd
		}
		panic("go-i2p: unable to determine home directory; set $HOME environment variable. " +
			"Refusing to fall back to temp directory for security reasons.")
	}

	return homeDir
}
