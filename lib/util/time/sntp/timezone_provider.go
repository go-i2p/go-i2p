package sntp

import (
	"os"
	"runtime"
	"strings"
	"time"
)

// timezoneProvider defines the interface for obtaining timezone information.
// This allows mocking timezone detection for testing.
type timezoneProvider interface {
	detectIANATimezone() string
}

// defaultTimezoneProvider is the standard implementation used in production.
type defaultTimezoneProvider struct{}

func (p *defaultTimezoneProvider) detectIANATimezone() string {
	strategies := []func() string{
		detectTimezoneFromEtcTimezone,
		detectTimezoneFromLocaltime,
		detectTimezoneFromGoStdlib,
	}
	for _, strategy := range strategies {
		if name := strategy(); name != "" {
			return name
		}
	}
	return ""
}

var currentTimezoneProvider timezoneProvider = &defaultTimezoneProvider{}

// detectIANATimezone attempts to determine the system's IANA timezone name
// using multiple platform-appropriate strategies. Returns "" if detection
// fails. This function does not make network calls.
//
// Detection order:
//  1. /etc/timezone file (Debian/Ubuntu)
//  2. /etc/localtime symlink target (most Linux, macOS)
//  3. Go stdlib time.Now().Location() (cross-platform fallback, works on Windows)
//
// Note: TZ environment variable is intentionally not consulted to prevent
// external processes from influencing NTP peer geography selection, which
// could weaken anonymity properties. See AUDIT.md LOW finding.
func detectIANATimezone() string {
	return currentTimezoneProvider.detectIANATimezone()
}

// detectTimezoneFromEtcTimezone reads /etc/timezone (Debian, Ubuntu).
func detectTimezoneFromEtcTimezone() string {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return ""
	}
	data, err := os.ReadFile("/etc/timezone")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// detectTimezoneFromLocaltime reads /etc/localtime symlink (Linux, macOS).
func detectTimezoneFromLocaltime() string {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return ""
	}
	target, err := os.Readlink("/etc/localtime")
	if err != nil {
		return ""
	}
	return extractIANAName(target)
}

// detectTimezoneFromGoStdlib uses Go's standard library to obtain the
// system's IANA timezone name. Go internally reads platform-specific
// sources (Windows registry, /etc/localtime, etc.) and maps them to
// IANA names. Returns "" if the result is "Local" or "UTC" (which are
// not useful for geographic NTP server selection).
func detectTimezoneFromGoStdlib() string {
	name := time.Now().Location().String()
	if name == "Local" || name == "UTC" || name == "" {
		return ""
	}
	if strings.Contains(name, "/") {
		return name
	}
	return ""
}
