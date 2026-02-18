package sntp

import (
	"bufio"
	"embed"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed zone_to_country.txt
var zoneToCountryFS embed.FS

// timezoneCountryMap maps IANA timezone names (e.g. "America/New_York") to
// ISO 3166-1 alpha-2 country codes (e.g. "us"). Built once from the
// embedded zone_to_country.txt on first access.
var (
	timezoneCountryMap  map[string]string
	timezoneCountryOnce sync.Once
)

// loadTimezoneCountryMap parses the embedded zone_to_country.txt file.
// Each line has the format "TimezoneName,CC" (e.g. "America/New_York,US").
func loadTimezoneCountryMap() map[string]string {
	m := make(map[string]string, 420)

	f, err := zoneToCountryFS.Open("zone_to_country.txt")
	if err != nil {
		log.WithError(err).Warn("Failed to open zone_to_country.txt")
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		tz := strings.TrimSpace(parts[0])
		cc := strings.ToLower(strings.TrimSpace(parts[1]))
		if tz != "" && cc != "" {
			m[tz] = cc
		}
	}

	return m
}

// getTimezoneCountryMap returns the timezone→country map, loading it once.
func getTimezoneCountryMap() map[string]string {
	timezoneCountryOnce.Do(func() {
		timezoneCountryMap = loadTimezoneCountryMap()
	})
	return timezoneCountryMap
}

// lookupCountryByTimezone returns the lowercase ISO country code for an
// IANA timezone name, or "" if not found.
func lookupCountryByTimezone(tzName string) string {
	m := getTimezoneCountryMap()
	if cc, ok := m[tzName]; ok {
		return cc
	}
	return ""
}

// detectIANATimezone attempts to determine the system's IANA timezone name
// using multiple platform-appropriate strategies. Returns "" if detection
// fails. This function does not make network calls.
//
// Detection order:
//  1. TZ environment variable (explicit user override)
//  2. /etc/timezone file (Debian/Ubuntu)
//  3. /etc/localtime symlink target (most Linux, macOS)
//  4. Go stdlib time.Now().Location() (cross-platform fallback, works on Windows)
func detectIANATimezone() string {
	// Strategy 1: TZ environment variable. Users may set this explicitly.
	if tz := os.Getenv("TZ"); tz != "" {
		// TZ can be a path (e.g. ":/usr/share/zoneinfo/America/New_York")
		// or a bare IANA name (e.g. "America/New_York"). Strip leading ":".
		tz = strings.TrimPrefix(tz, ":")
		if name := extractIANAName(tz); name != "" {
			return name
		}
	}

	// Strategy 2: /etc/timezone (Debian, Ubuntu, and derivatives).
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" {
			return name
		}
	}

	// Strategy 3: /etc/localtime symlink (most Linux distros, macOS).
	// The symlink typically points to /usr/share/zoneinfo/<Area>/<Location>.
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if name := extractIANAName(target); name != "" {
			return name
		}
	}

	// Strategy 4: Go's time.Now().Location() (cross-platform fallback).
	// On Windows, Go reads the registry key
	// HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation and maps
	// the Windows timezone name to an IANA name via its embedded mapping
	// table. On all platforms, this returns the IANA timezone name if
	// the system timezone is configured. "Local" is returned when the
	// name cannot be determined, which is not a valid IANA name.
	if name := detectTimezoneFromGoStdlib(); name != "" {
		return name
	}

	return ""
}

// detectTimezoneFromGoStdlib uses Go's standard library to obtain the
// system's IANA timezone name. Go internally reads platform-specific
// sources (Windows registry, /etc/localtime, etc.) and maps them to
// IANA names. Returns "" if the result is "Local" or "UTC" (which are
// not useful for geographic NTP server selection).
func detectTimezoneFromGoStdlib() string {
	name := time.Now().Location().String()
	// "Local" means Go couldn't determine the timezone name.
	// "UTC" is valid but doesn't help with geographic NTP selection.
	if name == "Local" || name == "" {
		return ""
	}
	// Validate it looks like an IANA name (contains "/").
	if strings.Contains(name, "/") {
		return name
	}
	return ""
}

// extractIANAName extracts an IANA timezone name from a path or string.
// It looks for the "zoneinfo/" prefix and returns everything after it.
// For bare IANA names like "America/New_York", it validates they contain
// a "/" and returns them directly.
func extractIANAName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Check for path containing "zoneinfo/" (e.g. "/usr/share/zoneinfo/America/New_York")
	if idx := strings.Index(s, "zoneinfo/"); idx != -1 {
		name := s[idx+len("zoneinfo/"):]
		if name != "" {
			return name
		}
	}

	// If it looks like a bare IANA name (contains "/" but doesn't start with "/")
	if !strings.HasPrefix(s, "/") && strings.Contains(s, "/") {
		return s
	}

	return ""
}
