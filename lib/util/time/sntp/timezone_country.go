package sntp

import (
	"bufio"
	"embed"
	"io"
	"os"
	"runtime"
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
	f, err := zoneToCountryFS.Open("zone_to_country.txt")
	if err != nil {
		log.WithError(err).Warn("Failed to open zone_to_country.txt")
		return make(map[string]string, 420)
	}
	defer func() { _ = f.Close() }()

	m, err := parseTimezoneCountryMap(f)
	if err != nil {
		log.WithError(err).Warn("Failed to parse zone_to_country.txt")
	}

	return m
}

func parseTimezoneCountryMap(r io.Reader) (map[string]string, error) {
	m := make(map[string]string, 420)
	scanner := bufio.NewScanner(r)
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
	if err := scanner.Err(); err != nil {
		return m, err
	}

	return m, nil
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
//  1. /etc/timezone file (Debian/Ubuntu)
//  2. /etc/localtime symlink target (most Linux, macOS)
//  3. Go stdlib time.Now().Location() (cross-platform fallback, works on Windows)
//
// Note: TZ environment variable is intentionally not consulted to prevent
// external processes from influencing NTP peer geography selection, which
// could weaken anonymity properties. See AUDIT.md LOW finding.
func detectIANATimezone() string {
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

// detectTimezoneFromEtcTimezone reads /etc/timezone (Debian, Ubuntu).
// Only attempted on Linux and Darwin where the file may exist.
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
// Only attempted on Linux and Darwin where the file may exist.
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
	// "Local" means Go couldn't determine the timezone name.
	// "UTC" is valid but doesn't help with geographic NTP selection.
	if name == "Local" || name == "UTC" || name == "" {
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
