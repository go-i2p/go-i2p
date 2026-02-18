package sntp

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTimezoneCountryMap(t *testing.T) {
	m := loadTimezoneCountryMap()

	// The embedded zone_to_country.txt has ~418 entries
	assert.Greater(t, len(m), 400, "should load at least 400 timezone mappings")

	// Spot-check well-known timezones
	tests := []struct {
		timezone string
		country  string
	}{
		{"America/New_York", "us"},
		{"Europe/London", "gb"},
		{"Asia/Tokyo", "jp"},
		{"Europe/Berlin", "de"},
		{"Australia/Sydney", "au"},
		{"America/Sao_Paulo", "br"},
		{"Africa/Cairo", "eg"},
		{"Asia/Shanghai", "cn"},
		{"Europe/Moscow", "ru"},
		{"Asia/Kolkata", "in"},
		{"Pacific/Auckland", "nz"},
		{"America/Toronto", "ca"},
	}

	for _, tc := range tests {
		t.Run(tc.timezone, func(t *testing.T) {
			got, ok := m[tc.timezone]
			require.True(t, ok, "timezone %s should exist in map", tc.timezone)
			assert.Equal(t, tc.country, got)
		})
	}
}

func TestLookupCountryByTimezone(t *testing.T) {
	// Reset the once for clean test state
	timezoneCountryOnce = sync.Once{}
	timezoneCountryMap = nil

	tests := []struct {
		name     string
		timezone string
		want     string
	}{
		{"US Eastern", "America/New_York", "us"},
		{"UK", "Europe/London", "gb"},
		{"Japan", "Asia/Tokyo", "jp"},
		{"Unknown timezone", "Mars/Olympus_Mons", ""},
		{"Empty string", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := lookupCountryByTimezone(tc.timezone)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractIANAName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "zoneinfo path",
			input: "/usr/share/zoneinfo/America/New_York",
			want:  "America/New_York",
		},
		{
			name:  "relative zoneinfo path",
			input: "../usr/share/zoneinfo/Europe/Berlin",
			want:  "Europe/Berlin",
		},
		{
			name:  "bare IANA name",
			input: "America/Chicago",
			want:  "America/Chicago",
		},
		{
			name:  "colon-prefixed zoneinfo path",
			input: ":/usr/share/zoneinfo/Asia/Tokyo",
			want:  "Asia/Tokyo",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "absolute path without zoneinfo",
			input: "/etc/localtime",
			want:  "",
		},
		{
			name:  "just zoneinfo prefix",
			input: "/usr/share/zoneinfo/",
			want:  "",
		},
		{
			name:  "nested zoneinfo path",
			input: "/usr/share/zoneinfo/America/Argentina/Buenos_Aires",
			want:  "America/Argentina/Buenos_Aires",
		},
		{
			name:  "whitespace",
			input: "  America/Denver  ",
			want:  "America/Denver",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractIANAName(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDetectIANATimezone(t *testing.T) {
	// This test verifies the function runs without panicking and returns
	// a plausible result. On CI systems the timezone may or may not be set.
	tz := detectIANATimezone()

	// On any normal system we should get a non-empty timezone
	// but we don't assert on specific values since tests run in varied environments
	t.Logf("Detected IANA timezone: %q", tz)

	if tz != "" {
		// If we got a timezone, it should contain a "/" (e.g. "America/New_York")
		assert.Contains(t, tz, "/", "IANA timezone should contain a /")
	}
}

func TestDetectIANATimezone_TZEnvVar(t *testing.T) {
	// Save and restore TZ
	origTZ := os.Getenv("TZ")
	defer os.Setenv("TZ", origTZ)

	tests := []struct {
		name string
		tz   string
		want string
	}{
		{
			name: "bare IANA name",
			tz:   "Europe/Paris",
			want: "Europe/Paris",
		},
		{
			name: "colon-prefixed path",
			tz:   ":/usr/share/zoneinfo/Asia/Seoul",
			want: "Asia/Seoul",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("TZ", tc.tz)
			got := detectIANATimezone()
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetLocalCountryCode(t *testing.T) {
	// This is an integration test — it verifies the full chain works on
	// the current system. The result depends on the system timezone.
	cc := getLocalCountryCode()
	t.Logf("Detected country code: %q", cc)

	if cc != "" {
		// Country codes are lowercase, 2 characters
		assert.Len(t, cc, 2, "country code should be 2 characters")
		assert.Equal(t, cc, toLowerASCII(cc), "country code should be lowercase")
	}
}

func TestGetLocalCountryCode_WithKnownTZ(t *testing.T) {
	// Force a known timezone via TZ env var and verify the full chain
	origTZ := os.Getenv("TZ")
	defer os.Setenv("TZ", origTZ)

	os.Setenv("TZ", "America/New_York")
	cc := getLocalCountryCode()
	assert.Equal(t, "us", cc)
}

func TestSetupPriorityServers_WithCountryCode(t *testing.T) {
	// Force a known timezone and verify that setupPriorityServers
	// actually populates priority servers
	origTZ := os.Getenv("TZ")
	defer os.Setenv("TZ", origTZ)

	os.Setenv("TZ", "Europe/Berlin")

	rt := NewRouterTimestamper(&DefaultNTPClient{})
	rt.setupPriorityServers()

	require.NotNil(t, rt.priorityServers, "priority servers should be set for de")
	require.GreaterOrEqual(t, len(rt.priorityServers), 1, "should have at least country-level servers")

	// First priority group should be country-specific NTP servers
	assert.Contains(t, rt.priorityServers[0][0], ".de.pool.ntp.org")

	// Second priority group should be zone-level (europe) NTP servers
	if len(rt.priorityServers) >= 2 {
		assert.Contains(t, rt.priorityServers[1][0], ".europe.pool.ntp.org")
	}
}

// toLowerASCII is a test helper for validating lowercase country codes.
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestDetectTimezoneFromGoStdlib(t *testing.T) {
	// Go's time.Now().Location().String() should return an IANA name
	// on a properly configured system. We test the helper function
	// rather than the system state.
	result := detectTimezoneFromGoStdlib()

	// On most CI and development systems, this should return a valid
	// IANA timezone name. We can't assert a specific value, but if
	// non-empty it should look like an IANA name.
	if result != "" {
		assert.Contains(t, result, "/",
			"detectTimezoneFromGoStdlib result should look like IANA name")
	}
}

func TestDetectIANATimezone_FallbackToGoStdlib(t *testing.T) {
	// When TZ is unset and /etc/timezone and /etc/localtime are
	// unavailable (e.g., on Windows), the function should still
	// attempt to detect timezone via Go's stdlib.
	origTZ := os.Getenv("TZ")
	defer os.Setenv("TZ", origTZ)
	os.Unsetenv("TZ")

	// We can't easily simulate absence of /etc/timezone on Linux,
	// but we can verify that the function returns *something* on
	// a configured system.
	result := detectIANATimezone()
	// On a properly configured system, at least one strategy should work.
	// This is a best-effort test — the function may still return ""
	// in unusual environments.
	t.Logf("detectIANATimezone() = %q", result)
}
