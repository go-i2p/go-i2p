package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Unit Tests for caps.go — BandwidthClass
// =============================================================================

func TestBandwidthClassFromRate(t *testing.T) {
	tests := []struct {
		name        string
		bytesPerSec uint64
		want        BandwidthClass
	}{
		// K class: under 12 KB/s
		{"zero bandwidth", 0, BandwidthClassK},
		{"1 KB/s", 1024, BandwidthClassK},
		{"11 KB/s (top of K)", 11 * 1024, BandwidthClassK},

		// L class: 12–48 KB/s
		{"12 KB/s (L boundary)", 12 * 1024, BandwidthClassL},
		{"30 KB/s (mid-L)", 30 * 1024, BandwidthClassL},
		{"47 KB/s (top of L)", 47 * 1024, BandwidthClassL},

		// M class: 48–64 KB/s
		{"48 KB/s (M boundary)", 48 * 1024, BandwidthClassM},
		{"60 KB/s (mid-M)", 60 * 1024, BandwidthClassM},
		{"63 KB/s (top of M)", 63 * 1024, BandwidthClassM},

		// N class: 64–128 KB/s
		{"64 KB/s (N boundary)", 64 * 1024, BandwidthClassN},
		{"100 KB/s (mid-N)", 100 * 1024, BandwidthClassN},
		{"127 KB/s (top of N)", 127 * 1024, BandwidthClassN},

		// O class: 128–256 KB/s
		{"128 KB/s (O boundary)", 128 * 1024, BandwidthClassO},
		{"200 KB/s (mid-O)", 200 * 1024, BandwidthClassO},
		{"255 KB/s (top of O)", 255 * 1024, BandwidthClassO},

		// P class: 256–2000 KB/s
		{"256 KB/s (P boundary)", 256 * 1024, BandwidthClassP},
		{"1000 KB/s (mid-P)", 1000 * 1024, BandwidthClassP},
		{"1999 KB/s (top of P)", 1999 * 1024, BandwidthClassP},

		// X class: over 2000 KB/s
		{"2000 KB/s (X boundary)", 2000 * 1024, BandwidthClassX},
		{"10000 KB/s (high X)", 10000 * 1024, BandwidthClassX},

		// Default bandwidth (1 MB/s = 1024 KB/s → P)
		{"default 1 MB/s", 1024 * 1024, BandwidthClassP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, BandwidthClassFromRate(tt.bytesPerSec),
				"BandwidthClassFromRate(%d)", tt.bytesPerSec)
		})
	}
}

func TestBandwidthClassString(t *testing.T) {
	classes := []BandwidthClass{
		BandwidthClassK, BandwidthClassL, BandwidthClassM,
		BandwidthClassN, BandwidthClassO, BandwidthClassP, BandwidthClassX,
	}
	expected := []string{"K", "L", "M", "N", "O", "P", "X"}

	for i, class := range classes {
		assert.Equal(t, expected[i], class.String(), "BandwidthClass[%d].String()", i)
	}
}

func TestBandwidthClassAllSingleCharacters(t *testing.T) {
	classes := []BandwidthClass{
		BandwidthClassK, BandwidthClassL, BandwidthClassM,
		BandwidthClassN, BandwidthClassO, BandwidthClassP, BandwidthClassX,
	}

	for _, class := range classes {
		assert.Len(t, class.String(), 1, "BandwidthClass %q is not a single character", class)
	}
}

func TestDefaultBandwidthClassIsP(t *testing.T) {
	assert.Equal(t, BandwidthClassP, BandwidthClassFromRate(defaultRouterConfig.MaxBandwidth),
		"default MaxBandwidth %d should map to class P", defaultRouterConfig.MaxBandwidth)
}

// =============================================================================
// Unit Tests for caps.go — BuildCapsString
// =============================================================================

func TestBuildCapsString_Basic(t *testing.T) {
	tests := []struct {
		name       string
		bandwidth  BandwidthClass
		reachable  bool
		floodfill  bool
		hidden     bool
		congestion CongestionFlag
		want       string
	}{
		{
			name:       "reachable P class no congestion",
			bandwidth:  BandwidthClassP,
			reachable:  true,
			floodfill:  false,
			hidden:     false,
			congestion: CongestionFlagNone,
			want:       "PR",
		},
		{
			name:       "unreachable K class",
			bandwidth:  BandwidthClassK,
			reachable:  false,
			floodfill:  false,
			hidden:     false,
			congestion: CongestionFlagNone,
			want:       "KU",
		},
		{
			name:       "floodfill reachable O class",
			bandwidth:  BandwidthClassO,
			reachable:  true,
			floodfill:  true,
			hidden:     false,
			congestion: CongestionFlagNone,
			want:       "ORf",
		},
		{
			name:       "with D congestion flag",
			bandwidth:  BandwidthClassN,
			reachable:  true,
			floodfill:  false,
			hidden:     false,
			congestion: CongestionFlagD,
			want:       "NRD",
		},
		{
			name:       "with E congestion flag and floodfill",
			bandwidth:  BandwidthClassP,
			reachable:  true,
			floodfill:  true,
			hidden:     false,
			congestion: CongestionFlagE,
			want:       "PRfE",
		},
		{
			name:       "with G congestion flag",
			bandwidth:  BandwidthClassX,
			reachable:  true,
			floodfill:  false,
			hidden:     false,
			congestion: CongestionFlagG,
			want:       "XRG",
		},
		{
			name:       "hidden unreachable",
			bandwidth:  BandwidthClassL,
			reachable:  false,
			floodfill:  false,
			hidden:     true,
			congestion: CongestionFlagNone,
			want:       "LUH",
		},
		{
			name:       "all flags set",
			bandwidth:  BandwidthClassX,
			reachable:  true,
			floodfill:  true,
			hidden:     true,
			congestion: CongestionFlagD,
			want:       "XRfHD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want,
				BuildCapsString(tt.bandwidth, tt.reachable, tt.floodfill, tt.hidden, tt.congestion))
		})
	}
}

func TestBuildCapsStringProducesValidCaps(t *testing.T) {
	// Every caps string produced by BuildCapsString must pass ValidateCapsString
	classes := []BandwidthClass{
		BandwidthClassK, BandwidthClassL, BandwidthClassM,
		BandwidthClassN, BandwidthClassO, BandwidthClassP, BandwidthClassX,
	}
	congestions := []CongestionFlag{
		CongestionFlagNone, CongestionFlagD, CongestionFlagE, CongestionFlagG,
	}

	for _, bw := range classes {
		for _, reachable := range []bool{true, false} {
			for _, ff := range []bool{true, false} {
				for _, hidden := range []bool{true, false} {
					for _, cong := range congestions {
						caps := BuildCapsString(bw, reachable, ff, hidden, cong)
						assert.NoError(t, ValidateCapsString(caps),
							"BuildCapsString(%s, reach=%v, ff=%v, hid=%v, cong=%s) produced invalid caps %q",
							bw, reachable, ff, hidden, cong, caps)
					}
				}
			}
		}
	}
}

func TestBuildCapsStringCanonicalOrder(t *testing.T) {
	assert.Equal(t, "XRfHD",
		BuildCapsString(BandwidthClassX, true, true, true, CongestionFlagD),
		"canonical order should be bandwidth+reachability+floodfill+hidden+congestion")
}

func TestBuildCapsFromDefaults(t *testing.T) {
	bw := BandwidthClassFromRate(defaultRouterConfig.MaxBandwidth)
	floodfill := Defaults().NetDB.FloodfillEnabled
	caps := BuildCapsString(bw, true, floodfill, false, CongestionFlagNone)

	assert.Equal(t, "PR", caps, "caps from defaults")
	assert.NoError(t, ValidateCapsString(caps), "caps from defaults is invalid")
}

// =============================================================================
// Unit Tests for caps.go — ValidateCapsString
// =============================================================================

func TestValidateCapsString_Valid(t *testing.T) {
	validCaps := []string{
		"PR", "KU", "LR", "MR", "NR", "OR", "XR", // bandwidth + reachability
		"PRf", "XRf", // with floodfill
		"PRD", "PRE", "PRG", // with congestion
		"PRfD", "XRfE", // floodfill + congestion
		"LUH",        // hidden
		"XRfHD",      // all flags
		"KRf", "MUG", // misc valid
		// Multi-bandwidth for backward compat (spec: "a router may publish
		// multiple bandwidth letters, for example 'PO'")
		"POR", "KLR",
		// No reachability (spec: "unless the reachability state is currently unknown")
		"P", "PD", "Pf",
	}

	for _, caps := range validCaps {
		t.Run(caps, func(t *testing.T) {
			assert.NoError(t, ValidateCapsString(caps), "ValidateCapsString(%q)", caps)
		})
	}
}

func TestValidateCapsString_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		caps    string
		wantErr string
	}{
		{"empty string", "", "must not be empty"},
		{"unrecognized flag", "PRA", "unrecognized caps flag: A"},
		{"numeric character", "PR1", "unrecognized caps flag: 1"},
		{"lowercase bandwidth", "pR", "unrecognized caps flag: p"},
		{"two reachability", "PRU", "at most one reachability flag"},
		{"two congestion", "PRDE", "at most one congestion flag"},
		{"no bandwidth", "RD", "at least one bandwidth class letter"},
		{"duplicate flag f", "PRff", "duplicate caps flag: f"},
		{"only congestion", "D", "at least one bandwidth class letter"},
		{"space in caps", "P R", "unrecognized caps flag:  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCapsString(tt.caps)
			require.Error(t, err, "ValidateCapsString(%q) should return error", tt.caps)
			assert.Contains(t, err.Error(), tt.wantErr, "ValidateCapsString(%q)", tt.caps)
		})
	}
}

// =============================================================================
// Unit Tests for caps.go — ValidateCongestionFlag
// =============================================================================

func TestValidateCongestionFlag_Valid(t *testing.T) {
	validFlags := []CongestionFlag{
		CongestionFlagNone, CongestionFlagD, CongestionFlagE, CongestionFlagG,
	}
	for _, f := range validFlags {
		assert.NoError(t, ValidateCongestionFlag(f), "ValidateCongestionFlag(%q)", f)
	}
}

func TestValidateCongestionFlag_Invalid(t *testing.T) {
	invalidFlags := []CongestionFlag{"A", "Z", "DE", "GG", "X", "d", "e", "g"}
	for _, f := range invalidFlags {
		t.Run(string(f), func(t *testing.T) {
			assert.Error(t, ValidateCongestionFlag(f), "ValidateCongestionFlag(%q)", f)
		})
	}
}

func TestCongestionFlagsAreValidCapsCharacters(t *testing.T) {
	flags := []CongestionFlag{CongestionFlagD, CongestionFlagE, CongestionFlagG}
	for _, f := range flags {
		assert.Len(t, f.String(), 1, "CongestionFlag %q is not a single character", f)
		r := rune(f.String()[0])
		_, ok := validCapsFlags[r]
		assert.True(t, ok, "CongestionFlag %q is not in validCapsFlags", f)
	}
}

func TestCongestionFlagNoneProducesNoCapsCharacter(t *testing.T) {
	assert.Equal(t, "PR",
		BuildCapsString(BandwidthClassP, true, false, false, CongestionFlagNone),
		"CongestionFlagNone should not add any character")
}

// =============================================================================
// Unit Tests for caps.go — ValidateRouterInfoOptionKeys
// =============================================================================

func TestValidateRouterInfoOptionKeys_AllSpecKeys(t *testing.T) {
	options := map[string]string{
		"router.version":       "0.9.64",
		"caps":                 "PRf",
		"netId":                "2",
		"netdb.knownRouters":   "5000",
		"netdb.knownLeaseSets": "1000",
		"family":               "myfamily",
		"family.key":           "base64key==",
		"family.sig":           "base64sig==",
	}
	assert.NoError(t, ValidateRouterInfoOptionKeys(options), "all spec keys")
}

func TestValidateRouterInfoOptionKeys_DeprecatedKeysAccepted(t *testing.T) {
	options := map[string]string{
		"router.version": "0.9.64",
		"coreVersion":    "0.9.64",
		"stat_uptime":    "3600",
	}
	assert.NoError(t, ValidateRouterInfoOptionKeys(options), "deprecated keys")
}

func TestValidateRouterInfoOptionKeys_StatPrefixAccepted(t *testing.T) {
	options := map[string]string{
		"router.version":                          "0.9.64",
		"stat_tunnel.buildExploratoryExpire.60m":  "100",
		"stat_tunnel.buildExploratoryReject.60m":  "50",
		"stat_tunnel.buildExploratorySuccess.60m": "200",
		"stat_tunnel.participatingTunnels.60m":    "500",
	}
	assert.NoError(t, ValidateRouterInfoOptionKeys(options), "stat_ prefix")
}

func TestValidateRouterInfoOptionKeys_SubsetValid(t *testing.T) {
	options := map[string]string{
		"router.version": "0.9.64",
		"caps":           "PR",
	}
	assert.NoError(t, ValidateRouterInfoOptionKeys(options), "subset")
}

func TestValidateRouterInfoOptionKeys_EmptyValid(t *testing.T) {
	assert.NoError(t, ValidateRouterInfoOptionKeys(map[string]string{}), "empty")
}

func TestValidateRouterInfoOptionKeys_ProprietaryKeyRejected(t *testing.T) {
	options := map[string]string{
		"router.version":   "0.9.64",
		"my.custom.option": "value",
	}
	err := ValidateRouterInfoOptionKeys(options)
	require.Error(t, err, "proprietary key should be rejected")
	assert.Contains(t, err.Error(), "my.custom.option")
}

func TestValidateRouterInfoOptionKeys_MultipleProprietaryKeys(t *testing.T) {
	options := map[string]string{
		"router.version": "0.9.64",
		"foo":            "bar",
		"debug.mode":     "true",
	}
	err := ValidateRouterInfoOptionKeys(options)
	require.Error(t, err, "multiple proprietary keys should be rejected")
	assert.Contains(t, err.Error(), "debug.mode")
	assert.Contains(t, err.Error(), "foo")
}

func TestSpecRouterInfoOptionKeysContainsRequiredKeys(t *testing.T) {
	for _, key := range []string{"router.version", "caps", "netId"} {
		_, ok := SpecRouterInfoOptionKeys[key]
		assert.True(t, ok, "SpecRouterInfoOptionKeys missing required key: %s", key)
	}
}
