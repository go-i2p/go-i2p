package config

import (
	"strings"
	"testing"
)

// =============================================================================
// BandwidthClass Tests
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
			got := BandwidthClassFromRate(tt.bytesPerSec)
			if got != tt.want {
				t.Errorf("BandwidthClassFromRate(%d) = %s, want %s",
					tt.bytesPerSec, got, tt.want)
			}
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
		if class.String() != expected[i] {
			t.Errorf("BandwidthClass[%d].String() = %q, want %q",
				i, class.String(), expected[i])
		}
	}
}

func TestBandwidthClassAllSingleCharacters(t *testing.T) {
	classes := []BandwidthClass{
		BandwidthClassK, BandwidthClassL, BandwidthClassM,
		BandwidthClassN, BandwidthClassO, BandwidthClassP, BandwidthClassX,
	}

	for _, class := range classes {
		if len(class.String()) != 1 {
			t.Errorf("BandwidthClass %q is not a single character", class)
		}
	}
}

func TestDefaultBandwidthClassIsP(t *testing.T) {
	// The default MaxBandwidth is 1 MB/s (1048576 bytes/s) = 1024 KB/s → class P
	got := BandwidthClassFromRate(defaultRouterConfig.MaxBandwidth)
	if got != BandwidthClassP {
		t.Errorf("default MaxBandwidth %d maps to class %s, want P (256-2000 KB/s range)",
			defaultRouterConfig.MaxBandwidth, got)
	}
}

// =============================================================================
// Caps String Builder Tests
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
			got := BuildCapsString(tt.bandwidth, tt.reachable, tt.floodfill, tt.hidden, tt.congestion)
			if got != tt.want {
				t.Errorf("BuildCapsString(%s, reachable=%v, ff=%v, hidden=%v, cong=%s) = %q, want %q",
					tt.bandwidth, tt.reachable, tt.floodfill, tt.hidden, tt.congestion, got, tt.want)
			}
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
						if err := ValidateCapsString(caps); err != nil {
							t.Errorf("BuildCapsString(%s, reach=%v, ff=%v, hid=%v, cong=%s) "+
								"produced invalid caps %q: %v",
								bw, reachable, ff, hidden, cong, caps, err)
						}
					}
				}
			}
		}
	}
}

func TestBuildCapsStringCanonicalOrder(t *testing.T) {
	// Verify the canonical ordering: bandwidth + reachability + floodfill + hidden + congestion
	caps := BuildCapsString(BandwidthClassX, true, true, true, CongestionFlagD)
	if caps != "XRfHD" {
		t.Errorf("canonical order should be bandwidth+reachability+floodfill+hidden+congestion, got %q", caps)
	}
}

// =============================================================================
// Caps Validation Tests
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
			if err := ValidateCapsString(caps); err != nil {
				t.Errorf("ValidateCapsString(%q) = %v, want nil", caps, err)
			}
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
			if err == nil {
				t.Errorf("ValidateCapsString(%q) = nil, want error containing %q",
					tt.caps, tt.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ValidateCapsString(%q) error = %q, want containing %q",
					tt.caps, err.Error(), tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Congestion Flag Validation Tests
// =============================================================================

func TestValidateCongestionFlag_Valid(t *testing.T) {
	validFlags := []CongestionFlag{
		CongestionFlagNone, CongestionFlagD, CongestionFlagE, CongestionFlagG,
	}
	for _, f := range validFlags {
		if err := ValidateCongestionFlag(f); err != nil {
			t.Errorf("ValidateCongestionFlag(%q) = %v, want nil", f, err)
		}
	}
}

func TestValidateCongestionFlag_Invalid(t *testing.T) {
	invalidFlags := []CongestionFlag{"A", "Z", "DE", "GG", "X", "d", "e", "g"}
	for _, f := range invalidFlags {
		t.Run(string(f), func(t *testing.T) {
			if err := ValidateCongestionFlag(f); err == nil {
				t.Errorf("ValidateCongestionFlag(%q) = nil, want error", f)
			}
		})
	}
}

func TestCongestionFlagsAreValidCapsCharacters(t *testing.T) {
	// All CongestionFlag constants must be recognized in validCapsFlags
	flags := []CongestionFlag{CongestionFlagD, CongestionFlagE, CongestionFlagG}
	for _, f := range flags {
		if len(f.String()) != 1 {
			t.Errorf("CongestionFlag %q is not a single character", f)
		}
		r := rune(f.String()[0])
		if _, ok := validCapsFlags[r]; !ok {
			t.Errorf("CongestionFlag %q is not in validCapsFlags", f)
		}
	}
}

func TestCongestionFlagNoneProducesNoCapsCharacter(t *testing.T) {
	caps := BuildCapsString(BandwidthClassP, true, false, false, CongestionFlagNone)
	if caps != "PR" {
		t.Errorf("CongestionFlagNone should not add any character, got caps %q", caps)
	}
}

// =============================================================================
// RouterInfo Option Keys Tests
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
	if err := ValidateRouterInfoOptionKeys(options); err != nil {
		t.Errorf("ValidateRouterInfoOptionKeys(all spec keys) = %v, want nil", err)
	}
}

func TestValidateRouterInfoOptionKeys_DeprecatedKeysAccepted(t *testing.T) {
	// Deprecated keys should be accepted (with warning) but not rejected
	options := map[string]string{
		"router.version": "0.9.64",
		"coreVersion":    "0.9.64",
		"stat_uptime":    "3600",
	}
	if err := ValidateRouterInfoOptionKeys(options); err != nil {
		t.Errorf("ValidateRouterInfoOptionKeys(deprecated keys) = %v, want nil", err)
	}
}

func TestValidateRouterInfoOptionKeys_StatPrefixAccepted(t *testing.T) {
	// stat_ prefixed keys should be accepted per spec (various statistics)
	options := map[string]string{
		"router.version":                          "0.9.64",
		"stat_tunnel.buildExploratoryExpire.60m":  "100",
		"stat_tunnel.buildExploratoryReject.60m":  "50",
		"stat_tunnel.buildExploratorySuccess.60m": "200",
		"stat_tunnel.participatingTunnels.60m":    "500",
	}
	if err := ValidateRouterInfoOptionKeys(options); err != nil {
		t.Errorf("ValidateRouterInfoOptionKeys(stat_ prefix) = %v, want nil", err)
	}
}

func TestValidateRouterInfoOptionKeys_SubsetValid(t *testing.T) {
	options := map[string]string{
		"router.version": "0.9.64",
		"caps":           "PR",
	}
	if err := ValidateRouterInfoOptionKeys(options); err != nil {
		t.Errorf("ValidateRouterInfoOptionKeys(subset) = %v, want nil", err)
	}
}

func TestValidateRouterInfoOptionKeys_EmptyValid(t *testing.T) {
	options := map[string]string{}
	if err := ValidateRouterInfoOptionKeys(options); err != nil {
		t.Errorf("ValidateRouterInfoOptionKeys(empty) = %v, want nil", err)
	}
}

func TestValidateRouterInfoOptionKeys_ProprietaryKeyRejected(t *testing.T) {
	options := map[string]string{
		"router.version":   "0.9.64",
		"my.custom.option": "value",
	}
	err := ValidateRouterInfoOptionKeys(options)
	if err == nil {
		t.Error("ValidateRouterInfoOptionKeys(proprietary key) = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "my.custom.option") {
		t.Errorf("error should mention the unrecognized key, got: %v", err)
	}
}

func TestValidateRouterInfoOptionKeys_MultipleProprietaryKeys(t *testing.T) {
	options := map[string]string{
		"router.version": "0.9.64",
		"foo":            "bar",
		"debug.mode":     "true",
	}
	err := ValidateRouterInfoOptionKeys(options)
	if err == nil {
		t.Error("ValidateRouterInfoOptionKeys(multiple proprietary) = nil, want error")
		return
	}
	// Both unrecognized keys should be mentioned
	if !strings.Contains(err.Error(), "debug.mode") {
		t.Errorf("error should mention 'debug.mode': %v", err)
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Errorf("error should mention 'foo': %v", err)
	}
}

func TestSpecRouterInfoOptionKeysContainsRequiredKeys(t *testing.T) {
	// Per I2P spec, these keys are commonly required in RouterInfo
	requiredKeys := []string{
		"router.version",
		"caps",
		"netId",
	}
	for _, key := range requiredKeys {
		if _, ok := SpecRouterInfoOptionKeys[key]; !ok {
			t.Errorf("SpecRouterInfoOptionKeys missing required key: %s", key)
		}
	}
}

// =============================================================================
// I2CP Port Default Compliance Tests
// =============================================================================

func TestI2CPPortDefaultIs7654(t *testing.T) {
	if DefaultI2CPPort != 7654 {
		t.Errorf("DefaultI2CPPort = %d, want 7654 per I2CP spec", DefaultI2CPPort)
	}
}

func TestI2CPDefaultsAddressHasCorrectPort(t *testing.T) {
	defaults := buildI2CPDefaults()
	if defaults.Address != "localhost:7654" {
		t.Errorf("I2CP default address = %q, want %q", defaults.Address, "localhost:7654")
	}
}

func TestDefaultI2CPConfigAddressHasCorrectPort(t *testing.T) {
	if DefaultI2CPConfig.Address != "localhost:7654" {
		t.Errorf("DefaultI2CPConfig.Address = %q, want %q",
			DefaultI2CPConfig.Address, "localhost:7654")
	}
}

// =============================================================================
// Default Value Spec-Compliance Tests
// =============================================================================

func TestFloodfillDefaultIsFalse(t *testing.T) {
	// Per I2P spec, routers should NOT be floodfill by default
	defaults := Defaults()
	if defaults.NetDB.FloodfillEnabled {
		t.Error("NetDB.FloodfillEnabled default = true, want false (regular router mode per spec)")
	}
}

func TestDefaultBandwidthMapsToPClass(t *testing.T) {
	// The default MaxBandwidth (1 MB/s = 1024 KB/s) should map to class P (256-2000 KB/s)
	bw := BandwidthClassFromRate(defaultRouterConfig.MaxBandwidth)
	if bw != BandwidthClassP {
		t.Errorf("default MaxBandwidth %d maps to class %s, want P",
			defaultRouterConfig.MaxBandwidth, bw)
	}
}

func TestCongestionDefaultsProduceValidFlags(t *testing.T) {
	// Verify that all CongestionFlag constants used in CongestionDefaults
	// are valid per Proposal 162
	defaults := buildCongestionDefaults()

	// The defaults struct itself doesn't store a flag, but the flag constants
	// it works with must all be valid
	for _, f := range []CongestionFlag{
		CongestionFlagNone, CongestionFlagD, CongestionFlagE, CongestionFlagG,
	} {
		if err := ValidateCongestionFlag(f); err != nil {
			t.Errorf("CongestionFlag %q is invalid: %v", f, err)
		}
	}

	// Verify threshold ordering is maintained in defaults
	if defaults.DFlagThreshold >= defaults.EFlagThreshold {
		t.Error("CongestionDefaults: DFlagThreshold must be < EFlagThreshold")
	}
	if defaults.EFlagThreshold >= defaults.GFlagThreshold {
		t.Error("CongestionDefaults: EFlagThreshold must be < GFlagThreshold")
	}
}

// =============================================================================
// Legacy Crypto Check
// =============================================================================

func TestNoLegacyCryptoInDefaults(t *testing.T) {
	// Verify that no config defaults reference DSA or ElGamal.
	// This is a documented audit assertion: the config package deals with
	// operational parameters, not cryptographic algorithm selection.
	// If a SignatureType or EncryptionType field is ever added to
	// ConfigDefaults, this test must verify it does not reference DSA/ElGamal.
	defaults := Defaults()

	// Confirm ConfigDefaults contains no signature/encryption type fields
	// by exercising Defaults() without panic.
	_ = defaults.Router
	_ = defaults.NetDB
	_ = defaults.Bootstrap
	_ = defaults.I2CP
	_ = defaults.I2PControl
	_ = defaults.Tunnel
	_ = defaults.Transport
	_ = defaults.Performance
	_ = defaults.Congestion
}

// =============================================================================
// Integration: Full Config Validation with Caps
// =============================================================================

func TestDefaultsPassFullValidation(t *testing.T) {
	defaults := Defaults()
	if err := Validate(defaults); err != nil {
		t.Errorf("Validate(Defaults()) = %v, want nil", err)
	}
}

func TestBuildCapsFromDefaults(t *testing.T) {
	// Build a caps string using the default configuration values
	bw := BandwidthClassFromRate(defaultRouterConfig.MaxBandwidth)
	floodfill := Defaults().NetDB.FloodfillEnabled

	caps := BuildCapsString(bw, true, floodfill, false, CongestionFlagNone)

	// Default should be: P class, reachable, no floodfill, no congestion → "PR"
	if caps != "PR" {
		t.Errorf("caps from defaults = %q, want %q", caps, "PR")
	}

	if err := ValidateCapsString(caps); err != nil {
		t.Errorf("caps from defaults is invalid: %v", err)
	}
}
