package config

import (
	"testing"
	"time"
)

// TestBuildCongestionDefaults verifies that buildCongestionDefaults returns
// configuration with all expected default values set per PROP_162 specification.
func TestBuildCongestionDefaults(t *testing.T) {
	cfg := buildCongestionDefaults()

	// Flag advertisement thresholds
	if cfg.DFlagThreshold != 0.70 {
		t.Errorf("DFlagThreshold = %v, want 0.70", cfg.DFlagThreshold)
	}
	if cfg.EFlagThreshold != 0.85 {
		t.Errorf("EFlagThreshold = %v, want 0.85", cfg.EFlagThreshold)
	}
	if cfg.GFlagThreshold != 1.00 {
		t.Errorf("GFlagThreshold = %v, want 1.00", cfg.GFlagThreshold)
	}

	// Hysteresis thresholds
	if cfg.ClearDFlagThreshold != 0.60 {
		t.Errorf("ClearDFlagThreshold = %v, want 0.60", cfg.ClearDFlagThreshold)
	}
	if cfg.ClearEFlagThreshold != 0.75 {
		t.Errorf("ClearEFlagThreshold = %v, want 0.75", cfg.ClearEFlagThreshold)
	}
	if cfg.ClearGFlagThreshold != 0.95 {
		t.Errorf("ClearGFlagThreshold = %v, want 0.95", cfg.ClearGFlagThreshold)
	}

	// Timing values
	if cfg.AveragingWindow != 5*time.Minute {
		t.Errorf("AveragingWindow = %v, want 5m", cfg.AveragingWindow)
	}
	if cfg.EFlagAgeThreshold != 15*time.Minute {
		t.Errorf("EFlagAgeThreshold = %v, want 15m", cfg.EFlagAgeThreshold)
	}

	// Capacity multipliers
	if cfg.DFlagCapacityMultiplier != 0.5 {
		t.Errorf("DFlagCapacityMultiplier = %v, want 0.5", cfg.DFlagCapacityMultiplier)
	}
	if cfg.EFlagCapacityMultiplier != 0.1 {
		t.Errorf("EFlagCapacityMultiplier = %v, want 0.1", cfg.EFlagCapacityMultiplier)
	}
	if cfg.StaleEFlagCapacityMultiplier != 0.5 {
		t.Errorf("StaleEFlagCapacityMultiplier = %v, want 0.5", cfg.StaleEFlagCapacityMultiplier)
	}
}

// TestCongestionDefaults_IntegratedWithConfigDefaults verifies congestion
// defaults are properly integrated into the main ConfigDefaults.
func TestCongestionDefaults_IntegratedWithConfigDefaults(t *testing.T) {
	cfg := Defaults()

	// Verify congestion config is present and has expected values
	if cfg.Congestion.DFlagThreshold != 0.70 {
		t.Errorf("Congestion.DFlagThreshold = %v, want 0.70", cfg.Congestion.DFlagThreshold)
	}
	if cfg.Congestion.AveragingWindow != 5*time.Minute {
		t.Errorf("Congestion.AveragingWindow = %v, want 5m", cfg.Congestion.AveragingWindow)
	}
}

// TestValidateCongestion_ValidConfig verifies that valid config passes validation
func TestValidateCongestion_ValidConfig(t *testing.T) {
	cfg := buildCongestionDefaults()

	if err := validateCongestion(cfg); err != nil {
		t.Errorf("validateCongestion() failed for default config: %v", err)
	}
}

// TestValidateCongestion_ThresholdOrdering verifies threshold ordering validation
func TestValidateCongestion_ThresholdOrdering(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*CongestionDefaults)
		wantErr bool
	}{
		{
			name:    "valid defaults",
			modify:  func(c *CongestionDefaults) {},
			wantErr: false,
		},
		{
			name: "D >= E threshold",
			modify: func(c *CongestionDefaults) {
				c.DFlagThreshold = 0.90
				c.EFlagThreshold = 0.85
			},
			wantErr: true,
		},
		{
			name: "E >= G threshold",
			modify: func(c *CongestionDefaults) {
				c.EFlagThreshold = 1.0
				c.GFlagThreshold = 1.0
			},
			wantErr: true,
		},
		{
			name: "D threshold negative",
			modify: func(c *CongestionDefaults) {
				c.DFlagThreshold = -0.1
			},
			wantErr: true,
		},
		{
			name: "G threshold > 1",
			modify: func(c *CongestionDefaults) {
				c.GFlagThreshold = 1.5
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := buildCongestionDefaults()
			tt.modify(&cfg)

			err := validateCongestion(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCongestion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateCongestion_HysteresisOrdering verifies hysteresis threshold validation
func TestValidateCongestion_HysteresisOrdering(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*CongestionDefaults)
		wantErr bool
	}{
		{
			name:    "valid hysteresis",
			modify:  func(c *CongestionDefaults) {},
			wantErr: false,
		},
		{
			name: "ClearD >= D threshold",
			modify: func(c *CongestionDefaults) {
				c.ClearDFlagThreshold = 0.70 // equal to DFlagThreshold
			},
			wantErr: true,
		},
		{
			name: "ClearE >= E threshold",
			modify: func(c *CongestionDefaults) {
				c.ClearEFlagThreshold = 0.90 // greater than EFlagThreshold
			},
			wantErr: true,
		},
		{
			name: "ClearG >= G threshold",
			modify: func(c *CongestionDefaults) {
				c.ClearGFlagThreshold = 1.0 // equal to GFlagThreshold
			},
			wantErr: true,
		},
		{
			name: "ClearD negative",
			modify: func(c *CongestionDefaults) {
				c.ClearDFlagThreshold = -0.1
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := buildCongestionDefaults()
			tt.modify(&cfg)

			err := validateCongestion(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCongestion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateCongestion_CapacityMultipliers verifies capacity multiplier validation
func TestValidateCongestion_CapacityMultipliers(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*CongestionDefaults)
		wantErr bool
	}{
		{
			name:    "valid multipliers",
			modify:  func(c *CongestionDefaults) {},
			wantErr: false,
		},
		{
			name: "D multiplier zero",
			modify: func(c *CongestionDefaults) {
				c.DFlagCapacityMultiplier = 0
			},
			wantErr: true,
		},
		{
			name: "E multiplier negative",
			modify: func(c *CongestionDefaults) {
				c.EFlagCapacityMultiplier = -0.1
			},
			wantErr: true,
		},
		{
			name: "D multiplier > 1",
			modify: func(c *CongestionDefaults) {
				c.DFlagCapacityMultiplier = 1.5
			},
			wantErr: true,
		},
		{
			name: "E multiplier > D multiplier",
			modify: func(c *CongestionDefaults) {
				c.DFlagCapacityMultiplier = 0.3
				c.EFlagCapacityMultiplier = 0.5
			},
			wantErr: true,
		},
		{
			name: "stale E multiplier zero",
			modify: func(c *CongestionDefaults) {
				c.StaleEFlagCapacityMultiplier = 0
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := buildCongestionDefaults()
			tt.modify(&cfg)

			err := validateCongestion(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCongestion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateCongestion_Timing verifies timing validation
func TestValidateCongestion_Timing(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*CongestionDefaults)
		wantErr bool
	}{
		{
			name:    "valid timing",
			modify:  func(c *CongestionDefaults) {},
			wantErr: false,
		},
		{
			name: "averaging window too short",
			modify: func(c *CongestionDefaults) {
				c.AveragingWindow = 30 * time.Second
			},
			wantErr: true,
		},
		{
			name: "E flag age threshold too short",
			modify: func(c *CongestionDefaults) {
				c.EFlagAgeThreshold = 30 * time.Second
			},
			wantErr: true,
		},
		{
			name: "minimum valid timing",
			modify: func(c *CongestionDefaults) {
				c.AveragingWindow = 1 * time.Minute
				c.EFlagAgeThreshold = 1 * time.Minute
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := buildCongestionDefaults()
			tt.modify(&cfg)

			err := validateCongestion(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCongestion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCongestionFlag_CongestionLevel verifies the CongestionLevel method
func TestCongestionFlag_CongestionLevel(t *testing.T) {
	tests := []struct {
		flag  CongestionFlag
		level int
	}{
		{CongestionFlagNone, 0},
		{CongestionFlagD, 1},
		{CongestionFlagE, 2},
		{CongestionFlagG, 3},
		{CongestionFlag("X"), 0}, // Unknown flag should return 0
	}

	for _, tt := range tests {
		t.Run(string(tt.flag), func(t *testing.T) {
			if got := tt.flag.CongestionLevel(); got != tt.level {
				t.Errorf("CongestionFlag(%q).CongestionLevel() = %d, want %d", tt.flag, got, tt.level)
			}
		})
	}
}

// TestCongestionFlag_String verifies the String method
func TestCongestionFlag_String(t *testing.T) {
	tests := []struct {
		flag CongestionFlag
		want string
	}{
		{CongestionFlagNone, ""},
		{CongestionFlagD, "D"},
		{CongestionFlagE, "E"},
		{CongestionFlagG, "G"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.flag.String(); got != tt.want {
				t.Errorf("CongestionFlag.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseCongestionFlag verifies parsing congestion flags from caps strings
func TestParseCongestionFlag(t *testing.T) {
	tests := []struct {
		name string
		caps string
		want CongestionFlag
	}{
		{
			name: "no congestion flags",
			caps: "NRU",
			want: CongestionFlagNone,
		},
		{
			name: "D flag only",
			caps: "NRUD",
			want: CongestionFlagD,
		},
		{
			name: "E flag only",
			caps: "NRUE",
			want: CongestionFlagE,
		},
		{
			name: "G flag only",
			caps: "NRUG",
			want: CongestionFlagG,
		},
		{
			name: "G takes priority over D and E",
			caps: "NRUDEG",
			want: CongestionFlagG,
		},
		{
			name: "E takes priority over D",
			caps: "NRUDE",
			want: CongestionFlagE,
		},
		{
			name: "empty caps string",
			caps: "",
			want: CongestionFlagNone,
		},
		{
			name: "typical full caps with D flag",
			caps: "BCKNORUXD",
			want: CongestionFlagD,
		},
		{
			name: "lowercase should not match",
			caps: "NRUd",
			want: CongestionFlagNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCongestionFlag(tt.caps)
			if got != tt.want {
				t.Errorf("ParseCongestionFlag(%q) = %q, want %q", tt.caps, got, tt.want)
			}
		})
	}
}

// TestValidate_CongestionConfigIntegration verifies congestion validation
// is integrated into the main Validate function
func TestValidate_CongestionConfigIntegration(t *testing.T) {
	cfg := Defaults()

	// Valid defaults should pass
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate() failed for default config: %v", err)
	}

	// Invalid congestion config should fail
	cfg.Congestion.DFlagThreshold = 1.5 // Out of range
	if err := Validate(cfg); err == nil {
		t.Error("Validate() should fail when congestion config is invalid")
	}
}
