package ssu2

import (
	"testing"
)

func TestNewConfig_DefaultValues(t *testing.T) {
	cfg, err := NewConfig(":9002")
	if err != nil {
		t.Fatalf("NewConfig returned error: %v", err)
	}
	if cfg.ListenerAddress != ":9002" {
		t.Errorf("expected ListenerAddress :9002, got %q", cfg.ListenerAddress)
	}
	if cfg.WorkingDir != "" {
		t.Errorf("expected empty WorkingDir, got %q", cfg.WorkingDir)
	}
	if cfg.SSU2Config != nil {
		t.Errorf("expected nil SSU2Config, got non-nil")
	}
}

func TestNewConfig_EmptyAddress(t *testing.T) {
	cfg, err := NewConfig("")
	if err != nil {
		t.Fatalf("NewConfig returned unexpected error: %v", err)
	}
	if cfg.ListenerAddress != "" {
		t.Errorf("expected empty ListenerAddress, got %q", cfg.ListenerAddress)
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate returned error for valid config: %v", err)
	}
}

func TestConfig_Validate_EmptyAddress(t *testing.T) {
	cfg, _ := NewConfig("")
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should fail for empty ListenerAddress")
	}
}

func TestConfig_GetMaxSessions_Default(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	if got := cfg.GetMaxSessions(); got != DefaultMaxSessions {
		t.Errorf("expected %d, got %d", DefaultMaxSessions, got)
	}
}

func TestConfig_GetMaxSessions_Custom(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.MaxSessions = 100
	if got := cfg.GetMaxSessions(); got != 100 {
		t.Errorf("expected 100, got %d", got)
	}
}

func TestConfig_GetMaxSessions_Zero(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.MaxSessions = 0
	if got := cfg.GetMaxSessions(); got != DefaultMaxSessions {
		t.Errorf("expected %d for zero MaxSessions, got %d", DefaultMaxSessions, got)
	}
}

func TestConfig_GetMaxSessions_Negative(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.MaxSessions = -1
	if got := cfg.GetMaxSessions(); got != DefaultMaxSessions {
		t.Errorf("expected %d for negative MaxSessions, got %d", DefaultMaxSessions, got)
	}
}
