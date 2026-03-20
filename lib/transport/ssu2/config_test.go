package ssu2

import (
	"testing"
	"time"
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

func TestConfig_GetKeepaliveInterval_Default(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	if got := cfg.GetKeepaliveInterval(); got != DefaultKeepaliveInterval {
		t.Errorf("expected %v, got %v", DefaultKeepaliveInterval, got)
	}
}

func TestConfig_GetKeepaliveInterval_Custom(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.KeepaliveInterval = 30 * time.Second
	if got := cfg.GetKeepaliveInterval(); got != 30*time.Second {
		t.Errorf("expected 30s, got %v", got)
	}
}

func TestConfig_GetKeepaliveInterval_Zero(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.KeepaliveInterval = 0
	if got := cfg.GetKeepaliveInterval(); got != DefaultKeepaliveInterval {
		t.Errorf("expected default %v for zero, got %v", DefaultKeepaliveInterval, got)
	}
}

func TestConfig_GetMaxRetransmissions_Default(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	if got := cfg.GetMaxRetransmissions(); got != DefaultMaxRetransmissions {
		t.Errorf("expected %d, got %d", DefaultMaxRetransmissions, got)
	}
}

func TestConfig_GetMaxRetransmissions_Custom(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.MaxRetransmissions = 5
	if got := cfg.GetMaxRetransmissions(); got != 5 {
		t.Errorf("expected 5, got %d", got)
	}
}

func TestConfig_GetMaxRetransmissions_Zero(t *testing.T) {
	cfg, _ := NewConfig(":9002")
	cfg.MaxRetransmissions = 0
	if got := cfg.GetMaxRetransmissions(); got != DefaultMaxRetransmissions {
		t.Errorf("expected default %d for zero, got %d", DefaultMaxRetransmissions, got)
	}
}
