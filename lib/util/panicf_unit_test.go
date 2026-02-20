package util

import "testing"

// =============================================================================
// Unit Tests for panicf.go — Panicf
// =============================================================================

// TestPanicfFormatsMessage verifies Panicf formats panic messages correctly.
func TestPanicfFormatsMessage(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if !ok {
				t.Fatalf("Expected string panic, got %T", r)
			}
			expected := "error code 42: test message"
			if msg != expected {
				t.Errorf("Expected panic message %q, got %q", expected, msg)
			}
		} else {
			t.Fatal("Expected Panicf to panic")
		}
	}()

	Panicf("error code %d: %s", 42, "test message")
}

// TestPanicfWithNoArgs verifies Panicf works with no format arguments.
func TestPanicfWithNoArgs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if !ok {
				t.Fatalf("Expected string panic, got %T", r)
			}
			expected := "simple panic message"
			if msg != expected {
				t.Errorf("Expected panic message %q, got %q", expected, msg)
			}
		} else {
			t.Fatal("Expected Panicf to panic")
		}
	}()

	Panicf("simple panic message")
}

// TestPanicfWithEmptyString verifies Panicf handles empty format string.
func TestPanicfWithEmptyString(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(string)
			if !ok {
				t.Fatalf("Expected string panic, got %T", r)
			}
			if msg != "" {
				t.Errorf("Expected empty panic message, got %q", msg)
			}
		} else {
			t.Fatal("Expected Panicf to panic")
		}
	}()

	Panicf("")
}
