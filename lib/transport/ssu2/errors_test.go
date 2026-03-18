package ssu2

import (
	"errors"
	"testing"
)

func TestErrSSU2NotSupported_IsError(t *testing.T) {
	if ErrSSU2NotSupported == nil {
		t.Error("ErrSSU2NotSupported should not be nil")
	}
}

func TestErrSessionClosed_IsError(t *testing.T) {
	if ErrSessionClosed == nil {
		t.Error("ErrSessionClosed should not be nil")
	}
}

func TestErrHandshakeFailed_IsError(t *testing.T) {
	if ErrHandshakeFailed == nil {
		t.Error("ErrHandshakeFailed should not be nil")
	}
}

func TestErrInvalidRouterInfo_IsError(t *testing.T) {
	if ErrInvalidRouterInfo == nil {
		t.Error("ErrInvalidRouterInfo should not be nil")
	}
}

func TestErrConnectionPoolFull_IsError(t *testing.T) {
	if ErrConnectionPoolFull == nil {
		t.Error("ErrConnectionPoolFull should not be nil")
	}
}

func TestErrInvalidListenerAddress_IsError(t *testing.T) {
	if ErrInvalidListenerAddress == nil {
		t.Error("ErrInvalidListenerAddress should not be nil")
	}
}

func TestErrInvalidConfig_IsError(t *testing.T) {
	if ErrInvalidConfig == nil {
		t.Error("ErrInvalidConfig should not be nil")
	}
}

func TestWrapSSU2Error_WrapsError(t *testing.T) {
	base := errors.New("underlying failure")
	wrapped := WrapSSU2Error(base, "connect")
	if wrapped == nil {
		t.Fatal("WrapSSU2Error returned nil")
	}
	msg := wrapped.Error()
	if msg == "" {
		t.Error("wrapped error message should not be empty")
	}
}

func TestWrapSSU2Error_NilBase(t *testing.T) {
	// oops.Wrapf(nil) returns nil — wrapping a nil error preserves nil.
	wrapped := WrapSSU2Error(nil, "read")
	if wrapped != nil {
		t.Errorf("WrapSSU2Error(nil) should return nil, got %v", wrapped)
	}
}
