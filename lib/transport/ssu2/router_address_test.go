package ssu2

import (
	"testing"

	"github.com/go-i2p/common/router_info"
)

func TestSupportsSSU2_NilRouterInfo(t *testing.T) {
	if SupportsSSU2(nil) {
		t.Error("SupportsSSU2(nil) should return false")
	}
}

func TestHasDialableSSU2Address_NilRouterInfo(t *testing.T) {
	if HasDialableSSU2Address(nil) {
		t.Error("HasDialableSSU2Address(nil) should return false")
	}
}

func TestHasDirectConnectivity_NilAddr(t *testing.T) {
	if HasDirectConnectivity(nil) {
		t.Error("HasDirectConnectivity(nil) should return false")
	}
}

func TestSupportsSSU2_EmptyRouterInfo(t *testing.T) {
	ri := &router_info.RouterInfo{}
	if SupportsSSU2(ri) {
		t.Error("empty RouterInfo should not support SSU2")
	}
}

func TestHasDialableSSU2Address_EmptyRouterInfo(t *testing.T) {
	ri := &router_info.RouterInfo{}
	if HasDialableSSU2Address(ri) {
		t.Error("empty RouterInfo should have no dialable SSU2 address")
	}
}

func TestExtractSSU2Addr_EmptyRouterInfo(t *testing.T) {
	var ri router_info.RouterInfo
	_, err := ExtractSSU2Addr(ri)
	if err == nil {
		t.Error("extracting SSU2 addr from empty RouterInfo should return error")
	}
}
