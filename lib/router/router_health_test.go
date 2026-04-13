package router

import (
	"testing"
)

func TestCountOpenFDs(t *testing.T) {
	n := countOpenFDs()
	// On Linux, we expect a positive count; on other platforms, -1
	if n == 0 {
		t.Error("countOpenFDs() returned 0, expected >0 on Linux or -1 on non-Linux")
	}
	if n > 0 {
		t.Logf("open file descriptors: %d", n)
	}
}
