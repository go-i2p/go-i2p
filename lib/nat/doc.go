// Package nat provides protocol-agnostic NAT-traversal utilities for I2P transports.
//
// This package extracts common NAT binding logic from NTCP2 (TCP) and SSU2 (UDP)
// transports, implementing:
//   - UPnP/NAT-PMP port mapping with configurable timeout and fallback
//   - OS-assigned port probing with TOCTOU race mitigation (P-1)
//   - SO_REUSEADDR socket option for immediate port reuse
//   - Loopback address detection to skip NAT for local testing
//   - Retry-with-jitter for transient bind failures
//
// All public functions are goroutine-safe.
package nat
