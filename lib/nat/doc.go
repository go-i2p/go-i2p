// Package nat provides protocol-agnostic NAT-traversal utilities for I2P
// transports.
//
// # What is NAT traversal?
//
// Most home and office networks sit behind a router that hides them from the
// internet. That router is a NAT (Network Address Translation) device: it
// rewrites addresses so that many devices on the local network can share one
// public address. The downside is that an outside peer cannot simply connect
// to a device inside the network — the router drops unsolicited inbound
// connections.
//
// An I2P router needs to be reachable by other routers, so it has to "punch
// through" the NAT. This package holds the shared logic for doing that, so
// that the TCP transport (NTCP2) and the UDP transport (SSU2) do not each
// reinvent it.
//
// # How it works
//
// The package combines three techniques:
//
//   - Port mapping. It asks the router to open a port using the UPnP
//     (Universal Plug and Play) and NAT-PMP (NAT Port Mapping Protocol)
//     protocols. If the router supports one of these, inbound connections can
//     be forwarded to the router.
//
//   - Binding with traversal. [BindWithNATTraversal] opens a local listener
//     and, where possible, maps the port on the router so the port is
//     reachable from outside.
//
//   - Probing with a race-free rebind. [ProbeAndBindWithNATTraversal] first
//     checks whether a port is free, then closes and rebinds it. This avoids a
//     race (a TOCTOU problem, "time of check to time of use") where the port
//     could be taken between the check and the bind. If the rebind fails
//     because the port was just taken, it retries with a small random delay
//     (jitter) instead of failing immediately.
//
// The package also classifies addresses (loopback, public, special-use) and
// provides retry-with-jitter helpers.
//
// # Usage
//
//	// Bind a UDP listener and map the port on the router if possible.
//	cfg := nat.DefaultBindConfig("udp4", "0.0.0.0:0")
//	result, err := nat.BindWithNATTraversal(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer result.Close()
//
// # Thread safety
//
// All exported functions are safe for concurrent use.
package nat
