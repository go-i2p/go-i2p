// Package bootstrap provides the interfaces a router uses to join the I2P
// network for the first time, and to reseed its network database later.
//
// # What is bootstrap?
//
// When a router starts, it needs to know about other routers before it can
// talk to them. Bootstrap is the process of loading that initial list of
// peers. It can come from:
//
//   - A reseed server (downloaded over the public internet).
//   - A local file of RouterInfo records.
//   - A directory of previously saved RouterInfo records.
//
// # RouterInfo validation
//
// Not every RouterInfo a reseed server sends is usable. Before a record is
// added to the network database, bootstrap validates it so that only
// well-formed, reachable peers enter the database.
//
// RouterInfo level:
//   - At least one valid RouterAddress must be present.
//   - The RouterInfo structure must be parseable.
//
// RouterAddress level:
//   - The transport style field must be non-empty and valid.
//   - Transport-specific checks apply based on the style:
//   - NTCP2: requires host, port, s (static key), and v (protocol version).
//   - SSU: requires host, port, and key.
//   - SSU2: requires host, port, s (static key), and i (intro key).
//   - The host must be a valid IPv4 or IPv6 address.
//   - The port must be in the valid range (1-65535).
//
// # Validation error reporting
//
// Validation functions return detailed error messages describing why a
// RouterInfo or RouterAddress failed:
//
//   - ValidateRouterInfo(): returns "no valid router addresses found" with the
//     last address validation error.
//   - ValidateRouterAddress(): returns specific errors like "missing required
//     NTCP2 key: s" or "invalid port number".
//   - ValidateNTCP2Address(): checks NTCP2-specific requirements (static key,
//     version, host/port).
//
// # Validation statistics
//
// The ValidationStats type tracks validation metrics during bootstrap:
//
//   - Total RouterInfos processed.
//   - Valid vs invalid counts.
//   - Breakdown of invalid reasons (for example, "missing NTCP2 static key" or
//     "introducer-only address").
//   - Validity rate percentage.
//
// Use ValidationStats.LogSummary() to print validation statistics when
// debugging reseed quality issues.
package bootstrap
