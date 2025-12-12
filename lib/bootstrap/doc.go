// provides generic interfaces for initial bootstrap into network and network reseeding
//
// # RouterInfo Validation
//
// The bootstrap package performs comprehensive validation on all RouterInfo entries
// obtained from reseed servers, local files, or netDb directories. This validation
// ensures that only well-formed, usable peer information enters the router's network database.
//
// # Validation Checks Performed
//
// RouterInfo Level:
//   - At least one valid RouterAddress must be present
//   - RouterInfo structure must be parseable
//
// RouterAddress Level:
//   - Transport style field must be non-empty and valid
//   - Transport-specific validation applies based on style:
//   - NTCP2: Requires host, port, s (static key), and v (protocol version) keys
//   - SSU: Requires host, port, and key keys
//   - SSU2: Requires host, port, s (static key), and i (intro key) keys
//   - Host must be a valid IPv4 or IPv6 address
//   - Port must be in valid range (1-65535)
//
// # Validation Error Reporting
//
// Validation functions return detailed error messages describing why a RouterInfo
// or RouterAddress failed validation:
//   - ValidateRouterInfo(): Returns "no valid router addresses found" with the last address validation error
//   - ValidateRouterAddress(): Returns specific errors like "missing required NTCP2 key: s" or "invalid port number"
//   - ValidateNTCP2Address(): Checks NTCP2-specific requirements (static key, version, host/port)
//
// # Validation Statistics
//
// The ValidationStats type tracks validation metrics during bootstrap:
//   - Total RouterInfos processed
//   - Valid vs invalid counts
//   - Breakdown of invalid reasons (e.g., "missing NTCP2 static key", "introducer-only address")
//   - Validity rate percentage
//
// Use ValidationStats.LogSummary() to output validation statistics for debugging reseed quality issues.
package bootstrap
