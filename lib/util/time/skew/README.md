# skew

Clock skew validation utilities for I2P router operations.

## Overview

Per the I2P specification (common-structures RouterInfo notes), routers **MUST**
reject RouterInfo with a published timestamp more than 60 minutes in the future
or past relative to the router's NTP-synchronized clock. This package provides
centralized timestamp validation functions to enforce this requirement.

## Usage

### RouterInfo Validation (NetDB)

```go
if err := skew.ValidateTimestamp(routerInfo.Published().Time()); err != nil {
    // Reject the RouterInfo — clock skew too large
    log.Warn("Rejecting RouterInfo:", err)
    return
}
```

### Boolean Check

```go
if !skew.IsTimestampValid(routerInfo.Published().Time()) {
    return ErrClockSkew
}
```

### Custom Skew Window (NTCP2 Handshake)

NTCP2 handshakes use a tighter ±2 minute tolerance:

```go
err := skew.ValidateTimestampWithSkew(handshakeTimestamp, 2*time.Minute)
if err != nil {
    // Reject the handshake
    return err
}
```

## Constants

| Name | Value | Source |
|------|-------|--------|
| `MaxClockSkew` | 60 minutes | I2P spec: common-structures RouterInfo |

## Spec Compliance

- Boundary behavior uses `>` (not `>=`), so a timestamp exactly 60 minutes old
  is accepted. This matches the Java I2P implementation.
- Zero-value `time.Time` is always rejected.
- `ValidateTimestampWithSkew` rejects non-positive `maxSkew` values.

## Integration

This package is used by:

- **`lib/netdb`** — RouterInfo acceptance validation
- **`lib/transport/ntcp2`** — Handshake timestamp validation (with ±2 min window)
