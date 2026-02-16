// Package skew provides clock skew validation utilities for I2P router operations.
//
// Per the I2P specification (common-structures RouterInfo notes), routers MUST reject
// RouterInfo with a published timestamp more than 60 minutes in the future or past
// relative to the router's NTP-synchronized clock. This package provides centralized
// timestamp validation functions to enforce this requirement consistently.
//
// Usage:
//
//	if err := skew.ValidateTimestamp(routerInfo.Published().Time()); err != nil {
//	    // Reject the RouterInfo
//	}
package skew
