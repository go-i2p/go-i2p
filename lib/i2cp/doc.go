// Package i2cp implements the I2P Client Protocol (I2CP) server.
//
// # What is I2CP?
//
// I2CP is the interface that lets ordinary applications talk to the I2P
// network. Instead of speaking I2P's wire protocols directly, an application
// connects to a local I2CP server and uses a simple request/response protocol
// to:
//
//   - Create sessions with a destination keypair (its I2P identity).
//   - Send and receive messages through tunnels.
//   - Publish a LeaseSet so others can reach it.
//
// The server listens on localhost:7654 by default (configurable via
// --i2cp.address). Protocol version: I2CP v0.9.67.
//
// I2CP is defined in the I2P specification:
// https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2cp.rst
//
// # Main components
//
//   - Server: handles TCP and Unix socket connections.
//   - Session: manages a client session and its tunnel pool.
//   - MessageRouter: routes messages through the tunnel system.
//   - Publisher: publishes LeaseSets to the NetDB.
//
// # Known limitations
//
// Message reliability: the i2cp.messageReliability option is parsed and
// stored, but all reliability modes (BestEffort, Guaranteed, None) are
// currently treated as BestEffort. Guaranteed-delivery acknowledgment
// tracking is not implemented. Applications that need guaranteed delivery
// must add their own acknowledgment layer (for example, via the go-streaming
// library).
package i2cp
