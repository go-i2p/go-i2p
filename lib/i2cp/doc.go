// Package i2cp implements the I2P Client Protocol (I2CP) server.
//
// I2CP allows client applications to communicate with the I2P network by:
//   - Creating sessions with destination keypairs
//   - Sending and receiving messages through tunnels
//   - Managing LeaseSet publication
//
// The server listens on localhost:7654 by default (configurable via --i2cp.address).
// Protocol version: I2CP v0.9.67
//
// Main components:
//   - Server: Handles TCP/Unix socket connections
//   - Session: Manages client sessions and tunnel pools
//   - MessageRouter: Routes messages through tunnel system
//   - Publisher: Publishes LeaseSets to NetDB
//
// # Known Limitations
//
// Message Reliability: The i2cp.messageReliability option is parsed and stored
// but all reliability modes (BestEffort, Guaranteed, None) are currently treated
// as BestEffort. Guaranteed delivery acknowledgment tracking is not implemented.
// Applications requiring guaranteed delivery must implement their own acknowledgment
// layer (e.g., via the go-streaming library).
package i2cp
