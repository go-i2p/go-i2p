# ssu2
--
    import "github.com/go-i2p/go-i2p/lib/transport/ssu2"

Package ssu2 will implement the SSU2 (Secure Semireliable UDP 2) transport
protocol for I2P router-to-router communication.

# Status: NOT IMPLEMENTED

This package is a placeholder. SSU2 transport is planned for future development
after the current focus on application layer protocols (Streaming, Datagrams,
SAM v3.3).

Until SSU2 is implemented, all go-i2p routers are NTCP2-only, which means:

    - Connections require TCP connectivity
    - NAT traversal via introducers is not available
    - Routers may be unreachable by peers that only support SSU2

# Planned Features

When implemented, SSU2 will provide:

    - UDP-based transport with lower latency than NTCP2
    - Session handshake using Noise XK pattern
    - Peer testing for NAT detection
    - Introducer support for NAT traversal
    - Connection migration for roaming clients

# I2P Specification

SSU2 is defined in the I2P specification at: https://geti2p.net/spec/ssu2

# Configuration

The router configuration supports SSU2 settings (for future use):

    transport:
      ssu2_enabled: false  // Will be true when implemented
      ssu2_port: 0         // Random port when 0

# Implementation Notes

SSU2 implementation will require:

    - Noise protocol integration (similar to NTCP2)
    - UDP socket management
    - Packet reassembly and congestion control
    - Session state machine
    - Introducer protocol

See lib/transport/ntcp2 for the existing TCP transport implementation.

## Usage
