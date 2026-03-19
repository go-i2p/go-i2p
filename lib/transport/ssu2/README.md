# ssu2
--
    import "github.com/go-i2p/go-i2p/lib/transport/ssu2"

Package ssu2 implements the SSU2 (Secure Semireliable UDP 2) transport protocol
for I2P router-to-router communication.

# Status: IMPLEMENTED

This package wraps the `go-noise/ssu2` library behind the `transport.Transport`
and `transport.TransportSession` interfaces used by the go-i2p router.

# Features

    - UDP-based transport with lower latency than NTCP2
    - Session handshake using Noise XK pattern
    - Congestion control (slow-start, congestion-avoidance, fast-recovery)
    - Retransmission with exponential backoff (configurable max attempts)
    - RTT estimation (smoothed RTT + RTTVAR)
    - Peer testing for NAT detection
    - Introducer support for NAT traversal
    - Connection migration for roaming clients
    - Block callback integration for all 20 SSU2 block types

# I2P Specification

SSU2 is defined in the I2P specification at: https://geti2p.net/spec/ssu2

# Configuration

    transport:
      ssu2_enabled: true
      ssu2_port: 9002   # 0 = random port assigned by OS

Advanced options (set programmatically via ssu2.Config):

    config.KeepaliveInterval  = 15 * time.Second  // SSU2.md default
    config.MaxRetransmissions = 3                 // attempts before teardown
    config.MaxSessions        = 512               // concurrent session limit

# Usage

    cfg, _ := ssu2.NewConfig(":9002")
    t, _ := ssu2.NewSSU2Transport(routerInfo, cfg, keystore)
    defer t.Close()

    // Outbound
    session, _ := t.GetSession(peerRouterInfo)
    session.QueueSendI2NP(msg)

    // Inbound
    conn, _ := t.Accept()

See lib/transport/ntcp2 for the analogous TCP transport implementation.

## Usage
