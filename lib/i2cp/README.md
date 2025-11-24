# I2CP - I2P Client Protocol

This package implements the I2P Client Protocol (I2CP) v2.10.0, which allows client applications to communicate with the I2P router to create sessions, send messages, and receive messages through the I2P network.

## Overview

I2CP is a client-server protocol that enables applications to:
- Create isolated I2P sessions with unique destinations
- Manage inbound and outbound tunnel pools
- Send messages to other I2P destinations
- Receive messages from other I2P destinations
- Configure tunnel parameters and session settings

## Architecture

The package consists of three main components:

### 1. Protocol (`protocol.go`)
- Message framing and serialization
- Protocol message type definitions
- Wire format encoding/decoding
- Message reading and writing utilities

### 2. Session Management (`session.go`)
- Session lifecycle management
- Client destination generation
- Tunnel pool integration
- Message queue management
- Configuration handling

### 3. Server (`server.go`)
- TCP server on localhost:7654 (default)
- Connection handling and routing
- Multi-client session management
- Message dispatching

## Usage

### Starting the I2CP Server

```go
import "github.com/go-i2p/go-i2p/lib/i2cp"

// Create server with default config
server, err := i2cp.NewServer(nil)
if err != nil {
    log.Fatal(err)
}

// Start listening
if err := server.Start(); err != nil {
    log.Fatal(err)
}
defer server.Stop()
```

### Custom Server Configuration

```go
config := &i2cp.ServerConfig{
    ListenAddr:  "localhost:17654",  // Custom port
    Network:     "tcp",               // or "unix" for Unix sockets
    MaxSessions: 50,                  // Max concurrent sessions
}

server, err := i2cp.NewServer(config)
```

### Creating a Session (Client Side)

```go
import "net"

// Connect to I2CP server
conn, err := net.Dial("tcp", "localhost:7654")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Send CreateSession message
createMsg := &i2cp.Message{
    Type:      i2cp.MessageTypeCreateSession,
    SessionID: i2cp.SessionIDReservedControl,
    Payload:   []byte{}, // Session config payload
}

if err := i2cp.WriteMessage(conn, createMsg); err != nil {
    log.Fatal(err)
}

// Read SessionStatus response
response, err := i2cp.ReadMessage(conn)
if err != nil {
    log.Fatal(err)
}

sessionID := response.SessionID
fmt.Printf("Session created with ID: 0x%04X\n", sessionID)
```

## Protocol Message Types

| Type | Name | Direction | Description |
|------|------|-----------|-------------|
| 1 | CreateSession | Client → Router | Create new session |
| 2 | SessionStatus | Router → Client | Session creation result |
| 3 | ReconfigureSession | Client → Router | Update session config |
| 4 | DestroySession | Client → Router | Terminate session |
| 5 | CreateLeaseSet | Client → Router | Publish LeaseSet |
| 6 | RequestLeaseSet | Router → Client | Request LeaseSet update |
| 7 | SendMessage | Client → Router | Send message to destination |
| 8 | MessagePayload | Router → Client | Received message |
| 9 | GetBandwidthLimits | Client → Router | Query bandwidth |
| 10 | BandwidthLimits | Router → Client | Bandwidth limits response |
| 11 | GetDate | Client → Router | Query router time |
| 12 | SetDate | Router → Client | Current router time |

## Wire Format

Each I2CP message follows this format:

```
+------+----------+--------+----------+
| Type | SessionID| Length | Payload  |
+------+----------+--------+----------+
  1 byte  2 bytes   4 bytes  variable
```

- **Type**: Message type identifier
- **SessionID**: Session identifier (big endian)
- **Length**: Payload length in bytes (big endian)
- **Payload**: Message-specific data

### Message Size Limits

Per the I2CP specification, **message payloads are limited to approximately 64 KB (65,535 bytes)**. This limit applies to:

- SendMessage payloads (destination hash + message data)
- MessagePayload payloads (message ID + decrypted data)

**Important for Client Applications:**

- The I2CP protocol does **NOT** provide automatic message fragmentation
- Client applications **MUST** fragment messages larger than ~64 KB at the application layer
- Attempting to send oversized messages will result in an error

For streaming applications requiring large data transfers, use the I2P Streaming Library which handles fragmentation and reassembly automatically.

## Session Configuration

Sessions can be configured with:

- **Tunnel Parameters**:
  - Inbound/outbound tunnel length (hops): default 3
  - Inbound/outbound tunnel count: default 5
  - Tunnel lifetime: default 10 minutes

- **Network Parameters**:
  - Message timeout: default 60 seconds
  - Nickname for debugging

Example:
```go
config := &i2cp.SessionConfig{
    InboundTunnelLength:  3,
    OutboundTunnelLength: 3,
    InboundTunnelCount:   5,
    OutboundTunnelCount:  5,
    TunnelLifetime:       10 * time.Minute,
    MessageTimeout:       60 * time.Second,
    Nickname:             "my-app",
}
```

## Reserved Session IDs

- `0x0000`: Control messages (pre-session)
- `0xFFFF`: Broadcast to all sessions (reserved)

## Integration with Tunnel Pools

Sessions integrate with the tunnel management system:

```go
session, _ := manager.CreateSession(nil, nil)

// Attach tunnel pools
session.SetInboundPool(inboundPool)
session.SetOutboundPool(outboundPool)

// Use pools for routing
inbound := session.InboundPool()
outbound := session.OutboundPool()
```

## Testing

Run the test suite:

```bash
go test ./lib/i2cp -v
```

Run with coverage:

```bash
go test ./lib/i2cp -cover
```

Current test coverage: **73.4%**

## Implementation Status

### ✅ Completed
- I2CP protocol message framing and serialization
- TCP server with multi-client support
- Session creation, destruction, and reconfiguration
- Session manager with automatic ID allocation
- Message queue management for incoming messages
- Integration framework for tunnel pools

### 🚧 In Progress (Phase 6)
- LeaseSet creation and publishing
- SendMessage payload parsing and routing
- MessagePayload delivery to clients
- Bandwidth limit reporting
- I2P time encoding for GetDate/SetDate

## References

- [I2CP Specification](https://geti2p.net/spec/i2cp)
- Protocol Version: 2.10.0
- Default Port: 7654 (TCP)

## License

MIT License - See LICENSE file for details
