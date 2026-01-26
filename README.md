# `go-i2p`

A pure Go implementation of the I2P router.

## Status

`go-i2p` is in active development. We recently completed several significant milestones including:

- **Complete I2CP Protocol Server**: Full session lifecycle management, message routing, and client support
- **End-to-End Message Routing**: Complete message routing system connecting I2CP clients through tunnels to other destinations with garlic encryption
- **Tunnel System**: Automatic tunnel building, pool management, and cryptographic processing
- **Transport Layer**: Full NTCP2 implementation with session management

The core router functionality is now operational. We have tested functionality using i2psnark-standalone against our I2CP API server. Basic compatibility is available. We are now focused application layer protocols. We have most of an I2CP client, part of a Streaming library, and almost none of a Datagrams library, all of which are requirements for SAMv3.3, which is what all our applications use. Therefore those are our next targets. After the turn of the year, we will return our focus to transports by implementing SSU2.

**`go-i2p`'s network presence is HIGHLY DISTINCTIVE at this time.** This is because:

 - We do not yet implement SSU2, all our routers are NTCP2 only. This will change.
 - We do not implement Elgamal or AES+SessionTag or DSA. This will not change.

### Implemented Features

- Clients
  - [X] I2CP Protocol Server (v2.10.0 - tested with i2psnark-standalone)
  - [X] Message routing (outbound I2CP → tunnels → garlic encryption)
  - [X] Inbound message delivery (tunnel → I2CP sessions)
  - [X] [I2CP Client: https://github.com/go-i2p/go-i2cp](https://github.com/go-i2p/go-i2cp)
  - [X] [Datagrams: https://github.com/go-i2p/go-datagrams](https://github.com/go-i2p/go-datagrams)
  - [X] [Streaming: https://github.com/go-i2p/go-streaming](https://github.com/go-i2p/go-streaming)
  - [ ] [SAM API v3.3: https://github.com/go-i2p/go-sam-bridge](https://github.com/go-i2p/go-sam-bridge)
- [Cryptographic primitives(see also: https://github.com/go-i2p/crypto)](https://github.com/go-i2p/crypto)
  - Signing
    - [X] ECDSA_SHA256_P256
    - [X] ECDSA_SHA384_P384
    - [X] ECDSA_SHA512_P521
    - [X] Ed25519
  - Verifying
    - [X] DSA
    - [X] ECDSA_SHA256_P256
    - [X] ECDSA_SHA384_P384
    - [X] ECDSA_SHA512_P521
    - [X] RSA_SHA256_2048
    - [X] RSA_SHA384_3072
    - [X] RSA_SHA512_4096
    - [X] Ed25519
    - [ ] Red25519
  - [X] ElGamal
  - [X] AES256
  - [X] X25519
  - [X] ChaCha20/Poly1305
  - [X] Elligator2
  - [X] HKDF
  - [X] HMAC
  - [X] Noise subsystem
- End-to-End Crypto
  - [X] Garlic messages
  - [X] ECIES-X25519-AEAD-Ratchet (primary)
  - [ ] ElGamal/AES+SessionTag (not implemented - ECIES-only destinations supported)
- I2NP
  - [X] Message parsing and serialization
  - [X] Message interfaces and factory patterns
  - [X] Database Store/Lookup message structures
  - [X] Tunnel Build message structures
  - [X] Data, DeliveryStatus, TunnelData messages
  - [X] Build Request/Response Record parsing
  - [X] Message routing and handling
- NetDB
  - [X] Local storage interface
  - [X] Reseed functionality (basic implementation)
  - [X] Persistence to disk
  - [X] RouterInfo management
  - [X] LeaseSet management
  - [X] Lookups
  - [X] Expiry
  - [X] Exploration
  - [X] Publishing
  - [X] Floodfill
  - [~] LS2 and Encrypted Leasesets (I2CP clients can publish; storage/retrieval supported; inbound client-side decryption and MetaLeaseSet resolution pending)
- Transport Layer
  - [X] Transport manager and interfaces
  - NTCP2
    - [X] Session handshake using noise protocol
    - [X] Connection management
    - [X] I2NP message framing and unframing
    - [X] Session lifecycle management
    - [X] Message queuing and worker threads
  - SSU2
    - [ ] Session handshake
    - [ ] Connection management
    - [ ] Peer Tests
    - [ ] Introducers
  - [Noise Subsystem (see also https://github.com/go-i2p/go-noise)](https://github.com/go-i2p/go-noise)
    - [X] Noise Socket Framework
    - [X] NTCP2 Socket Framework
    - [ ] SSU2 Socket Framework
- Tunnels
  - [X] Message structure parsing (delivery instructions)
  - [X] Fragment handling and reassembly
  - [X] Build Request/Response record interfaces
  - [X] Tunnel building and management
  - [X] Tunnel cryptography (layered encryption)
  - [X] Gateway and endpoint implementation
  - [X] Participant functionality
- [Common Data Structures(see also: https://github.com/go-i2p/common](https://github.com/go-i2p/common)
    - [X] Keys and Cert
    - [X] Key Certificates
    - [X] Certificate
    - [X] Lease
    - [X] Lease Set
    - [X] Router Info
    - [X] Router Identity
    - [X] Router Address
    - [X] Session Key
    - [X] Signature Types
    - [X] Destination
    - [X] Data Types
    - [X] Session Tag

## Verbosity ##
Logging can be enabled and configured using the `DEBUG_I2P` environment variable. By default, logging is disabled.

> **Note:** Logging is configured via environment variables (not config.yaml or command-line flags) because it is managed by an external logger package and needs to be set before the application starts.

There are three available log levels:

- Debug
```shell
export DEBUG_I2P=debug
```
- Warn
```shell
export DEBUG_I2P=warn
```
- Error
```shell
export DEBUG_I2P=error
```

If DEBUG_I2P is set to an unrecognized variable, it will fall back to "debug".

## Fast-Fail mode ##

Fast-Fail mode can be activated by setting `WARNFAIL_I2P` to any non-empty value. When set, every warning or error is Fatal.
It is unsafe for production use, and intended only for debugging and testing purposes.

```shell
export WARNFAIL_I2P=true
```

If `WARNFAIL_I2P` is set and `DEBUG_I2P` is unset, `DEBUG_I2P` will be set to `debug`.

## I2CP Server

The I2CP (I2P Client Protocol) server allows client applications to communicate with the I2P router. It is enabled by default and listens on `localhost:7654`.

### Configuration

You can configure the I2CP server using command-line flags:

```shell
# Disable I2CP server
go-i2p --i2cp.enabled=false

# Change listen address
go-i2p --i2cp.address=0.0.0.0:7654

# Adjust maximum sessions (default is 100)
go-i2p --i2cp.max-sessions=200

# Use Unix domain socket instead of TCP
go-i2p --i2cp.network=unix --i2cp.address=/tmp/i2cp.sock
```

### Features

- **Session Management**: Create, reconfigure, and destroy client sessions
- **Message Protocol**: Full I2CP v2.10.0 protocol implementation
- **Multi-client Support**: Handle multiple concurrent client sessions (default: 100)
- **Thread-safe**: Concurrent session access with proper synchronization

For more details, see `lib/i2cp/README.md`.

## Contributing

See CONTRIBUTING.md for more information.

## License

This project is licensed under the MIT license, see LICENSE for more information.
