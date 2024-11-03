# go-i2p Implementation Roadmap

## Transport Layer (NTCP2)
- Build on existing lib/transport/noise implementation
- Core NTCP2 components:
  * Session handshake using noise protocol
  * Connection management
  * I2NP message transport

## Reseed System
- SU3 file format implementation:
  * Format parsing and validation(Much of this work is done in reseed-tools, may need to be moved here)
  * Signature verification system(Much of this work is done in reseed-tools, may need to be moved here)
- Local reseed functionality:
  * File-based reseed operations
- Self-signed/Package-pinned X.509 certificate handling for reseed validation

## NetDb and Database Store
- Database Store message handling:
  * Message structure implementation
  * Message handling implementation
- NetDb core implementation:
  * RouterInfo management
  * LeaseSet management
  * Lookup system
  * Storage interface
  * Peer selection logic?(Maybe do something very basic for now like i2pd used to do, and then improve it later, the important part will be interface design at first)

## Tunnel Implementation
- Tunnel cryptography:
  * Key generation and management
  * Layered encryption scheme
- Message processing:
  * Build request/response handling
  * Gateway implementation
  * Message forwarding logic

Notes:
- Excluding legacy protocols (SSU1, NTCP1, elgamal, DSA)
- Leveraging existing noise protocol implementation
- SSU2 is not on this roadmap but is fair game for implementation as soon as NTCP2 is done. We're focused on NTCP2 to get this thing sending I2NP messages.