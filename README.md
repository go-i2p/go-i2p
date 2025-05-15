# go-i2p

A pure Go implementation of the I2P router.

## Status

go-i2p is in early development. The master branch is being refactored and API's are
definitely going to change. If you choose to use any part of this code right now,
please keep up with these changes, as they will not be backward compatible and require
**Fundamentally** changing any code that treats this as a dependency.

### Implemented Features

- Clients
  - [ ] Datagrams
  - [ ] I2CP
  - [ ] Message routing
  - [ ] Streaming
- Cryptographic primitives
  - Signing
    - [ ] ECDSA_SHA256_P256
    - [ ] ECDSA_SHA384_P384
    - [ ] ECDSA_SHA512_P521
    - [X] Ed25519
  - Verifying
    - [X] DSA
    - [ ] ECDSA_SHA256_P256
    - [ ] ECDSA_SHA384_P384
    - [ ] ECDSA_SHA512_P521
    - [ ] RSA_SHA256_2048
    - [ ] RSA_SHA384_3072
    - [ ] RSA_SHA512_4096
    - [X] Ed25519
    - [ ] Red25519
  - [X] ElGamal
  - [X] AES256
  - [X] X25519
  - [X] ChaCha20/Poly1305
  - [ ] Elligator2
  - [ ] HKDF
  - [X] HMAC
  - [X] Noise subsystem
- End-to-End Crypto
  - [ ] Garlic messages
  - [ ] ElGamal/AES+SessionTag
  - [ ] Ratchet/X25519
- I2NP
  - [ ] Message parsing
  - [ ] Message handling
- NetDB
  - [~] Local storage
  - [~] Persistence to disk
  - [X] Reseeding
  - [ ] Lookups
  - [ ] Expiry
  - [ ] Exploration
  - [ ] Publishing
  - [ ] Floodfill
  - [ ] LS2 and Encrypted Leasesets
- Transports
  - [X] Transport manager
  - NTCP2
    - [X] Handshake
    - [ ] Session tracking
    - [ ] Automatic session creation
  - SSU2
    - [ ] Handshake
    - [ ] Session tracking
    - [ ] Automatic session creation
    - [ ] Peer Tests
    - [ ] Introducers
- Tunnels
    - [ ] Building
    - [ ] Build Message Crypto (ElGamal)
    - [ ] Build Message Crypto (ECIES)
    - [ ] Participating
    - [ ] Tunnel Message Crypto
    - [ ] Tunnel Message Fragmentation/Reassembly
- Common Data Structures
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

## Contributing

See CONTRIBUTING.md for more information.

## License

This project is licensed under the MIT license, see LICENSE for more information.
