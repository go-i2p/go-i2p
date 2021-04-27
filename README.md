# go-i2p

A pure Go implementation of the I2P router.

## Status

go-i2p is in early development.

### Implemented Features

- Clients
  - [ ] Datagrams
  - [ ] I2CP
  - [ ] Message routing
  - [ ] SAM
  - [ ] Streaming
  - [ ] Tunnel Manager
- Cryptographic primitives
  - Signing
    - [ ] ECDSA_SHA256_P256
    - [ ] ECDSA_SHA384_P384
    - [ ] ECDSA_SHA512_P521
    - [ ] Ed25519
  - Verifying
    - [ ] DSA
    - [ ] ECDSA_SHA256_P256
    - [ ] ECDSA_SHA384_P384
    - [ ] ECDSA_SHA512_P521
    - [ ] RSA_SHA256_2048
    - [ ] RSA_SHA384_3072
    - [ ] RSA_SHA512_4096
    - [ ] Ed25519
    - [ ] Red25519
  - [ ] ElGamal
  - [ ] AES256
  - [ ] X25519
  - [ ] ChaCha20/Poly1305
  - [ ] Elligator2
  - [ ] HKDF
  - [ ] HMAC
  - [ ] Noise subsystem
- End-to-End Crypto
  - [ ] Garlic messages
  - [ ] ElGamal/AES+SessionTag
  - [ ] Ratchet/X25519
- I2NP
  - [ ] Message parsing
  - [ ] Message handling
- NetDB
  - [ ] Local storage
  - [ ] Persistence to disk
  - [ ] Reseeding
  - [ ] Lookups
  - [ ] Expiry
  - [ ] Exploration
  - [ ] Publishing
  - [ ] Floodfill
  - [ ] LS2 and Encrypted Leasesets
- Transports
  - [ ] Transport manager
  - NTCP2
    - [ ] Handshake
    - [ ] Session tracking
    - [ ] Automatic session creation
  - SSU
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


## Contributing

See CONTRIBUTING.md for more information.

## License

This project is licensed under the MIT license, see LICENSE for more information.
