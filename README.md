# go-i2p

A pure Go implementation of the I2P router.

## Status

go-i2p was in early development. Now it's being restructured in some
fundamental ways, so it's even less done than before(on this branch, for now)
but when this restructuring is complete, it will be a fully-fledged I2P router
and library for writing, embedding, and possiblly extending I2P routers in Go
applications.

The go module is declared as: `github.com/go-i2p/go-i2p`, in order to clone
anonymously you may use `torsocks` with `go get`(YMMV) or you may clone
it from git.idk.i2p using:

        #Set your $GOPATH, if it isn't set already then GOPATH=$HOME/go
        $GOPATH/go/src/i2pgit.org/idk/
        git clone git@127.0.0.1:idk/go-i2p $GOPATH/go/src/github.com/go-i2p/go-i2p
        $GOPATH/go/src/github.com/go-i2p/go-i2p

And build with `GO111MODULES=off` or use a `replace` directive in your `go.mod`
to direct to the local module source. Or you may run your own Go Modules proxy as
a hidden service. I'll make this about a billion times easier in the near future I
promise.

### Implemented Features

As the application is restructured and moved away from representing I2P data
structures as byte slices, this chart will be filled in. Currently, much of
this is partially implemented in byte-slice versions and partially implemented
as Go Structs. Very little of it will work until it's all moved to Go Structs
where appropriate. Most of this will happen in /lib/common.

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
  - [ ] ElGamal
  - [ ] AES256
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
- Transports
  - [ ] Transport manager
  - NTCP
    - [ ] Handshake
    - [ ] Session tracking
    - [ ] Automatic session creation
  - NTCP2
    - [ ] Handshake
    - [ ] Session tracking
    - [ ] Automatic session creation
  - [ ] SSU


## Contributing

See CONTRIBUTING.md for more information.

## License

This project is licensed under the MIT license, see LICENSE for more information.
