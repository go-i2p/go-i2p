Release notes for: `go-i2p` Version `0.1.2-rc1`
==========================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

In version 0.1.1 we officially introduce the `lib/embedded` API for `go-i2p`.
This API allows Go developers to simply and straightforwardly include a `go-i2p` router in their own downstream applications.
This release also corresponds to significant progress in other parts of the namespace, enabled by the new embedded library.

 - [`go-i2cp` now functions as a pure-Go I2CP Client library.](https://github.com/go-i2p/go-i2cp)
 - [`go-datagrams` now functions as a pure-Go I2P Datagrams library](https://github.com/go-i2p/go-datagrams)
 - [`go-streaming` now functions as a pure-Go I2P Streaming library](https://github.com/go-i2p/go-streaming)
 - and most importantly, [`go-sam-bridge` implements the SAMv3.3 API, and embeds a `go-i2p` router, *and* is embeddable itself](https://github.com/go-i2p/go-sam-bridge)

All these changes are building toward the big API target for `go-i2p`, which is making I2P integration as simple as possible for Go applications. The latest checkin of `onramp` now embeds a `go-sam-bridge` and starts it automatically if SAMv3.3 is not available on the host, meaning that in the next version of `onramp`, those who upgrade will seamlessly upgrade to having optional embedded I2P routers. Our hope is that it is also possible to do this for the lower-level `go-sam-go` library as well. Zero-Configuration I2P applications are nearly upon us!
