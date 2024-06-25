At long last... something useful
================================

It's been 2 years of me mostly not having time to work on go-i2p itself since my last update.
However, after much waiting, this library is actually **useful** for something.
It is now being used in the `reseed-tools` application to examine RouterInfos prior to including them in reseed bundles.
Routers that self-report as unreachable or congested will be excluded from future reseed bundles.
Additionally, routers that self-report an old version will be excluded from reseed bundles.
This should help new users build better connections faster with the existing, working router implementations.

This is not a working release of a go-i2p router
------------------------------------------------

It is a numbered version of the go-i2p library, which is pre-release, expressly for use in the `reseed-tools` application.
The common library works, and so do some of the cryptographic primitives, however the API is unstable and the software itself is certain to have serious bugs outside of a few well-tested areas.
If you're using it for something other than parsing and analyzing RouterInfos and LeaseSets, you'll probably encounter bugs.
Please report them to the https://github.com/go-i2p/go-i2p
Use any part of it at your own risk.
