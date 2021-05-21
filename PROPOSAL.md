Proposal for developing go-i2p
==============================

Goals:
------

Make it easy to seamlessly integrate Go applications with I2P routers where
a pre-installed I2P router with SAM is not already present.

Implement an I2P library with a memory-safe language capable of outputting
shared objects and C libraries for use by other languages, in order to make
embedding I2P in other projects easier.

### Why Go? 

Go is a popular programming language developed at Google and now
implemented by several projects. It is a memory-safe language which compiles
binary executables for a target platform, as opposed to running on a virtual
machine or interpreter. Go features a suite of cross-compilers with identical
usage, making it a "Write-once, compile-anywhere" language. This is especially
true when writing pure Go. Go compilers normally produce executables which are
maximally "static" and only link dynamic libraries provided by the platform
when instructed to specifically, however this behavior can be disabled. Go
libraries can produce shared objects for other applications to use, and third
party Go applications can seamlessly generate C bindings as a bridge to other
languages. I can do this automatically with Java by generating JNI bindings,
enabling go-i2p to interface with Java I2P readily.

### Why go-i2p?

go-i2p was a project to implement an I2P router and library of I2P structures
using Go which gained interest for a time 7-8 years ago, but which has since
gone dormant. In spite of that considerable lapse in time, the structure is
a sound, understandable way of laying out a Go project and the extant code is
usable as the basis for beginning the development of a Go based I2P router.
It will considerably reduce the amount of work required to create a Go I2P
router.

### Why Go Applications?

Go applications manage network connections and listeners in a way which
enables easily configuring alternate transports and building different types
of "addresses" which are useful for contacting people on those transports.
The advantages of this approach will likely affect all parts of the go-i2p
router and the applications that come with it. At this time the power of this
approach is primarily visible in the power of Go's SAM libraries, which
implement all of Go's interface types for network connections and addresses
and can be "swapped" with any Go library which uses those interface types.
In a matter of an hour or two, sometimes even less a developer who wishes
to make their application able to build I2P connections can do so.

Moreover, these connections can often be used to transport other connections
inside. It is therefore possible to use Go as an alternate way of doing
"Native WebRTC" using I2P connections and add WebTorrent support to a
desktop I2P BitTorrent Application. The best way to do this would be to
add support to the `anacrolix/torrent` library which already supports regular
WebTorrent.

Another key application is IPFS. IPFS is designed to use transports in a
way which allows them to be readily substituted out, nested and combined.
Interest in I2P transports has been expressed to me before, and I've enabled
them using SAM in the past. Interestingly, however, IPFS has it's own pluggable
peer-discovery methods as well, inclusing the "Hashmatter" anonymous DHT and
in fact an IPFS network could hypothetically use a NetDB-like structure for
anonymous peer discovery and also have I2P transports(related or unrelated).

Deeper into the router, this approach yields possibilities for experimenting
with other types of transports, in particular transports which imitate other
traffic. Tor's pluggable transports are largely written in Go, for instance,
but perhaps more interestingly Go has a library for building custom SSH clients
and servers(`gliderlabs/ssh`) which could be used to build ssh-alike transports
that wouldn't be easily distinguishable from the real thing. Besides that,
there is `pion/webrtc` and the accompanying libraries, which implement a
memory-safe desktop WebRTC implementation that is used in Snowflake to mimic
browser-to-browser connections WebRTC as a Tor pluggable transport. There are
popular Go libraries which are used for everything from TLS to KCP, and each
potential transport would need to be evaluated for utility, security, etc,
however implementing such an "imitating" transport should eventually be
something we are able to rapidly prototype by implementing our own `transport`
interface and wrapping existing connection types.

#### Specific Applications

Besides having the most extensive SAM and I2CP libraries available in a Non-Java
language, go has several applications which could improve I2P's ecosystem.

##### Extant, applications that have users

 - [XD](https://github.com/majestrate/XD) - Simple bittorrent client with a WebUI
  and a custom RPC interface
 - [libanonvpn](https://github.com/RTradeLtd/libanonvpn) - Easy, self-healing TUN
  Devices over I2P on Linux, OSX, TAP devices over I2P on Windows
 - [BRB](https://github.com/eyedeekay/brb) - I2P IRC client with the ability to
  support multiple simultaneous anonymous users, a built-in IRC server, and a
  WebIRC interface for easy ephemeral groupchat.
 - [Railroad](https://github.com/eyedeekay/railroad) - Easy selfhosted blogging
  tool which supports live, WYSIWYG editing using a side-by-side Mardown Editor
  and Preview Panel.
 - [sam-forwarder](https://github.com/eyedeekay/sam-forwarder) - Versatile tunnel
  building and management tool like i2ptunnel with similar support. Slightly easier
  HTTPS support.
 - [eephttpd](https://github.com/eyedeekay/eephttpd) - Simple static http server
  with the ability to clone a git repository and automatically generate a site,
  and to in-turn be cloned by another git client. Also has a built-in bittorrent
  tracker and generates/shares a .torrent of everything in the docroot, with itself
  as a web seed.
 - [reseed-tools](https://i2pgit.org/idk/reseed-tools) Reseed server and library for
  handling `.su3` files in Go.
 - [syndie](https://github.com/kpetku/syndie-core) Maintained implementation of the
  Syndie message board system in Go.

... Many, many others but these are the most useful.

##### Partial/In Development

 - [Brook](https;//github.com/txthinking/brook) - Selfhosting multi-transport VPN and
  transparent proxy with Android support.
 - [bt](https://github.com/xgfone/bt) - a very simple, readable, and safe pure-Go
  bittorent library with a similar set of features to I2PSnark.  Although `anacrolix/torrent`
  supports more features, `xgfone/bt` is slightly easier to work with when cross-compiling.
 - [gophertunnel/gopherhole](https://i2pgit.org/idk/gophertunnel) - Are a simple Gopher
  client and server in pure Go which automatically configure themselves with I2P. Also
  has the ability to proxy Gopher content into the I2P Web.
 - [darkssh/darksshd](https://github.com/eyedeekay/darkssh) - SSH client and server
  with transparent support for I2P and Tor addresses, making MITM attacks based on
  social-engineering SSH clients into connecting to malicious servers impossible.
 - [samsocks](https://github.com/eyedeekay/samsocks) - Transparent socksifier with UDP
  support, built on SAM.
 - [i2pbrowser](https://github.com/eyedeekay/i2pbrowser) - Not pure go, this is
  actually an installer and bundling tool intended to pre-configure a browser
  for use with I2P and a suite of I2P applications. In a far-fling future where
  go-i2p is completed, this i2pbrowser would embed go-i2p instead of i2p-zero,
  while retaining it's other "router-agnostic" attitudes.

##### Proposed

 - [Smallstep] - Smallstep is a Certificate Authority by Let's Encrypt which is often
  used for private CA's for SSH servers. It has ACME protocol support. It could be used
  in I2P as a CA for I2P sites
 - [torrent](https://github.com/anacrolix/torrent) - Anacrolix torrent is a very popular
  Bittorrent library used in 20-30 bittorrent clients, and which has features which are
  comparable to BiglyBT.
 - [Gitea](https://github.com/gitea/gitea) - Gitea is a Git web server similar to Gitea
  but in most ways simpler to self-host.
 - [Syncthing](https://github.com/syncthing/syncthing) - Syncthing is a continuous,
  multi-device file synchronization tool which combines concepts from Git with Bittorrent
  downloads to provide fast, decentralized file synchronization.
 - [webrtc](https://github.com/pion/webrtc) - Go has the only implementation of the WebRTC
  stack in a memory-safe language. `pion/webrtc` can be used with alternate transports and
  listeners as is standard in Go so it lends itself to adapting WebRTC applications to Go.
 - [SAM-PT] This is a pluggable transport for Tor which has two parts: on the server side,
  an I2P-enabled Tor bridge serving itself over a single hop. On the client side, an I2P
  enabled pluggable transport client connecting to the Tor bridge over any number of hops.
  This is a means of hiding the address of long-term bridge operators from probing by
  malicious actors who attempt to access Tor bridges for enumeration purposes.

### What are the alternatives?


 - Wrap `libi2pd/api.h` in a C library, provide a CGO wrapper to interface with Go.
  - I can't think of a single reason not to do this, regardless of whether go-i2p
   development is supported by the project. There are good reasons to do both, but
   it's not actually a good reason not to develop go-i2p. This also does not gain the same
   ability to experiment with i2p at the transport level that a complete go-i2p would.
   Nonetheless, the value for embedders is tremendous so a C interface to i2pd is likely
   to be completed by me soon anyway.
 - Continue development on `str4d/ire`.
  - While this is a fine idea, and ire is technically more complete than go-i2p,
   I've written hundreds of thousands of lines of Go, and understand the details of
   the language intimately. On the other hand, I've written exactly 98 lines of Rust,
   exactly the amount required to stand up my pastebin. I also know developers in the
   Go application community who are already asking me about contributing.

Milestones and Ongoing Tasks
----------------------------

 - Milestone 1: Common Structures Update
 - Milestone 2: Have a transport(NTCP2)
 - Milestone 3: Connect 2 go-i2p routers on the same network.
 - Milestone 4: Have a working NetDB
 - Milestone 5: Communicate across a tunnel with an extant I2P router on a testnet.
 - Milestone 6: Be a functioning standalone Reseed Server
 - Milestone 7: Streaming and Datgram Libraries
 - Milestone 9: Provide a usable I2CP Socket
 - Milestone 9: Build a SAM API on the I2CP Socket

It should be considered essential that in particular all exposed function, struct, and
interface comments pass `golint` and `go vet` at all times, since this is expressly intended
to produce a useful library for building I2P routers.