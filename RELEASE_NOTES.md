Release notes for: `go-i2p` Unreleased
======================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

This release closes out a full specification-compliance audit against the language-agnostic I2P
specifications referenced from the package documentation. Four Critical and nine Warning findings were
fixed, each with a regression test verified to fail against the unfixed code.

Tunnel building changed most. Build records are now shuffled into random wire slots, as the spec
requires, with the slot index used as the ChaCha20 nonce on both the creator and hop side. Inbound
tunnels additionally insert a "phony" record carrying our own router hash and a real ephemeral key, and
both record sets are padded to the spec's minimum of four and maximum of eight, so a relay cannot tell
which records are ours. Because the phony record's creator layers and the hop re-XORs cancel exactly,
it returns byte-identical, which is what lets us detect records modified in transit; that check is now
performed and a tampered tunnel is discarded. The default build expiration moved from 480 to the
specified 600 seconds.

NTCP2 now performs the protocol handshake on inbound connections instead of the generic transport one,
validates block ordering, verifies the `s=`/`i=`/`v=` address options before dialing, accepts unpadded
I2P base64 and addresses published as `"NTCP"`, stops fragmenting I2NP messages across ChaChaPoly
frames, reports the true count of valid frames received in its termination block, validates remote
static keys as X25519 curve points, and persists its last-shutdown time. SSU2 now rejects out-of-session
Peer Test and Hole Punch messages that are stale or missing a DateTime block, which closes an unbounded
replay hole against unauthenticated traffic, and its termination handling delegates to go-noise.

I2CP asynchronous message statuses now carry the originating nonce instead of zero, a nonce of zero
suppresses the status as specified, DestroySession answers with a DisconnectMessage and closes the
connection, unsupported message types disconnect rather than being logged and skipped, the session
config Mapping sort order is enforced so signatures verify, and CreateLeaseSet2's store type now selects
the framing, validation and NetDB record type instead of being parsed and discarded. BandwidthLimits are
reported in KBps as the spec defines rather than bytes per second. `[String]` fields use the specified
one-byte length prefix.

Noncompliant dead APIs were deleted after confirming the live path uses a conformant replacement: the
NTCP2 options serializer (11 bytes where the spec requires 12), `I2NPUnframer` (a four-byte prefix where
the spec defines two), the SSU2 `FragmentI2NPMessage`/`FrameI2NPToBlock` pair, and
`ShortTunnelBuild.Bytes()`, which emitted unsendable cleartext records.

A note on I2NP TunnelBuild (21) and TunnelBuildReply (22), which an earlier release removed as
"deprecated": the specification's message registry does label them deprecated, but the normative notes
for those same two messages state they "has not been deprecated. Routers must implement." The removed
handler could not parse encrypted records, so deleting it did not remove working capability, and
VariableTunnelBuild covers the same one-to-eight record range, but the gap is real and is recorded as
outstanding rather than resolved. The same correction applies to I2CP DestLookup (34) and DestReply (35),
which the registry never labelled deprecated at all.

Several validation gaps belong to upstream go-noise rather than to this repository and are reported
there instead of patched locally: `writeFramed` silently fragmenting payloads, the missing minimum-size
check on msg3 part 2 Options blocks, the responder's inability to learn Alice's intro key on the listener
path, and the replay cache being created only for responders.

**This release requires go-noise at or past `6372d5b`, which is not yet on `trunk`.** Moving the SSU2
test harnesses onto the production listener path exposed a real upstream defect: a router using one
shared SSU2 listen socket — the normal deployment — could not receive any data-phase traffic for an
accepted session, because the SessionConfirmed and Data header protectors share `k_header_1` and the
demuxer matched on the destination connection ID alone, so the wrong protector false-matched first and
the payload was never decrypted. go-noise's own suite had no test that delivered data over the listener,
so the bug was invisible there; `6372d5b` fixes it and adds that missing test. Building against
go-noise `trunk` still passes `go build ./...` but fails four SSU2 integration tests at their read
timeouts. The fix must be merged onto `trunk` and pushed. Routing the tests back around the listener was
rejected: that is the non-production path which hid the bug, and `ssu2.rst:1587-1588` forbids it.

A second go-noise listener defect was exposed while stabilising those same harnesses and is likewise
reported upstream rather than patched locally. The data-phase inbound header protector is installed
out-of-band: `SSU2Conn.notifyRecvDataKey` performs a non-blocking send (a `select` with a `default`
branch) into a channel the listener wires up separately, and a listener goroutine then calls
`AcceptedSessionRegistry.SetDataPhaseProtector`. On rare schedules the protector is never installed for
that session, and because `TrialDeobfuscate` silently skips sessions it cannot deobfuscate, every
inbound data-phase packet for the session is dropped for good. The sender gets no feedback — data
packets are retransmitted only on RTO expiry for unACKed packets, never because the peer could not
deobfuscate them — so the loss is unrecoverable within the session. This was confirmed empirically: the
failing sessions never delivered a message across ten send retries spanning 30 seconds while the reader
stayed alive, and re-establishing the session instead of re-sending reduced the SSU2 package failure
rate from 3/100 to 0/100. go-i2p's test harnesses now verify both data directions before handing a
session to a test, so the race is detected and bounded rather than asserted through.

Release notes for: `go-i2p` Version `0.1.70001`
============================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

Fixes an issue where tunnels were never ready for leaseset publication.
Fixes another issue where incorrect keys were used for inbound tunnels.

Release notes for: `go-i2p` Version `0.1.67`
==========================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

This release resolves issues across the entire codebase.
Bugs in the tunnel system were especially widespread and have been the focus of resolution.
The code has been extensively refactored to enforce the intended scope of all packages.
Ratchet has been factored out of go-i2p and moved to go-noise.
Preliminary support for SSU2 is now available.

Release notes for: `go-i2p` Version `0.1.4`
==========================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

This release refactors several netDb subsystems to be more flexible when selecting peers.
We have implemented congestion cap handling, both honoring remote congestion caps and broadcasting our own congestion state.
We have implemented proper reseeding, downloading RouterInfos from multiple sources, verifying TLS and SU3 certificates, to meet the reseed security model.
We have fixed dozens of bugs all over the codebase and closed multiple functional gaps.

Release notes for: `go-i2p` Version `0.1.3`
==========================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

This release resolves build issues in `go-i2p/crypto` and brings the library stack into sync.

Release notes for: `go-i2p` Version `0.1.2`
==========================================

This release is only recommended for developers at this time.
The first general-use release will be version `0.2.0`

This release was conducted specifically to test CI/CD pipelines and to bring the library stack in sync.

Release notes for: `go-i2p` Version `0.1.1`
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

Production uses the same go-noise listener (startSSU2Listener in lib/transport/ssu2/transport.go), so an
accepted inbound session there can be affected too. It is survivable rather than benign: the peer gets no
answer, gives up on the session and dials a fresh one, which re-establishes the protector. It still costs
a session setup and any in-flight message, so it is worth fixing upstream.
