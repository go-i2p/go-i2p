# SSU2: what "experimental" means

Updated: 2026-11-03 (inbound accept path added; see "Inbound accept path")

The README marks the SSU2 transport **currently experimental**
(`README.md`, and the `--transport.ssu2-enabled` help text). That label has
until now carried no specifics. This document states exactly what is and is not
proven, what the known gaps are, and what has to happen before the designation
can be dropped.

SSU2 is enabled by default (`lib/config/defaults.go` →
`DefaultTransportConfig.SSU2Enabled = true`), so "experimental" here describes
confidence level, not an opt-in preview.

## What is implemented

Everything the spec's core SSU2 surface requires, in
[`lib/transport/ssu2`](../lib/transport/ssu2) (22 non-test files) on top of the
`go-noise/ssu2` Noise state machine:

| Area | Status | Where |
|---|---|---|
| Session handshake (Noise XK) | Implemented | delegated to `go-noise/ssu2/handshake` |
| Connection management | Implemented | `transport.go`, `session.go` |
| Fragmentation / reassembly | Implemented | `fragments.go` |
| Congestion control | Implemented | `session.go` (`congestionCtrl`, `sendWithCongestionControl`) |
| Connection migration | Implemented | `go-noise/ssu2/session/conn_read.go` (path validation per spec §"Connection Migration") |
| Peer tests (all roles) | Implemented | `nat.go`, `nat_state.go`, `nat_ri.go` |
| Introducers | Implemented | `introducer_dial.go`, `ExtractIntroducers` |
| Hole punching | Implemented | `nat_outofsession.go`, `nat_outofsession_inbound.go` |
| Relay requests / responses / intros | Implemented | block handling in `framing.go` |
| Path challenge / new token | Implemented | block handling in `framing.go` |
| Out-of-session DateTime skew validation | Implemented | `nat_outofsession_inbound.go` (±2 min, `ssu2.rst:4036-4039`) |

323 tests exercise this package, including `spec_compliance_test.go`, which
validates all 19 block types against the live specification.

## What is NOT proven

This is the substance of the experimental label.

### 1. No live-network interoperability evidence

`docs/interop-matrix.md` records the evidence produced by the daily
live-network suite (`TestLiveNetwork*` against real Java I2P and i2pd peers).
The paths it asserts are bootstrap/peer overlap, RouterInfo publication and
LeaseSet publication/retrieval. **None of them asserts anything SSU2-specific.**
The only SSU2 reference in `lib/router/live_network_integration_test.go` is a
diagnostic log of `ssu2.ExtractIntroducers(addr)`.

So: SSU2 is proven against **itself** (loopback and harness peers built from
this same code plus `go-noise`), and against the specification text, but not
against a Java or i2pd peer on the real network. NTCP2 is proven against both.
A transport that has never completed a handshake with a different
implementation is exactly what "experimental" is meant to signal.

The gap is partly environmental: outbound SSU2 needs UDP reachability, and the
live suite runs in a NAT'd sandbox where the router's own RouterAddress is
published as capabilities-only (see the publish-RouterInfo row of
`docs/interop-matrix.md`). Demonstrating inbound SSU2 requires a deployment with
a routable address.

### 2. Initiator-side replay cache is not enforced

`ssu2.rst:1576-1581` requires the initiator ("Alice") to "maintain a local
cache of previously-used handshake values and reject duplicates", with entries
living at least 2\*D. `go-noise` creates that cache only for responders
(`ssu2/handshake/handshake_handler.go`: `if !initiator { handler.replayCache = … }`),
so a dialing router has no duplicate-handshake cache.

`lib/transport/ssu2/transport.go` adds a transport-level check
(`checkConnectionReplay` → `checkReplayToken` → `handler.CheckReplay`) that does
maintain a cache, but it runs on **inbound** connections only, so it covers the
responder case that go-noise already handles and not the initiator case the spec
also requires. The token system limits the impact of a replayed Session Request
(`ssu2.rst:4050-4056` — "a replayed Session Request message will never have a
valid token"), which is why this is a gap rather than a critical hole.

### 3. Peer tests and introducers are individually flagged experimental

The README marks both sub-items experimental: peer tests have all roles
implemented with end-to-end integration ongoing, and introducer registration and
republish are wired but not proven against live introducers.

### 4. Deferred replay checks are observable but not resolvable here

When `GetReplayToken()` returns nil, the transport counts the event
(`metrics.go` → `ReplayChecksDeferred`) and proceeds. The counter is the thing
to watch on a real deployment: a large deferred count means the replay check is
being skipped in practice, not merely in theory.

Before the inbound-handshake fix this counter was guaranteed to rise on every
inbound connection, because replay material is only populated during
`Handshake()` and the transport never called it — the check could not have real
input. Now that `Accept()` delivers established connections, a non-zero
`ReplayChecksDeferred` means what it was always meant to mean.

### 5. Data-phase key derivation is now per-session, but has no live-traffic evidence

Until 2026-11-01 the `go-i2p/noise` fork zeroed the CipherState key arrays
inside `Split`/`SplitWithASK`, because `hkdf` appends into the slices it is
given and `Split` passed it `s1.k[:0]`/`s2.k[:0]` directly. `go-noise` derives
the SSU2 data-phase keys from that stored key
(`ssu2/handshake/kdf.go` → `cs.UnsafeKey()`), so every session used
`HKDF(0^32, ZEROLEN, "HKDFSSU2DataKeys", 64)` — a value any observer can
compute. The data phase between two go-i2p routers was publicly decryptable and
forgeable, and no other implementation could read go-i2p's data phase at all.
The AEAD objects hold a by-value copy of the key, so encryption round-trips
passed throughout and the defect was silent.

The fork now writes the HKDF outputs to independent buffers before copying them
into the key arrays, and zeroes those buffers. `go-noise` needed no derivation
change: it already matched `ssu2.rst` §"KDF for data phase", and this was
confirmed against the reference implementation rather than by self-consistency —
`TestSSU2_DataPhaseKeys_JavaInterop_KAT` in `go-noise/ssu2/handshake` asserts
`k_data` and `k_header_2` equal the values Java I2P 2.12.0
(`net.i2p.crypto.HKDF`, the call shape `SSU2Util.hkdf` uses) produces for the
same split key. Because the derivation was already correct, rekeying
(`ssu2/session/conn_data.go` → `deriveRekeyKey`) was affected by the same zeroed
input and is fixed by the same change.

What is still not proven is the consequence of the fix on real traffic. All
prior wire evidence — including the decrypted-frame counts recorded while the
defect was being confirmed — was measured against the buggy build, so it says
nothing about interoperability now. Two things follow:

- Live SSU2 interop with Java I2P and i2pd (checklist items 1 and 2) has never
  been demonstrated end to end, and is now the first opportunity to do so.
- Sessions recorded before this fix remain decryptable by anyone holding the
  capture. No long-term secret is exposed, so no key rotation is warranted, but
  past captures must be treated as public.

## Inbound accept path

No inbound SSU2 session had ever completed until the 005 fix — not from a foreign
peer, and not between two go-i2p routers over loopback either. Two independent
defects combined to make every inbound session impossible:

1. **No responder handshake.** `go-noise`'s `SSU2Listener.Accept()` returns a
   connection in `StateInit` holding only a parsed SessionRequest; the XK responder
   half runs only when the caller invokes `Handshake()`. Nothing in
   `lib/transport/ssu2` ever called it. `SSU2Transport.Accept()` now runs a
   background accept loop that admits each connection against a pre-authentication
   budget, completes the handshake in its own worker goroutine with a timeout, runs
   the duplicate and anti-replay checks on the established connection, and delivers
   only established sessions to `Accept()`.
2. **The router's type assertion always failed.** The transport and the muxer each
   wrap the connection in a `transport.TrackedConn`, so the value reaching
   `handleNewConnection` is wrapped twice and `conn.(*ssu2noise.SSU2Conn)` never
   matched. The router now unwraps via `transport.UnwrapTrackedConn` first.

The stall that made this an availability problem is fixed too. On a failed
assertion the router used to call `conn.Close()` inline on the single
`monitorInboundSessions` goroutine, which also serves NTCP2 accepts; `go-noise`'s
`Close` waits the spec's 11 s `DestroyTimeout`, so one unauthenticated — and
possibly spoofed — SessionRequest blocked every inbound transport for 11 s.
Rejections now close asynchronously, and connections abandoned before they were
established are torn down with `CloseImmediate`.

A third defect, found while testing the fix, was that `NewSSU2Transport` created
the listener *before* `initKeyManagement` loaded the intro key onto the shared
config. The listener builds its inbound header protector from `IntroKey` inside
`NewSSU2Listener`, and a SessionRequest's header is obfuscated with the receiver's
intro key — so the protector was nil at construction and no inbound SessionRequest
could be deobfuscated. Key management now runs before the listener is created.

## Outbound sessions: a handshake the peer never completed

Finding 012. An SSU2 dial that reached SessionConfirmed was treated as an
established session the moment SessionConfirmed was written, without waiting for
any acknowledgement from the peer. A responder that accepted the SessionRequest,
answered SessionCreated, and then rejected or ignored the SessionConfirmed (a
stale RouterInfo — see finding 010's H-161 — or a crash) left the initiator
holding a session that reported itself live. Three independent mechanisms made
that state permanent, all in `go-noise/ssu2/session`:

1. **No completion condition.** `finalizeHandshake` returned after writing
   SessionConfirmed. `ssu2.md` §"Handshake Retransmission" -> §"Session
   Confirmed" makes the peer's first data message the event that ends Session
   Confirmed retransmission, so the spec expects an endpoint to know whether that
   event happened; nothing here did.
2. **An unreachable retry cap.** `retransmitExpired` resends unacknowledged
   contents under a fresh packet number, as §"Packet Numbering" requires, and
   then re-tracked the new packet with `Retries: 0`. The packet number changed,
   so the count restarted, so `maxPacketRetries` was never reached and one
   message was resent 1157 times in seven and a half minutes on the lab testnet.
3. **A timer that could not fire.** Every resend refreshed `lastActivity`, which
   is what the idle check measures.

The fix is in `go-noise/ssu2/session/conn_data_phase.go` plus the two send-path
changes in `conn_write.go`:

- The initiator now arms a deadline for the peer's first authenticated
  data-phase packet and closes the session with
  `TerminationSessionConfirmedError` when it passes. The default is 13 s —
  §"Total Timeout"'s 12.5 s plus the final 5 s SessionConfirmed interval — so a
  handshake the spec still considers in progress is never cut short. Tunable via
  `SSU2Config.DataPhaseTimeout`; negative disables it.
- The retry count belongs to the contents and now rides with them across
  resends, so the cap is reachable and unacknowledged data is abandoned.
- A retransmission no longer refreshes the idle timer.
- A data-phase datagram that arrives while the initiator is still handshaking is
  retained and replayed once `finalizeHandshake` installs the data-phase keys,
  instead of being dropped.
- The data-phase header protector reaches the listener's session registry
  synchronously, inside the handshake goroutine that derives the key.

The first three act on the connection itself, so they apply to every dial path,
including the shared listener socket this router dials through. The last two are
what make the race survivable on a shared socket.

Retention needs care on the listener path, because a listener-multiplexed
session never runs the connection's own read loop — one goroutine owns the
shared socket and it belongs to the listener — so the connection-side buffer
would simply never be fed. Two changes cover it. The protector install used to
be a non-blocking send into a channel that only exists once the listener has
wired it and that a background goroutine drains; if the handshake derived the
key first the send hit its default branch and the protector was never installed
at all, leaving the session permanently deaf with no error anywhere. It is now a
synchronous hook, so there is no handoff to lose. That removes the large window
but not the last few instructions of it, and for that residue the listener's
demux cascade ends with an attribution stage: header protection masks bytes 0-7
with `k_header_1`, which for an inbound Data packet is the listener's own
introduction key, so the destination connection ID can be recovered even though
the packet cannot be read. The raw datagram is then handed to that session's
bounded retention buffer and replayed by `finalizeHandshake`.

`SSU2Conn.RecvStats()["handshake_retained"]` counts what that buffer held. A
non-zero value means the peer answered Session Confirmed immediately, which is
normal and spec-directed; a value pinned at the buffer bound means the session
was repeatedly losing packets it could not recover.

Holding a packet that arrives mid-handshake is only safe if the handshake is not
itself waiting for that packet — the buffer is drained inside `finalizeHandshake`,
so a held handshake message would be a self-inflicted hang. Retention therefore
requires a completed handshake, which means every message the connection could
still be waiting for has already arrived; a responder additionally has to have
been offered its own Session Confirmed stage. Both conditions are asserted by
tests in `ssu2/server/retain_fallback_test.go` and
`ssu2/session/retain_listener_test.go`.

Residual risk of the deadline, stated plainly: a peer that completes the
handshake and then genuinely sends nothing for 13 s has its session closed, and
the router redials. Every conformant implementation sends something inside that
window — §"Packet Numbering" tells the responder its first Data packet "should
be an ACK of the Session Confirmed", and §"Total Timeout" gives the handshake as
a whole 12.5 s — so this is a peer outside the spec's own envelope. If a live
peer turns out to be slow rather than dead, `DataPhaseTimeout` raises the bound
or disables it.

`SSU2Conn.PeerDataReceived()` exposes the bilateral condition to the router. In
`lib/transport/ssu2`, `HasSession` no longer reports a session whose context is
cancelled (matching NTCP2), a message that exhausts its retransmissions into a
peer that has never sent us a data packet now closes the session instead of
being dropped quietly, and a fatal read error closes the session rather than
leaving the registry entry behind.

Two things deliberately left alone:

- **A session with a continuous stream of fresh sends still refreshes its own
  idle clock.** What defeated the 5-minute idle timeout in the lab (a 104-minute
  session that never expired) was retransmission: `sendPacketDirect` counted every
  resend as activity, so a stuck session kept restarting the timer and, separately,
  each resend reset the retry counter so the cap was never reached. Both are fixed,
  and the idle timeout now does fire — `ssu2/session/data_phase_deadline_test.go`
  proves it on a dead peer and on a session with resends queued. The keepalive was
  never part of the problem: with nothing received to acknowledge,
  `ACKHandler.GenerateACK` returns nil and `sendImmediateACK` sends nothing, so an
  idle session's keepalive does not refresh `lastActivity` either.
  What remains is the case where the application keeps handing the session genuinely
  new data: those sends are activity, so the idle timeout is not the recovery path
  there. It is the retry cap and the data-phase deadline that end such a session, and
  making the idle clock measure inbound activity instead would require turning the
  keepalive into an ack-eliciting probe — otherwise every quiet-but-live session gets
  reaped. That is a wider behavioural change than this finding.
- **Inbound sessions are never judged by peer silence.** A responder's peer has
  already proved itself by completing the handshake and may simply not have sent
  data yet; `peerSilent()` is scoped to `IsInitiator()` so healthy inbound
  sessions are not closed on a race.

### Operator-visible consequences

- The transport now passes its session cap down to the go-noise listener (whose
  built-in 65536 was never bounded by the router's 512-slot pool), and exposes
  `ssu2_max_inflight_handshakes` / `ssu2_max_handshakes_per_source` to cap
  pre-authentication work. See `config.yaml.example`.
- **`ssu2_require_retry` must stay off.** Source-address validation is the right
  hardening in principle, but the go-noise version pinned here routes a tokenless
  SessionRequest through its Token-Request path and AEAD-opens the payload with the
  intro key. A SessionRequest payload is Noise-encrypted, not intro-key-sealed, so
  the check always fails and the request is dropped — every inbound SessionRequest,
  valid peers included. Enabling it is a total inbound SSU2 outage. The knob is
  plumbed so it can be turned on once that upstream path is fixed; the transport's
  own handshake budget is what bounds a spoofed flood today.

## Production-readiness checklist

The experimental designation can be removed when all of these hold:

- [ ] **Live interop, outbound**: `TestLiveNetwork*` establishes at least one
      SSU2 session to a Java peer and one to an i2pd peer, asserted by transport
      type rather than inferred from a successful netdb operation.
- [ ] **Live interop, inbound**: a peer on the public network dials this
      router's SSU2 address and completes a handshake, with a routable
      (non-caps-only) published RouterAddress. The mechanism is now proven in-repo
      (`lib/transport/ssu2/inbound_handshake_test.go`
      `TestAcceptDeliversEstablishedConnection` dials a real bound transport and
      gets an established session back from `Accept()`); what remains is a real
      foreign implementation.
- [ ] **Interop matrix updated**: `docs/interop-matrix.md` gains an SSU2 row
      with the same pass criteria as the NTCP2 paths.
- [ ] **Data-phase interop**: I2NP actually flows over an SSU2 session with a
      Java or i2pd peer, in both directions. This is a separate gate from the
      handshake completing: before the key-derivation fix in section 5, a peer
      could finish SessionConfirmed and still never read a single data packet.
- [ ] **Initiator replay cache**: either enforced upstream in `go-noise` for
      `initiator == true`, or enforced in this transport on the dial path.
- [ ] **Peer tests**: end-to-end NAT detection against a real Java/i2pd peer,
      producing a correct external-address verdict.
- [ ] **Introducers**: a real relay through a live introducer to a firewalled
      peer.
- [ ] **Soak**: sustained traffic over SSU2 sessions with no AEAD-failure
      terminations and a bounded `ReplayChecksDeferred` count.

Until then, routers that must interoperate with the widest set of peers should
keep NTCP2 enabled; SSU2 adds reachability where UDP works and is safe to run
alongside it, but its real-network behaviour is unverified.
