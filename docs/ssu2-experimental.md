# SSU2: what "experimental" means

Updated: 2026-11-01

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

## Production-readiness checklist

The experimental designation can be removed when all of these hold:

- [ ] **Live interop, outbound**: `TestLiveNetwork*` establishes at least one
      SSU2 session to a Java peer and one to an i2pd peer, asserted by transport
      type rather than inferred from a successful netdb operation.
- [ ] **Live interop, inbound**: a peer on the public network dials this
      router's SSU2 address and completes a handshake, with a routable
      (non-caps-only) published RouterAddress.
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
