# ORGANIZATION AUDIT — 2026-05-16

Scope: Code-organization and architecture audit of `github.com/go-i2p/go-i2p` —
library-forward design, entrypoint thinness, interface-driven boundaries, and
separation of concerns. Source tree was not modified.

## Architecture Summary

- **Module**: `github.com/go-i2p/go-i2p` (Go 1.24 per `go.mod`).
- **Stated intent** (per [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md)):
  pure-Go I2P router; common data types, crypto, and Noise live in sibling
  modules (`go-i2p/common`, `go-i2p/crypto`, `go-i2p/go-noise`); this repo holds
  the router + protocol implementations and a CLI entrypoint. The README
  describes an embeddable router and explicitly markets `lib/embedded` as the
  programmatic entry point. CONTRIBUTING.md sets concrete code-quality limits
  (functions ≤ ~35 lines, cyclomatic complexity ≤ ~10, nesting < 3).
- **Entrypoints**:
  - Root `main` package: [main.go](main.go) (~80 lines, package `main`, 3 funcs).
    Wires cobra, signal handler, config, and calls `embedded.NewStandardEmbeddedRouter`
    then `router.Run(ctx)`. No business logic.
  - Sub-commands: [lib/config/cmd/configcmd.go](lib/config/cmd/configcmd.go)
    (`package configcmd`) and [lib/tui/cmd/tuicmd.go](lib/tui/cmd/tuicmd.go)
    (`package tuicmd`). Both are cobra command factories invoked from `main()`.
- **Library packages** (27 packages, 274 non-test files, ~36.8 KLOC):
  - Domain / protocol: `lib/i2np`, `lib/i2cp`, `lib/i2pcontrol`, `lib/tunnel`,
    `lib/netdb`, `lib/transport`, `lib/transport/ntcp2`, `lib/transport/ssu2`,
    `lib/keys`, `lib/naming`, `lib/bootstrap`.
  - Orchestration: `lib/router` (composes transports, netdb, i2np, i2cp, tunnels),
    `lib/embedded` (lifecycle wrapper over `router.Lifecycle`).
  - Configuration: `lib/config`, `lib/config/cliflags`, `lib/config/cmd`.
  - Utilities: `lib/util`, `lib/util/signals`, `lib/util/time/{monotonic,skew,sntp}`,
    `lib/testutil`, `lib/tui`, `lib/tui/cmd`.
- **Dependency flow**: `main` → `embedded` → `router` → (`netdb` | `i2cp` |
  `i2np` | `tunnel` | `transport/{ntcp2,ssu2}` | `keys`) → common/utility
  packages. `go-stats-generator` reports **no circular dependencies**.
- **Interface surface**: 107 exported/private interface declarations across
  the library packages (notably in `lib/i2np/processor.go`,
  `lib/i2np/database_manager.go`, `lib/router/lifecycle_interface.go`,
  `lib/embedded/embedded.go`, `lib/transport/`). Interface-driven boundaries
  are the dominant style for cross-package coupling.
- **Baseline**: `go build ./...` is clean; `go test -race ./...` passes across
  all packages (≈100 s wall time). Average function length 12.7 lines; longest
  function 76 lines; max overall complexity 10.6 — generally consistent with
  CONTRIBUTING.md guidance.

## Organization Scorecard

| Category | Rating | Evidence |
|----------|--------|----------|
| Library-Forward Design | ✅ | `main` is ~80 lines, defers entire lifecycle to `embedded.NewStandardEmbeddedRouter` ([main.go:44-69](main.go#L44-L69)); the README documents `lib/embedded` as the embedding API. |
| Entrypoint Thinness | ✅ | Root `main` and both subcommands only parse flags, construct dependencies, and call library APIs (e.g. [lib/config/cmd/configcmd.go](lib/config/cmd/configcmd.go), [lib/tui/cmd/tuicmd.go](lib/tui/cmd/tuicmd.go)). No domain logic in entrypoints. |
| Struct/Interface Boundaries | ⚠️ | 107 interfaces are used at most cross-package seams (e.g. [lib/i2np/processor.go](lib/i2np/processor.go), [lib/router/lifecycle_interface.go](lib/router/lifecycle_interface.go)), but the same domain concept `BuildRequestRecord` is duplicated as a concrete struct in two packages ([lib/i2np/build_request_record.go#L160](lib/i2np/build_request_record.go#L160) and [lib/tunnel/builder.go#L70](lib/tunnel/builder.go#L70)) "to avoid import cycles", which the comment itself flags as a deliberate workaround. |
| Separation of Concerns | ⚠️ | Directory layout is clear (domain/transport/config/util) and packages are well-named, but `lib/router/router.go` (857 lines, 42 funcs) mixes router struct, transport bootstrapping, address publication, and status accessors, and contains an unrelated `routerBandwidthProvider` adapter ([lib/router/router.go:843](lib/router/router.go#L843)) that belongs next to the bandwidth code in [lib/router/bandwidth.go](lib/router/bandwidth.go). |
| Extensibility | ✅ | Embedding contract `embedded.EmbeddedRouter` plus router-level `Lifecycle`/dispatcher interfaces let alternative wiring (tests, embedders, alternate UIs) substitute components. The two cobra subcommands (`configcmd`, `tuicmd`) compose cleanly into `RootCmd` and share library services. |

## Findings

Every finding below references a specific file (and, where relevant, a line)
and proposes a concrete restructuring. False-positive prevention checks from
the workflow were applied before inclusion (see "False Positives Considered
and Rejected" below).

### CRITICAL

_None._ The entrypoint is genuinely thin, domain logic lives in library
packages, and there are no circular dependencies or architectural choices that
fundamentally block extension.

### HIGH

- [x] Duplicated `BuildRequestRecord` type across two packages —
  [lib/i2np/build_request_record.go:160](lib/i2np/build_request_record.go#L160)
  and [lib/tunnel/builder.go:70](lib/tunnel/builder.go#L70) — the comment on
  the tunnel-side declaration says "defined here to avoid import cycles". Two
  concrete types representing the same domain concept force conversion logic,
  invite drift in field semantics, and undermine the package-boundary
  ownership model (`i2np` should own its on-wire records). **Impact:**
  long-term divergence risk; consumers must know which `BuildRequestRecord`
  they hold; substitution at the boundary is impossible without conversion
  helpers. **Remediation:**
  1. Extract a small, dependency-free record type (e.g. `BuildRequestRecord`
     and its accessors) into a new leaf package such as `lib/i2np/buildrecord`
     (or `lib/common/buildrecord`) that depends on `common/*` only.
  2. Have both `lib/i2np` and `lib/tunnel` import the leaf package and delete
     the second definition in [lib/tunnel/builder.go](lib/tunnel/builder.go).
  3. Validation: `go build ./...`, `go test -race ./...`,
     `go-stats-generator analyze . --sections packages,structs` (expect the
     duplicate struct entry to disappear and `lib/tunnel`'s dependency on
     `lib/i2np` to remain absent).

- [x] `lib/router/router.go` (857 lines, 42 functions) concentrates four
  distinct concerns: the `Router` aggregate struct ([lib/router/router.go:32](lib/router/router.go#L32)),
  router-wide initialization (`CreateRouter`, `initializeRouterComponents`,
  `initializeNetDBAndTransports`), transport-specific construction
  (`buildNTCP2Transport`, `createNTCP2TransportInstance`,
  `publishNTCP2Address`, `buildSSU2Transport`, `createSSU2TransportInstance`,
  `publishSSU2Address`, `recomputeReachabilityCaps`,
  `validateAndAddTransportAddress`, `addTransportAddress`,
  `resolveTransportPort`), and runtime status accessors
  (`GetBandwidthRates*`, `GetActiveSessionCount`, `GetNTCP2SessionCount`,
  `GetSSU2SessionCount`, `GetTransportAddr`, `GetSSU2Addr`,
  `GetNetworkStatus`). **Impact:** newcomers cannot locate where transports
  are wired vs. where the aggregate is defined; bandwidth/status logic
  duplicates work that already lives in [lib/router/bandwidth.go](lib/router/bandwidth.go);
  the file approaches a "god module" pattern even though sibling files
  (`router_lifecycle.go`, `router_mainloop.go`, `router_shutdown.go`, etc.)
  already exist to receive these responsibilities. **Remediation:**
  1. Move all NTCP2 helpers to [lib/router/router_ntcp2.go](lib/router/router_ntcp2.go)
     (new) and SSU2 helpers to the existing [lib/router/router_ssu2.go](lib/router/router_ssu2.go).
  2. Move the runtime status accessors (`GetBandwidthRates*`,
     `GetActiveSessionCount`, `GetNTCP2SessionCount`, `GetSSU2SessionCount`,
     `GetTransportAddr`, `GetSSU2Addr`, `GetNetworkStatus`,
     `getTotalBandwidth`) into [lib/router/bandwidth.go](lib/router/bandwidth.go)
     or a new `lib/router/router_status.go`.
  3. Keep only the `Router` struct, `CreateRouter`, `FromConfig`, and the
     orchestration helpers in `router.go`.
  4. Validation: `go build ./...`, `go test -race ./lib/router/...`,
     `go-stats-generator analyze . --sections packages,functions` (expect
     `router.go` line count to drop and per-file cohesion in `lib/router` to
     improve).

### MEDIUM

- [x] `routerBandwidthProvider` is defined inside
  [lib/router/router.go:843](lib/router/router.go#L843) but is an I2CP
  bandwidth-adapter whose only responsibility is exposing
  `cfg.MaxBandwidth` to the I2CP server. The adjacent
  [lib/router/bandwidth.go](lib/router/bandwidth.go) already groups bandwidth
  types and methods. **Impact:** related bandwidth logic is split across two
  files; the stats tool's misplaced-method report flags this kind of
  cross-file scatter as one of the recurring patterns. **Remediation:**
  1. Move the `routerBandwidthProvider` struct, its `GetBandwidthLimits`
     method, and any helper code into [lib/router/bandwidth.go](lib/router/bandwidth.go).
  2. Validation: `go build ./...`, `go test -race ./lib/router/...`.

### LOW

- [x] File-name stuttering in [lib/embedded/](lib/embedded) —
  `embedded_configure.go`, `embedded_constructors.go`, `embedded_shutdown.go`,
  `embedded_state.go`. Inside the package, the `embedded_` prefix is
  redundant. **Impact:** minor; degrades scannability of directory listings.
  **Remediation:** rename to `configure.go`, `constructors.go`, `shutdown.go`,
  `state.go` (matching the suggestions emitted by the stats analyzer). The
  same pattern exists in [lib/i2np/i2np.go](lib/i2np/i2np.go),
  [lib/bootstrap/bootstrap.go](lib/bootstrap/bootstrap.go), and
  [lib/config/config.go](lib/config/config.go) — `bootstrap.go` and
  `config.go` are conventional for the canonical type-file, so prefer leaving
  those alone unless the project decides to standardize on shorter primary
  filenames. Validation: `go build ./...`, `go test -race ./...`.

## False Positives Considered and Rejected

| Candidate Finding | Reason Rejected |
|-------------------|-----------------|
| "Business logic in `main`" | [main.go](main.go) only wires cobra, the signal handler, and `embedded.NewStandardEmbeddedRouter` → `router.Run(ctx)`. There is no algorithmic or protocol logic; the README explicitly designates `lib/embedded` as the embedding entry point. |
| "Packages have 0 interfaces (per stats summary)" | The `=== PACKAGE ANALYSIS ===` table prints 0 interfaces per package, but a direct grep finds 107 `type … interface` declarations across `lib/`. The summary number is a stats-tool quirk, not a real boundary problem. |
| "High coupling in `lib/router` (25 deps)" | `lib/router` is the orchestration aggregate that composes every transport, netdb, i2np, i2cp, tunnel, and keys package. High fan-out is intrinsic to its role and consistent with the README's "core router" framing. No circular dependencies are present. |
| "Large packages (`i2np` 582 funcs, `netdb` 441 funcs)" | I2NP and NetDB are large I2P specifications; splitting them artificially would invite circular dependencies between message types that already cross-reference. The packages are partitioned across many topic-named files (`tunnel_build.go`, `database_*.go`, `garlic_*.go`, etc.), keeping per-file size manageable. |
| "Avg dependencies/package = 7.9 is high" | This is dominated by the orchestration tier (`router`, `embedded`, `i2cp`, `i2np`, `netdb`). Leaf packages (`monotonic`, `skew`, `signals`, `util/*`, `config/cliflags`) have small fan-out, matching the intended layered design. |
| "Method placement: `BuildRequestRecord.Bytes` etc. mis-located" | The placement report compares the receiver-file (`lib/i2np/build_request_record.go`) to the duplicate-type file (`lib/tunnel/builder.go`). This is a symptom of the HIGH duplicated-type finding; once the type is unified, the method-placement warnings clear automatically — no separate remediation needed. |
| "Code-clone pairs (24 / 526 lines / 0.71%)" | Duplication ratio of 0.71% is well below typical thresholds and the clones are short (6–29 lines) shutdown/wiring stanzas in `lib/router/router_*.go`. Extracting helpers would harm readability of the shutdown sequence. Not an organization issue. |
| "Stuttered file names `lib/bootstrap/bootstrap.go`, `lib/config/config.go`" | Idiomatic Go uses a file matching the package name to hold canonical types/constructors. The stuttering warning is a false positive for these specific files. |
| "`lib/i2cp/session.go` (1343 lines) and `lib/i2cp/server_dispatch.go` (1413 lines) are too large" | They are partitioned by feature (session lifecycle vs. dispatch table) and the per-function complexity stays inside CONTRIBUTING.md limits (max 9.3). Size alone is not an organization defect when the boundaries are coherent. |
| "`lib/util` should be deleted entirely" | Its four utilities (`checkfile`, `closeables`, `home`, `panicf`) are real reusable helpers, just genericly grouped. Split rather than delete — recorded under LOW. |
# ORGANIZATION AUDIT — 2026-05-16

Scope: Repository at module `github.com/go-i2p/go-i2p` (Go 1.26.1). Audit
covers package layout, entrypoint thinness, interface boundaries, separation
of concerns, and extensibility. Tests pass (`go build ./...` clean; race tests
run in [tmp/organize-test-results.txt](tmp/organize-test-results.txt) — not
persisted).

Evidence sources:
- `go-stats-generator analyze .` (JSON metrics, see Phase 2 commands)
- 27 packages, 269 non-test files, 36,857 LOC, 1,130 functions, 2,260 methods,
  278 structs, **98 interfaces**, 0 circular dependencies.
- README claims a library-forward design where reusable logic lives under
  `lib/` and the binary is a thin shell.

## Architecture Summary

- **Entrypoints**
  - [main.go](main.go) — 79 lines. Wires Cobra root command, registers
    subcommands [lib/config/cmd/configcmd.go](lib/config/cmd/configcmd.go) and
    [lib/tui/cmd/tuicmd.go](lib/tui/cmd/tuicmd.go), then calls
    `embedded.NewStandardEmbeddedRouter(...)` and `router.Run(ctx)`. No
    business logic. ✅
  - `configcmd` (76 LOC, 3 funcs) and `tuicmd` (61 LOC, 2 funcs) are also
    thin and delegate to library packages.
- **Library packages (under `lib/`)** — 25 packages own all feature logic.
  Ordered by LOC: `i2np` 12,754; `netdb` 8,946; `i2cp` 8,213; `tunnel` 8,104;
  `router` 7,134; `ssu2` 4,943; `ntcp2` 4,866; `i2pcontrol` 4,001;
  `config` 3,317; `bootstrap` 2,853; `keys` 1,836; remainder small utilities.
- **Embedding façade** — [lib/embedded/embedded.go](lib/embedded/embedded.go)
  defines `EmbeddedRouter` (9-method interface) and depends on
  `router.Lifecycle` (7-method interface in
  [lib/router/lifecycle_interface.go](lib/router/lifecycle_interface.go))
  rather than the concrete `*router.Router`. Test-injection constructor
  `NewStandardEmbeddedRouterWith(r router.Lifecycle, ...)` exists. ✅
- **Dependency flow** — `main → embedded → router → {i2np, tunnel, netdb,
  transport/{ntcp2,ssu2}, i2cp, i2pcontrol, keys, bootstrap, config}`.
  Auxiliary trees: `i2pcontrol → {config, i2np, netdb, tunnel}`,
  `i2np ↔ tunnel` (i2np imports tunnel; tunnel does not import i2np).
- **Internal packages** — None. The project relies on package-name boundaries
  rather than `internal/` to scope visibility.
- **Interface coverage** — 98 exported interfaces across 17 packages;
  `i2np` alone defines 39 (notably `MessageSerializer`, `DatabaseReader`,
  `TunnelOrchestrator`), `tunnel` 9 (peer selection, filtering), `transport`
  5 (Transport, TransportSession, PeerConnNotifier, etc.), `i2pcontrol` 7
  (RouterAccess and sub-readers). Interface-driven seams are pervasive.

## Organization Scorecard

| Category | Rating | Evidence |
|----------|--------|----------|
| Library-Forward Design | ✅ | `main.go` 79 LOC, zero business logic; all router lifecycle in `lib/embedded` + `lib/router`. README explicitly markets `lib/embedded` as the API surface. |
| Entrypoint Thinness | ✅ | `main` + `configcmd` + `tuicmd` total ~210 LOC, 8 functions. Subcommands instantiate Cobra and delegate to library APIs. |
| Struct/Interface Boundaries | ⚠️ | 98 interfaces with active use (`Lifecycle`, `TunnelOrchestrator`, `Transport`, `KeyStore`, etc.), but a few public interfaces leak concrete pointer types (see Finding H1). |
| Separation of Concerns | ⚠️ | Clean cmd↔lib split, no circular deps, but tunnel building/coordination lives in `lib/i2np` (1,970-line `tunnel_manager.go`) instead of `lib/tunnel`, contradicting `lib/i2np/doc.go` and `lib/tunnel/doc.go`. |
| Extensibility | ✅ | New transports, peer selectors, RPC handlers, and bootstrap sources can be added behind existing interfaces without touching the binary. Embedded façade allows third-party processes to host the router. |

`go-stats-generator` organization-health summary: 0 circular dependencies,
0 high-fan-in/-out packages, 0 deep directories, duplication ratio 0.71 %
(526 duplicated lines across 24 clone pairs, largest 29 lines in
`lib/config/cliflags/cliflags.go`).

## Findings

### CRITICAL

_None._ Core feature logic is not located in `main`/entrypoints, and the
public API of `lib/embedded` is interface-mediated, so embedders are not
forced into invasive rewrites to extend the router.

### HIGH

- [x] **H1 — `RouterInfoReader` returns concrete pointers, defeating the
  abstraction it advertises** —
  [lib/i2pcontrol/access_interfaces.go:17](lib/i2pcontrol/access_interfaces.go#L17)
  and [lib/i2pcontrol/access_interfaces.go:23](lib/i2pcontrol/access_interfaces.go#L23).
  `GetNetDB() *netdb.StdNetDB` and `GetParticipantManager() *tunnel.Manager`
  expose full concrete structs (74 + 28 methods respectively). The lone
  consumer, `routerStatsProvider` in
  [lib/i2pcontrol/stats.go:344](lib/i2pcontrol/stats.go#L344) /
  [:358](lib/i2pcontrol/stats.go#L358) /
  [:420](lib/i2pcontrol/stats.go#L420), uses only 4 NetDB read methods
  (`GetRouterInfoCount`, `GetActivePeerCount`, `GetFastPeerCount`,
  `GetHighCapacityPeerCount`) and 1 participant-manager method
  (`ParticipantCount`). Test mocks must therefore stand up — or wrap — full
  netdb/tunnel implementations even though only counts are needed. **Impact:**
  blocks substitution and tightens the I2PControl→netdb/tunnel coupling that
  the doc comment ("Decouples I2PControl from router internals") promises to
  avoid. **Remediation:** add two minimal read-only interfaces in
  `lib/i2pcontrol/access_interfaces.go` (`NetDBStatsReader { GetRouterInfoCount(); GetActivePeerCount(); GetFastPeerCount(); GetHighCapacityPeerCount() }`
  and `ParticipantStatsReader { ParticipantCount() int }`); change
  `RouterInfoReader.GetNetDB` / `GetParticipantManager` to return these
  interfaces; keep the concrete getters on `*router.Router` (which already
  satisfy them by structural typing). Validate with `go build ./...`,
  `go test -race ./lib/i2pcontrol/...`, and re-run
  `go-stats-generator analyze . --sections interfaces`.

### MEDIUM

- [ ] **M1 — Tunnel building/coordination is implemented in `lib/i2np`
  rather than `lib/tunnel`** —
  
  **STATUS (2026-05-17):** Phases 1-3 complete ✅. Phase 4.1 complete ✅
  (refactored TunnelManager to use messageFactory and buildSessionProv,
  git commit 533e35e5a). Phases 4.2-4.6 BLOCKED ⚠️ — attempting to move
  TunnelManager files to lib/tunnel/build creates a circular dependency:
  
  - lib/tunnel/build/manager_core.go needs to import lib/i2np for
    `SessionProvider`, `ReplyProcessor`, and `buildEventWindow` types
  - lib/i2np/build_message_factory.go imports lib/tunnel/build for
    `BuildMessageFactory` and `BuildSessionProvider` interfaces
  - Result: lib/tunnel/build → lib/i2np → lib/tunnel/build (cycle)
  
  **Root cause:** TunnelManager is tightly coupled to I2NP-specific types
  that cannot be abstracted without significant design changes. The
  buildMessageFactory and buildSessionProvider adapters themselves depend
  on lib/i2np types (I2NPTransportSession, BaseI2NPMessage) and cannot
  move to lib/tunnel/build.
  
  **Resolution options:**
  1. Move ReplyProcessor and buildEventWindow to lib/tunnel/build as
     interfaces (major refactoring of reply handling)
  2. Create lib/i2np/adapter package that imports both lib/i2np and
     lib/tunnel/build for the adapter implementations
  3. Keep TunnelManager in lib/i2np and accept the current architecture
     (Phase 4.1 improvements still provide better separation)
  
  Recommendation: Option 3 for now. Phase 4.1 successfully decoupled
  message creation logic through the BuildMessageFactory interface,
  reducing direct I2NP Message dependencies by ~200 lines. Further
  extraction requires deeper architectural changes beyond M1 scope.
  
  [lib/i2np/tunnel_manager_core.go](lib/i2np/tunnel_manager_core.go)
  (`type TunnelManager struct`, 20 fields, 101 methods split across 5 files
  after M2) and
  [lib/i2np/tunnel_orchestrator.go:17](lib/i2np/tunnel_orchestrator.go#L17)
  (`TunnelOrchestrator` composed of `TunnelBuildCoordinator` +
  `TunnelStatsReader` after the MEDIUM split). The package’s own design
  doc, [lib/i2np/doc.go:57](lib/i2np/doc.go#L57), states *“See lib/tunnel for
  tunnel management and building”*, and
  [lib/tunnel/doc.go:5](lib/tunnel/doc.go#L5) advertises *“Tunnel building
  with encrypted build records / Tunnel pool management”*. The manager
  imports `lib/tunnel` and holds `*tunnel.Pool` fields. Meanwhile,
  `lib/tunnel/manager.go` is only the transit-**participant** manager. Two
  unrelated `Manager` types in adjacent packages confuse readers and
  reviewers. **Impact:** every change to tunnel-building logic forces edits
  in the message-format package; contributors must learn that `lib/tunnel` is
  *not* where tunnels are built; the `tunnel ← i2np` import direction
  prevents future extraction of `lib/i2np` as a pure wire-format library.

  **Why a naive move creates an import cycle:**
  `lib/i2np` → `lib/tunnel` (17 non-test files, for `tunnel.TunnelID`,
  `tunnel.Pool`, `tunnel.PeerSelector`, `tunnel.BuildTunnelRequest`, etc.).
  If `TunnelManager` moves into `lib/tunnel`, then `lib/tunnel` would need
  `GarlicKeyRegistrar`, `TunnelBuilder`, `TunnelReplyHandler`, and
  `SessionProvider` — all currently defined in `lib/i2np` —
  producing `lib/tunnel` → `lib/i2np` → `lib/tunnel`.

  **Cycle-break strategy — three-phase extraction:**

  > The root cause is that four coordinator interfaces live in `lib/i2np`
  > even though they have no dependency on i2np wire formats. Lowering
  > `BuildResponseRecord` into `lib/tunnel/buildrecord` (its sibling
  > `BuildRequestRecord` is already there) and hoisting the four interfaces
  > into a new `lib/tunnel/build` subpackage severs the cycle, after which
  > `TunnelManager` can be relocated without any circular import.

  **Phase 1 — Lower `BuildResponseRecord` into `lib/tunnel/buildrecord`**

  `BuildResponseRecord` (defined in
  [lib/i2np/build_response_record.go:56](lib/i2np/build_response_record.go#L56))
  uses only external packages (`common/data`, `crypto/types`). Its sibling
  `BuildRequestRecord` is already in `lib/tunnel/buildrecord`.

  - [x] 1.1 Move the `BuildResponseRecord` struct and its helpers from
        `lib/i2np/build_response_record.go` into a new file
        `lib/tunnel/buildrecord/build_response_record.go`; change
        `package i2np` to `package buildrecord`.
  - [x] 1.2 Replace the original definition in
        `lib/i2np/build_response_record.go` with a type alias:
        `type BuildResponseRecord = buildrecord.BuildResponseRecord`.
  - [x] 1.3 `go build ./...` — no compilation errors.
  - [x] 1.4 `go test -race ./lib/i2np/... ./lib/tunnel/...`

  **Phase 2 — Create `lib/tunnel/build` coordinator-interface package**

  All four coordinator interfaces used by `TunnelManager` are free of
  i2np wire-format types once Phase 1 is complete:
  `GarlicKeyRegistrar` uses only `[8]byte`/`[32]byte`; `TunnelBuilder`
  uses `buildrecord.BuildRequestRecord`; `TunnelReplyHandler` uses
  `buildrecord.BuildResponseRecord` (after Phase 1);
  `TunnelBuildReplyProcessor` uses `TunnelReplyHandler`. `SessionProvider`
  uses `I2NPTransportSession` which carries `i2np.Message` — decouple it
  by introducing a `BuildSession interface { Send([]byte) error }` so
  `lib/tunnel/build` never mentions `lib/i2np`.

  - [x] 2.1 Create `lib/tunnel/build/` package (new directory).
  - [x] 2.2 Create `lib/tunnel/build/interfaces.go` containing:
        `GarlicKeyRegistrar`, `TunnelBuilder`, `TunnelReplyHandler`,
        `TunnelBuildReplyProcessor`. Imports: `lib/tunnel/buildrecord`,
        `common/data`. No import of `lib/i2np`.
  - [x] 2.3 Create `lib/tunnel/build/session.go` containing:
        `BuildSession interface { Send([]byte) error }` and
        `BuildSessionProvider interface { GetSessionByHash(common.Hash) (BuildSession, error) }`.
        This replaces `i2np.SessionProvider`/`I2NPTransportSession` for the
        coordinator without referencing `i2np.Message`.
  - [x] 2.4 In `lib/i2np/processor.go` and `lib/i2np/database_manager.go`,
        replace the local interface bodies with re-exports pointing at the
        `lib/tunnel/build` definitions (type aliases or embedding), keeping
        `lib/i2np` callers source-compatible.
  - [x] 2.5 `go build ./...` — no compilation errors.
  - [x] 2.6 `go test -race ./lib/i2np/... ./lib/tunnel/...`

  **Phase 3 — Re-route `tunnel.TunnelID` in protocol-only files**

  11 non-manager `lib/i2np` files import `lib/tunnel` solely for
  `tunnel.TunnelID`, which is already
  `type TunnelID = buildrecord.TunnelID`
  ([lib/tunnel/message.go:124](lib/tunnel/message.go#L124)). Switching
  these files to `lib/tunnel/buildrecord` directly removes their
  `lib/tunnel` dependency. Affected files:
  `i2np.go`, `types.go`, `utils.go`, `garlic_builder.go`,
  `garlic_clove_delivery_instructions.go`, `processor.go`,
  `processor_handlers.go`, `tunnel_data.go`, `tunnel_data_message.go`,
  `tunnel_gateway.go`, `tunnel_reply_handler.go`.

  - [x] 3.1 For each of the 11 files above: replace
        `"github.com/go-i2p/go-i2p/lib/tunnel"` with
        `"github.com/go-i2p/go-i2p/lib/tunnel/buildrecord"` and update
        every `tunnel.TunnelID` reference to `buildrecord.TunnelID`.
  - [x] 3.2 `go build ./lib/i2np/...` — confirm those 11 files no longer
        import `lib/tunnel`
        (`grep -rn '"lib/tunnel"' lib/i2np/ | grep -v tunnel_manager`
        should match only `message_router_i2np.go` for `PeerSelector`).
  - [x] 3.3 `go test -race ./lib/i2np/...`

  **Phase 4 — Move `TunnelManager` and orchestrator into `lib/tunnel/build`**

  At this point `lib/tunnel/build` imports `lib/tunnel` (for `Pool`,
  `PeerSelector`, `BuildTunnelRequest`, `BuildTunnelResult`) but
  `lib/tunnel` does not import `lib/tunnel/build`, so no cycle exists.

  - [ ] 4.1 Copy `lib/i2np/tunnel_manager_core.go` →
        `lib/tunnel/build/manager_core.go`; change `package i2np` to
        `package tunnelbuild`; update imports (`lib/tunnel/build`
        interfaces replace the old `lib/i2np` ones; `lib/tunnel` is still
        imported for Pool/PeerSelector).
  - [ ] 4.2 Repeat for `tunnel_manager_build.go`,
        `tunnel_manager_metrics.go`, `tunnel_manager_pool.go`,
        `tunnel_manager_reply.go`.
  - [ ] 4.3 Move `lib/i2np/tunnel_orchestrator.go` →
        `lib/tunnel/build/orchestrator.go`; update package and imports.
  - [ ] 4.4 Delete the original `lib/i2np/tunnel_manager_*.go` and
        `lib/i2np/tunnel_orchestrator.go`.
  - [ ] 4.5 Add thin re-export shims in `lib/i2np/tunnel_shims.go` (e.g.
        `type TunnelOrchestrator = tunnelbuild.TunnelOrchestrator`,
        `type TunnelBuildCoordinator = tunnelbuild.TunnelBuildCoordinator`,
        `type TunnelStatsReader = tunnelbuild.TunnelStatsReader`,
        `var NewTunnelManager = tunnelbuild.NewTunnelManager`) so all
        callers outside `lib/i2np` continue to compile without changes in
        this step.
  - [ ] 4.6 `go build ./...` — no compilation errors.
  - [ ] 4.7 `go test -race ./lib/i2np/... ./lib/tunnel/...`

  **Phase 5 — Update external callers and remove shims**

  - [ ] 5.1 Update `lib/router/router.go:61` — change field type from
        `i2np.TunnelOrchestrator` to `tunnelbuild.TunnelOrchestrator`
        (add import `lib/tunnel/build`).
  - [ ] 5.2 Update `lib/router/router.go:401` — `GetTunnelManager()`
        return type to `tunnelbuild.TunnelOrchestrator`.
  - [ ] 5.3 Update `lib/router/router_tunnel_wiring.go:428` —
        `i2np.NewTunnelManager` → `tunnelbuild.NewTunnelManager`.
  - [ ] 5.4 Update `lib/i2pcontrol/access_interfaces.go` —
        `GetTunnelManager()` return type to
        `tunnelbuild.TunnelStatsReader`.
  - [ ] 5.5 Update `lib/i2pcontrol/stats.go` —
        `RouterBackend.GetTunnelManager()` and
        `RealRouter.GetTunnelManager()` return type to
        `tunnelbuild.TunnelStatsReader`.
  - [ ] 5.6 Update `lib/i2cp/message_router.go` if it references
        `i2np.TunnelOrchestrator` or `i2np.TunnelBuildCoordinator`.
  - [ ] 5.7 Delete `lib/i2np/tunnel_shims.go` (the re-export shims from
        step 4.5).
  - [ ] 5.8 `go build ./...` — no compilation errors.
  - [ ] 5.9 `go test -race ./...`

  **Phase 6 — Verification and doc alignment**

  - [ ] 6.1 `go-stats-generator analyze . --sections packages` — confirm
        no oversized files in `lib/tunnel/build/` and that `lib/i2np` is
        no longer in the oversized-file list for manager-related code.
  - [ ] 6.2 Verify `lib/i2np/doc.go:57` statement *“See lib/tunnel for
        tunnel management and building”* is now accurate (the manager
        lives in `lib/tunnel/build`, reachable from `lib/tunnel`’s doc).
  - [ ] 6.3 Confirm import graph is acyclic:
        `go list -f '{{.ImportPath}}: {{.Imports}}' ./lib/tunnel/build/ | grep i2np`
        must return no output.
  - [ ] 6.4 Update [lib/i2np/README.md](lib/i2np/README.md) and
        [lib/tunnel/README.md](lib/tunnel/README.md) to reflect the new
        package layout.

- [x] **M2 — `i2np/tunnel_manager.go` is a single-file god struct** —
  [lib/i2np/tunnel_manager.go:50](lib/i2np/tunnel_manager.go#L50). One struct
  (`TunnelManager`) carries 20 fields and 101 methods in a single 1,970-line
  file (top of `go-stats-generator` oversized-file list; burden 3.35). It is
  the largest single struct in the codebase by combined field+method count.
  Even after relocation per M1, the orchestrator should be split. **Impact:**
  any contributor adding a build-related feature must navigate 1,970 lines;
  test coverage and review become harder; the file mixes correlation,
  retries, expiry, pool wiring, and metrics. **Remediation:** decompose into
  cohesive files inside the new package: `orchestrator_core.go` (struct +
  ctor + run loop), `orchestrator_build.go` (build request emission),
  `orchestrator_reply.go` (reply correlation, expiry), `orchestrator_pool.go`
  (pool wiring/maintenance hooks), `orchestrator_metrics.go` (build stats
  accessors). Keep the same exported surface so the refactor is behaviour-
  preserving. Validate with `go test -race ./lib/tunnel/...` and
  `go-stats-generator analyze . --sections functions,structs`.

- [x] **M3 — `router.Router` exposes a wide implicit API via struct
  embedding** — [lib/router/router.go:34-38](lib/router/router.go#L34-L38).
  `*keys.RouterInfoKeystore`, `*transport.TransportMuxer`, and
  `*netdb.StdNetDB` are embedded as anonymous fields. Through promotion this
  publishes ~100 additional methods on `*router.Router` (KeyStore 3,
  Transport 41 across muxer, StdNetDB 74) without any local documentation.
  Combined with 31 explicit fields and 19 declared methods, `router.Router`
  effectively *is* the union of those subsystems. **Impact:** ambient
  callers can reach across boundaries (e.g. tunnel wiring code can call
  `r.GetRouterInfoCount()` directly), making it hard to introduce
  alternative implementations and inflating what `router.Lifecycle` *could*
  expose if someone embeds it. **Remediation:** convert the three embeds
  into named fields (`keystore *keys.RouterInfoKeystore`, `transports
  *transport.TransportMuxer`, `netdb *netdb.StdNetDB`); add explicit
  accessor methods only for the operations actually used outside the
  package (a quick scan via `grep -rn "r\.\\(StoreRouterInfo\\|GetRouterInfo\\|Lookup\\)" lib/`
  will enumerate them). Validate by re-running `go build ./...` and
  `go-stats-generator analyze . --sections structs` (expect drop in
  `router.Router` method count).

- [x] **M4 — Duplicated flag-binding blocks in CLI flags package** —
  [lib/config/cliflags/cliflags.go:195](lib/config/cliflags/cliflags.go#L195),
  [lib/config/cliflags/cliflags.go:222](lib/config/cliflags/cliflags.go#L222),
  [lib/config/cliflags/cliflags.go:223](lib/config/cliflags/cliflags.go#L223).
  `go-stats-generator` flags the three highest-ROI clone groups in the
  repository here: 29-line, 24-line, and 22-line duplicate blocks (largest
  clone in the entire codebase). **Impact:** every new flag risks being
  added inconsistently; the file is the only public flag-registration
  surface so drift directly affects user-visible CLI. **Remediation:**
  extract a `bindFlag(cmd *cobra.Command, v *viper.Viper, name, key,
  description string, def any)` helper (or per-type helpers for string/int/
  bool/duration) and replace the three duplicated blocks. Validate with
  `go test ./lib/config/cliflags/...` and
  `go-stats-generator analyze . --sections duplication` (expect duplicated
  lines to drop from 526 toward ~440).

### LOW

- [ ] **L1 — Misplaced helpers flagged by cohesion analysis** —
  [lib/transport/ntcp2/termination.go](lib/transport/ntcp2/termination.go)
  (`TerminationReasonString`),
  [lib/transport/ntcp2/framing.go](lib/transport/ntcp2/framing.go)
  (`NewBlockUnframer`),
  [lib/transport/ntcp2/rekey.go](lib/transport/ntcp2/rekey.go) (`Rekeyer`
  interface) — each is the sole declaration referenced from
  `lib/transport/ntcp2/session.go` per `go-stats-generator` placement
  suggestions. **Impact:** mildly fragmented reading order; no behavioural
  risk. **Remediation:** inline into `session.go` only when the next
  substantive edit touches them; otherwise leave as-is. Validate with
  `go test ./lib/transport/ntcp2/...`.

- [x] **L2 — Two unrelated `Manager` exports in adjacent packages** —
  [lib/i2np/tunnel_manager.go:50](lib/i2np/tunnel_manager.go#L50)
  (`i2np.TunnelManager` = build orchestrator) and
  [lib/tunnel/manager.go:50](lib/tunnel/manager.go#L50) (`tunnel.Manager` =
  transit participant accounting). Same generic name, different
  responsibilities. **Impact:** confuses navigation and code review;
  obscured by qualified package names but surfaces in mixed-import files
  like `lib/i2pcontrol/access_interfaces.go`. **Remediation:** as part of
  M1, rename `tunnel.Manager` to `tunnel.ParticipantManager` (the role it
  actually performs; this matches `r.GetParticipantManager()` already used
  externally). Validate with `go build ./...` and `gopls rename`.

- [x] **L3 — Empty interface declared inside an implementation file** —
  [lib/i2pcontrol/stats.go:247](lib/i2pcontrol/stats.go#L247) declares
  `RouterAccess` as an embedded-only aggregate of four readers, but the
  other four reader interfaces live in
  [lib/i2pcontrol/access_interfaces.go](lib/i2pcontrol/access_interfaces.go).
  **Impact:** newcomers expect the aggregate to be next to its parts.
  **Remediation:** move the 4-line `RouterAccess` type from `stats.go` into
  `access_interfaces.go`; no behaviour change. Validate with
  `go build ./lib/i2pcontrol/...`.

- [ ] **L4 — `i2np.NewTunnelManager` and `i2np.NewSSU2Session` cohesion
  hints** — `go-stats-generator` refactoring suggestions #6 and #9 mark
  `NewMessageRouter` ([lib/i2cp/message_router.go](lib/i2cp/message_router.go))
  and `NewSSU2Session` ([lib/transport/ssu2/session.go](lib/transport/ssu2/session.go))
  for relocation toward `lib/router/`. **Impact:** none in practice — these
  constructors belong to their owning packages and the wiring point is
  legitimately the router. Recorded only because it appears in the metrics
  output; treat as informational and ignore unless a future change makes
  movement natural.

## False Positives Considered and Rejected

| Candidate Finding | Reason Rejected |
|-------------------|----------------|
| `main.go` registers Cobra subcommands inside `main()` instead of in a separate package | The entrypoint is 79 lines and does *only* wiring; the README explicitly markets `lib/embedded` as the library. Adding another package for ~5 `AddCommand` lines would increase noise without benefit. |
| Many packages do not export interfaces for every struct (e.g. `tunnel.Pool`, `i2cp.Session`, `ntcp2.NTCP2Session`) | These are concrete implementations consumed *within* their packages or via already-existing higher-level interfaces (`tunnel.PeerSelector`, `transport.TransportSession`, `i2np.TunnelOrchestrator`). Wrapping every struct in an interface would be cargo-cult abstraction; per Phase 3f rule #3, no extension seam is being blocked. |
| Top-10 oversized files include `lib/netdb/std.go` (79 funcs), `lib/transport/ntcp2/transport.go` (76 funcs), `lib/config/defaults.go` (53 funcs) | These are the canonical implementation files for their packages, sit at burden 2.0–2.5 (modest), and split would scatter cohesive ctor + wiring code. Recorded as monitoring targets, not findings. |
| 27 packages and no `internal/` boundary | Project uses package naming + import direction for boundaries and exposes `lib/embedded` as the intentional public API. README and per-package READMEs document the intent. Not an org defect. |
| `lib/i2np` is 12,754 LOC across 46 non-test files | The Java reference router has a similarly large I2NP layer; the file granularity (most files 200–800 LOC, one outlier covered by M2) is reasonable. Only the misplaced orchestrator (M1/M2) is a real concern. |
| `router.Router` carries 31 fields | A central wiring struct in a router unavoidably aggregates subsystem pointers; per Phase 3f rule #1, the project’s scope justifies it. The actionable issue is the *implicit* method surface from embedding (covered by M3), not the field count itself. |
| `performance_antipatterns: 1103` reported by `go-stats-generator` | This category mostly flags string concatenation and slice growth in hot paths; orthogonal to *organization*. Out of scope for this audit. |
| Cyclomatic complexity ≤ 7 across the entire codebase, no `god_objects`, no `long_methods`, no `deep_nesting` detected | Confirms that within-function organization is healthy; no findings warranted. |
# ORGANIZATION AUDIT — 2026-05-16

## Architecture Summary

- Module: `github.com/go-i2p/go-i2p` (`go 1.26.1`) with one executable root package and 26 supporting importable packages under `lib/`.
- Entrypoints: one `main` package at the repository root; there are no additional `main` packages under `cmd/`. Command-specific helpers live in `lib/config/cmd` and `lib/tui/cmd`.
- Orchestration ownership: root `main` delegates process startup to `lib/embedded` (`main.go:41`), and `lib/router` is explicitly documented as the subsystem coordinator for I2CP, tunnels, NetDB, transports, and message routing (`lib/router/doc.go:1`).
- Business/domain ownership: `lib/i2np`, `lib/tunnel`, `lib/netdb`, `lib/i2cp`, `lib/i2pcontrol`, `lib/naming`, and `lib/keys` hold protocol, routing, and state-management logic.
- Integration ownership: `lib/transport/ntcp2`, `lib/transport/ssu2`, `lib/netdb/reseed`, `lib/config`, `lib/util/time/sntp`, `lib/config/cmd`, and `lib/tui/cmd` hold transport, time, configuration, and operator-facing I/O concerns.
- Directory conventions: feature-first packages under `lib/`; router internals split by lifecycle/wiring concern (`router_mainloop.go`, `router_startup.go`, `router_tunnel_wiring.go`, etc.); transport protocols isolated in subpackages; implementation code remains in exported packages rather than a hidden package tree.
- Public-surface profile from `go-stats-generator`: 36,857 LOC, 27 packages, 1,130 functions, 2,260 methods, 278 structs, 98 interfaces, 0 circular dependencies, and 0.72% duplication.
- Key package metrics from `go-stats-generator`: `main` has 3 functions across 2 files; `embedded` has 24 functions across 9 files; `router` has 355 functions across 29 files with coupling score 10.0; `i2np` has 582 functions across 43 files.
- Baseline validation: `go build ./...` passed and `go test -race ./...` passed.
- Online context: GitHub issue/PR searches for `architecture` and `refactor` did not surface project-specific organization complaints. Official Go guidance says a single root command is valid and `cmd/` is conventional but not mandatory for single-binary repos.

## Organization Scorecard

| Category | Rating | Evidence |
|----------|--------|----------|
| Library-Forward Design | ✅ | Core routing, NetDB, transport, tunnel, and I2CP logic live in `lib/*`; the root `main` package is only 3 functions / 2 files and delegates runtime to `lib/embedded` and `lib/router`. |
| Entrypoint Thinness | ✅ | `main.go` only initializes config/CLI wiring, constructs the embedded router, and executes commands; business logic sits in reusable library packages. |
| Struct/Interface Boundaries | ⚠️ | Interface use is extensive (94 exported interfaces, average 2.36 methods), but `i2pcontrol` still exposes concrete subsystem types and `i2np.TunnelOrchestrator` is a broad 20-method seam. |
| Separation of Concerns | ⚠️ | Packages are feature-oriented and acyclic, but some consumer boundaries still duplicate or overexpose implementation details. |
| Extensibility | ⚠️ | The embedded facade and feature packages support reuse, but alternate implementations still pay unnecessary cost at the `i2pcontrol` and tunnel-orchestration seams. |

## Findings

### CRITICAL

None.

### HIGH

- [x] `lib/i2pcontrol/access_interfaces.go:17` — `RouterInfoReader` exposes `*netdb.StdNetDB`, `*tunnel.Manager`, and untyped transport addresses (`interface{}` at `lib/i2pcontrol/access_interfaces.go:27` and `lib/i2pcontrol/access_interfaces.go:31`) across a public package boundary. The main consumer only reads narrow statistics-oriented slices of those objects (`lib/i2pcontrol/stats.go:344`, `lib/i2pcontrol/stats.go:358`, `lib/i2pcontrol/stats.go:420`, `lib/i2pcontrol/stats.go:643`), so the contract is tighter to implementation than the use cases require. This blocks clean substitution with smaller fakes or alternate router backends and makes `i2pcontrol` harder to reuse independently of the current `netdb` and `tunnel` implementations. **Remediation:** introduce `i2pcontrol`-owned capability interfaces for the exact reads being used (for example peer-count readers, participant counters, and a typed transport-address provider returning `net.Addr` or `fmt.Stringer`), change `RouterInfoReader`/`RouterAccess` to depend on those interfaces, adapt `RealRouter`, and verify with `go-stats-generator analyze . --sections packages,interfaces,structs`, `go build ./...`, and `go test -race ./...`.

### MEDIUM

- [x] `lib/i2pcontrol/stats.go:766` — `RealRouter` defines a second, anonymous 16-method router contract even though the package already has a named `RouterAccess` interface at `lib/i2pcontrol/stats.go:247`. That duplicates the boundary definition inside the same package, creates two sources of truth for the adapter surface, and raises the odds of drift when router stats/control capabilities change. **Remediation:** type `RealRouter.Router` as `RouterAccess` (or as a smaller named composition if the adapter truly needs a narrower subset), remove the anonymous duplicate, and verify with `go-stats-generator analyze . --sections interfaces,packages`, `go build ./...`, and `go test -race ./...`.

- [x] `lib/i2np/tunnel_orchestrator.go:17` — `TunnelOrchestrator` is explicitly documented as the extension seam for tunnel coordination, but it combines 20 methods for pool access, lifecycle, dependency injection, build operations, reply processing, and metrics. Downstream consumers only use slices of that surface (`lib/i2np/message_router_i2np.go:69`, `lib/i2np/message_router_i2np.go:132`, `lib/i2np/message_router_i2np.go:141`, `lib/i2pcontrol/stats.go:724`), so any substitute must implement unrelated responsibilities just to satisfy one consumer. That makes testing, replacement, and future decomposition of tunnel building heavier than necessary. **Remediation:** split the seam into focused consumer-owned interfaces such as a build coordinator, pool reader, and build-stats reader; have `TunnelManager` implement the composed set incrementally; update `I2NPMessageDispatcher` and `i2pcontrol` to depend on the smaller contracts; and verify with `go-stats-generator analyze . --sections interfaces,packages`, `go build ./...`, and `go test -race ./...`.

### LOW

- [ ] `README.md:18` — the repository explicitly says the API should stabilize above a future `go-i2p/onramp` boundary, but the current exported package tree still leaves that boundary mostly documentation-defined rather than package-defined. This is not a runtime defect, but it means external consumers can couple directly to low-level packages the project already warns will change aggressively, with no strong signal beyond docs about which surfaces are meant to be long-term entrypoints. **Remediation:** promote a single stable consumer-facing facade (for example `onramp` or the existing `embedded` layer), add explicit package-level support/experimental markers and deprecation guidance for low-level packages, and verify with `go list ./...`, `go build ./...`, and `go test -race ./...`.

## False Positives Considered and Rejected

| Candidate Finding | Reason Rejected |
|-------------------|----------------|
| `main.go` implements too much business logic | Rejected because the root entrypoint is deliberately thin (`main.go:41`) and delegates router lifecycle to `lib/embedded`; `go-stats-generator` reports only 3 functions in the `main` package. |
| Missing `cmd/` directory is automatically a design failure | Rejected because Go guidance treats `cmd/` as a convention, not a requirement, and this repository currently exposes one installable command rather than many binaries. |
| High coupling in `lib/router` is itself a defect | Rejected because `lib/router` is explicitly documented as the subsystem coordinator (`lib/router/doc.go:1`), and the codebase has no circular dependencies; the coupling is notable but contextually expected for the orchestration owner. |
| `EmbeddedRouter` is too large because it has 9 methods | Rejected because its methods are a cohesive lifecycle surface for the embeddable facade, not a mix of unrelated capabilities, and the package supplies a single clear implementation around that contract. |
