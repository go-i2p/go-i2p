# Mixed-Peer Interoperability Matrix

Updated: 2026-07-01
Owner: transport-maintainers

This matrix captures the current interoperability evidence for mixed peers (Java I2P + i2pd) using the live-network integration suite.

## Scope

- Local router under test: go-i2p.
- External peers: Java I2P (geti2p/i2p) and i2pd (purplei2p/i2pd).
- Verification source:
  - Integration tests in `lib/router/live_network_integration_test.go`.
  - CI workflow `.github/workflows/live-network-daily.yml`.
  - Runner script `.github/scripts/run-live-network-daily.sh`.

## Matrix

| Path | Java I2P peer coverage | i2pd peer coverage | Validation method | Pass criteria | Artifacts |
|---|---|---|---|---|---|
| Bootstrap and peer overlap | Required (`overlap.JavaMatches >= 1`) | Required (`overlap.I2PDMatches >= 1`) | `TestLiveNetworkBootstrapAndInterop` | Router starts and discovers at least one peer from each source netDb snapshot | `test-logs/live-network-attempt*.log`, `tmp/live-network-artifacts/**` |
| RouterInfo publication | Required ACK path (Java floodfill DeliveryStatus ACK) | Mixed-peer routing baseline from shared netDb and transport paths | `TestLiveNetworkPublishRouterInfo` with retries and diagnostics | At least one ACK after publish (`ReplyTokenAckReceived` increases) | `test-logs/live-network-attempt*.log`, optional timeout dump path in test log |
| LeaseSet publication and retrieval | Required as part of floodfill publication path exercised by the test | Required as part of mixed-peer bootstrap and route selection preconditions | `TestLiveNetworkPublishLeaseSet` | Publish succeeds, LeaseSet persists in local netDb, retrieved bytes match published bytes | `tmp/live-network-artifacts/leaseset-publish*`, `test-logs/live-network-attempt*.log` |

## Execution

```bash
bash .github/scripts/run-live-network-daily.sh
```

Manual integration invocation (without the daily wrapper):

```bash
GO_I2P_INTEGRATION=1 go test -tags=integration -count=1 -v ./lib/router -run '^TestLiveNetwork'
```

## Quarantine policy

The daily workflow retries once and classifies known transient network patterns as quarantined (non-blocking) while still storing logs/artifacts for triage.

Known transient patterns are tracked in `.github/scripts/run-live-network-daily.sh` under `transient_pattern`.

## Maintenance checklist

- Update this matrix when test names, pass criteria, or artifact paths change.
- Keep Java and i2pd container images current in the daily workflow.
- Keep quarantine patterns narrow to avoid hiding deterministic regressions.
