# Transport and Tunnel Flake Baseline

- Generated: 2026-09-04T22:28:39Z
- Iterations per package: 2
- Per-test timeout: 20m
- Scope: transport and tunnel critical-path packages
- Result: 12/12 passing runs

## Package Results

| Package | Passes | Failures |
|---|---:|---:|
| ./lib/transport | 2 | 0 |
| ./lib/transport/ntcp2 | 2 | 0 |
| ./lib/transport/ssu2 | 2 | 0 |
| ./lib/tunnel | 2 | 0 |
| ./lib/tunnel/build | 2 | 0 |
| ./lib/tunnel/buildrecord | 2 | 0 |

## Remediation Backlog and Owners

| Priority | Scope | Trigger | Owner | Next Action |
|---|---|---|---|---|
| P2 | transport+tunnel | No flaky failures observed in this sample | transport-maintainers | Keep scheduled sampling and gate on new failures |

## Reproduction

```bash
bash .github/scripts/generate-flake-baseline.bash 2 docs/transport-flake-baseline.md 20m
# Use Go's default timeout behavior for very long suites
bash .github/scripts/generate-flake-baseline.bash 2 docs/transport-flake-baseline.md default
```
