# Transport and Tunnel Flake Baseline

- Generated: 2026-07-01T18:11:25Z
- Iterations per package: 2
- Scope: transport and tunnel critical-path packages
- Result: 11/12 passing runs

## Package Results

| Package | Passes | Failures |
|---|---:|---:|
| ./lib/transport | 2 | 0 |
| ./lib/transport/ntcp2 | 1 | 1 |
| ./lib/transport/ssu2 | 2 | 0 |
| ./lib/tunnel | 2 | 0 |
| ./lib/tunnel/build | 2 | 0 |
| ./lib/tunnel/buildrecord | 2 | 0 |

## Remediation Backlog and Owners

| Priority | Scope | Trigger | Owner | Next Action |
|---|---|---|---|---|
| P1 | ./lib/transport/ntcp2 | 1/2 failed runs | transport-maintainers | Capture failing seed/logs and stabilize nondeterminism in this package |

## Reproduction

```bash
bash .github/scripts/generate-flake-baseline.bash 2 docs/transport-flake-baseline.md
```
