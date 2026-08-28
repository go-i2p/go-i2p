# Anonymity-Safe Logging

This document describes logging settings that are safer for anonymity-sensitive deployments.

## Production Defaults

- Production deployments MUST set `DEBUG_I2P=warn` or stricter.
- `DEBUG_I2P=info` is acceptable for day-to-day operational triage (including `./run.sh`).
- `DEBUG_I2P=debug` is for development and benchmarking only.

## Supported Log Levels

The router recognises four log levels (most verbose to least verbose):

- `debug` — full diagnostic / hot-path output; **never use in production**
- `info` — lifecycle and operational milestones; recommended `./run.sh` default
- `warn` — warnings and errors only; recommended for production
- `error` — errors only; most restrictive option

Any unrecognised value falls back to `info` (go-i2p applies this after the
external logger package initializes). This prevents a typo from enabling the
debug firehose.

## Why This Matters

Debug logs can include detailed timing, session lifecycle, peer identifiers, and protocol event context. Even when secrets are not logged, high-detail operational logs can increase correlation risk and should be minimized in production.

## Recommended Environment Profiles

- Development: `DEBUG_I2P=debug`
- Day-to-day / `./run.sh`: `DEBUG_I2P=info`
- Staging: `DEBUG_I2P=warn`
- Production: `DEBUG_I2P=warn` (or `DEBUG_I2P=error` for strictest setting)

## Operational Guidance

- Keep warning/error log retention short unless incident response requires otherwise.
- Restrict log file access to router operators only.
- Treat exported log bundles as sensitive operational metadata.
