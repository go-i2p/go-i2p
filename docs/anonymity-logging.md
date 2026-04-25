# Anonymity-Safe Logging

This document describes logging settings that are safer for anonymity-sensitive deployments.

## Production Defaults

- Production deployments MUST set `DEBUG_I2P=warn` or stricter.
- `DEBUG_I2P=debug` is for development and benchmarking only.

## Supported Log Levels

The router recognises three log levels (most verbose to least verbose):
- `debug` — full diagnostic output; **never use in production**
- `warn` — warnings and errors only; recommended for production
- `error` — errors only; most restrictive option

Any unrecognised value (including the previously-documented `info`) falls back to
`debug`. Always use one of the three values listed above.

## Why This Matters

Debug logs can include detailed timing, session lifecycle, peer identifiers, and protocol event context. Even when secrets are not logged, high-detail operational logs can increase correlation risk and should be minimized in production.

## Recommended Environment Profiles

- Development: `DEBUG_I2P=debug`
- Staging: `DEBUG_I2P=warn`
- Production: `DEBUG_I2P=warn` (or `DEBUG_I2P=error` for strictest setting)

## Operational Guidance

- Keep warning/error log retention short unless incident response requires otherwise.
- Restrict log file access to router operators only.
- Treat exported log bundles as sensitive operational metadata.
