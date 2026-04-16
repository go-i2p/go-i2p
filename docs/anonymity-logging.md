# Anonymity-Safe Logging

This document describes logging settings that are safer for anonymity-sensitive deployments.

## Production Defaults

- Production deployments MUST set `DEBUG_I2P=info` or stricter.
- `DEBUG_I2P=debug` is for development and benchmarking only.

## Why This Matters

Debug logs can include detailed timing, session lifecycle, peer identifiers, and protocol event context. Even when secrets are not logged, high-detail operational logs can increase correlation risk and should be minimized in production.

## Recommended Environment Profiles

- Development: `DEBUG_I2P=debug`
- Staging: `DEBUG_I2P=info`
- Production: `DEBUG_I2P=info` (or stricter)

## Operational Guidance

- Keep warning/error log retention short unless incident response requires otherwise.
- Restrict log file access to router operators only.
- Treat exported log bundles as sensitive operational metadata.
