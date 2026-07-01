# Transport and Tunnel Observability

This document defines the minimum metrics and structured log taxonomy used to
triage transport and tunnel incidents in go-i2p.

## Scope

- Transport protocols: NTCP2 and SSU2
- Session lifecycle: handshake, established data flow, teardown
- Tunnel path: build, forwarding, and delivery status/error flow

## Minimum Metrics Set

These metrics are intentionally minimal. They are enough to answer: what failed,
where, and at what rate.

### Transport Session Metrics

- `transport_handshake_attempts_total{transport, direction}`
- `transport_handshake_failures_total{transport, direction, reason}`
- `transport_handshake_replay_reject_total{transport}`
- `transport_clock_skew_reject_total{transport}`
- `transport_sessions_active{transport}`
- `transport_session_close_total{transport, reason}`

### Message-Path Metrics

- `transport_i2np_send_fail_total{transport, phase}`
- `transport_i2np_recv_drop_total{transport, reason}`
- `tunnel_fragment_reassembly_fail_total{reason}`
- `tunnel_delivery_status_timeout_total`

### NAT/Introducer Metrics

- `ssu2_peer_test_fail_total{phase, reason}`
- `ssu2_relay_request_reject_total{reason}`
- `ssu2_hole_punch_fail_total{reason}`

## Log Taxonomy

All warning and error logs in transport/tunnel critical paths should include
structured context for reliable triage.

### Required Fields

- `at`: code location or logical operation
- `reason`: compact machine-parseable reason category
- `phase`: lifecycle phase (for example `handshake`, `established`, `teardown`)

### Strongly Recommended Fields

- `transport`: `ntcp2` or `ssu2`
- `session_state`: current session state if known
- `peer_hash`: short, privacy-safe peer hash prefix when available
- `direction`: `inbound` or `outbound`
- `error`: attached via `WithError(err)`

### Reason Vocabulary

Use stable, low-cardinality reason labels, for example:

- `replay_detected`
- `clock_skew_exceeded`
- `termination_write_failed`
- `queue_full`
- `parse_failed`

## Operator-Safe Defaults

- Production: `DEBUG_I2P=warn` (or `DEBUG_I2P=error` for strict environments)
- Never use `DEBUG_I2P=debug` in anonymity-sensitive production deployments
- Keep warning/error retention minimal and access restricted

For full deployment guidance, see `docs/anonymity-logging.md`.

## Anti-Footgun Guidance

- Do not log full peer identities or full cryptographic material.
- Prefer hash/key prefixes over complete values.
- Keep `reason` values stable; do not embed dynamic text in `reason`.
- Emit one clear warning/error per failure point; avoid duplicate spam.