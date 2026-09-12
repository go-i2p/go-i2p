package i2np

// F060-F064: Tunnel build reply structural fixes.
// Per audit (AUDIT.md Phase 5):
// - F060: Build record acceptance must test the correct response field (not wrong offset)
// - F061: Build reply message type and identifier must match spec (not deprecated aliases)
// - F062: Layer keys must be registered (not zeroed) for each hop
// - F063: Creator must derive keys for its own hops (not skip derivation)
// - F064: Build reply must be routed correctly (not misrouted to wrong tunnel)
//
// These require structural rewrites of tunnel_manager_build.go and
// tunnel_build_reply.go. The partial fixes (W-1, BUG-5, CRITICAL-1/2/3)
// address routing/registration but full spec-compliance requires:
// 1. Correct BuildResponseRecord parsing (F060)
// 2. Correct reply message type mapping (F061)
// 3. Non-zero layer key derivation per hop (F062, F063)
// 4. Correct reply routing to pending build (F064)
