package logutil

// ──────────────────────────────────────────────────────────────────────────────
// Identity hash log prefixes
// ──────────────────────────────────────────────────────────────────────────────

// hashPrefixBytes is how many leading bytes of an identity hash are rendered as
// hex in a log line — 16 characters. Logging a full SHA-256 makes a line hard to
// scan and gives an observer more precision than a log message needs; correlating
// two mentions of the same router only needs the leading bytes, and a truncated
// prefix is what the anonymity-logging policy requires so logs cannot be used to
// build a complete hash by collecting its pieces.
//
// Moved from: logutil.go
const hashPrefixBytes = 8
