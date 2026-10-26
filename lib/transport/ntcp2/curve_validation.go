package ntcp2

import (
	"crypto/subtle"
	"math/big"

	"github.com/samber/oops"
)

// NTCP2 static keys are X25519 (Curve25519 Montgomery u-coordinates).
//
// The spec requires both peers to validate that a remote static key is a
// valid point on the curve before using it:
//   - ntcp2.rst:298 — "Alice must validate that Bob's static key is a valid
//     point on the curve here" (before the MixHash of rs in the handshake);
//   - ntcp2.rst:1142 — "Bob must validate that Alice's static key is a valid
//     point on the curve here" (while processing message 3 part 2; on any
//     error Bob must halt and close abnormally, ntcp2.rst:1144-1147).
//
// No upstream validator exists: go-i2p's crypto/curve25519 package documents
// that it performs no curve-point membership check (crypto/curve25519/
// constants.go:23), and go-noise's XK handshake MixHashes the remote static
// key without validating it. Go's crypto/ecdh (used by x/crypto/curve25519)
// only rejects inputs whose Diffie-Hellman output is all-zero — the four
// small-order u-values of RFC 7748 §6.1 — not general curve membership, so it
// cannot be used as the validator. This is reported upstream as a defect.
//
// Validation implemented here (all arithmetic in GF(2^255-19)):
//  1. the key must be exactly 32 bytes;
//  2. the little-endian u-coordinate has its high bit masked (RFC 7748 §5)
//     and must be < p after reduction;
//  3. u must not be one of the four degenerate values {0, 1, p-1, p-2}
//     (RFC 7748 §6.1: inputs that produce all-zero or twist-small-order
//     results);
//  4. u must be a curve point: rhs = u^3 + 486662*u^2 + u must be zero or a
//     quadratic residue (Legendre symbol == 1);
//  5. u must not be a small-order point: the RFC 7748 Montgomery ladder for
//     scalar 8 must not return the identity (z == 0) or u = 0. Curve25519 has
//     cofactor 8, so exactly the points of order 1, 2, 4 and 8 fail this
//     test; a valid ECDH public key always has large order.

var (
	curve25519P     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curve25519A     = big.NewInt(486662)
	curve25519A24   = big.NewInt(121666)
	largeSubgroupP  = new(big.Int).Sub(curve25519P, big.NewInt(1)) // p-1
	largeSubgroupP2 = new(big.Int).Sub(curve25519P, big.NewInt(2)) // p-2
)

// ValidateNTCP2StaticKey checks that key is a valid X25519 curve point usable
// as an NTCP2 static key per ntcp2.rst:298 / :1142. It returns the masked,
// reduced 32-byte little-endian encoding of the key on success.
func ValidateNTCP2StaticKey(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, oops.Errorf("NTCP2 static key must be 32 bytes, got %d", len(key))
	}

	// Mask the high bit: X25519 u-coordinates are decoded mod 2^255
	// (RFC 7748 §5). Two encodings differing only in the high bit are the
	// same key, so validation operates on the masked value.
	masked := make([]byte, 32)
	copy(masked, key)
	masked[31] &= 0x7f

	u := leToBig(masked)
	if u.Cmp(curve25519P) >= 0 {
		u.Mod(u, curve25519P)
	}

	// Rule 3: reject the four degenerate u-values.
	if u.Sign() == 0 || u.Cmp(big.NewInt(1)) == 0 ||
		u.Cmp(largeSubgroupP) == 0 || u.Cmp(largeSubgroupP2) == 0 {
		return nil, oops.Errorf("NTCP2 static key is a degenerate X25519 u-coordinate (RFC 7748 section 6.1 small-order value)")
	}

	// Rule 4: curve membership.
	if !isCurve25519Point(u) {
		return nil, oops.Errorf("NTCP2 static key is not a valid point on Curve25519")
	}

	// Rule 5: reject small-order (cofactor) points.
	if isCurve25519SmallOrder(u) {
		return nil, oops.Errorf("NTCP2 static key is a small-order Curve25519 point")
	}

	out := bigToLE(masked)
	return out, nil
}

// isCurve25519Point reports whether u is the u-coordinate of a curve point or
// (0,0): rhs = u^3 + A*u^2 + u must be zero or a quadratic residue mod p.
// (The RFC 7748 decoding maps u = 0 to the order-2 point (0,0), which is on
// the curve; the small-order check rejects it later.)
func isCurve25519Point(u *big.Int) bool {
	// rhs = u^3 + A*u^2 + u = u*(u*(u + A) + 1)
	rhs := new(big.Int).Add(u, curve25519A)
	rhs.Mul(rhs, u)
	rhs.Add(rhs, big.NewInt(1))
	rhs.Mul(rhs, u)
	rhs.Mod(rhs, curve25519P)
	if rhs.Sign() == 0 {
		return true
	}
	// Legendre symbol rhs^((p-1)/2) == 1 mod p means rhs is a square.
	exp := new(big.Int).Rsh(new(big.Int).Sub(curve25519P, big.NewInt(1)), 1)
	l := new(big.Int).Exp(rhs, exp, curve25519P)
	return l.Cmp(big.NewInt(1)) == 0
}

// isCurve25519SmallOrder computes [8]u with the RFC 7748 §5 Montgomery ladder
// in projective coordinates and reports whether the result is the identity
// (z == 0) or u == 0, i.e. whether u has order dividing 8.
func isCurve25519SmallOrder(u *big.Int) bool {
	x1 := new(big.Int).Set(u)

	x2, z2 := big.NewInt(1), new(big.Int)
	x3, z3 := new(big.Int).Set(u), big.NewInt(1)

	// Scalar 8: fixed pass over bits 254..0; only bit 3 triggers a swap.
	for t := 254; t >= 0; t-- {
		swap := (8 >> t) & 1
		if swap == 1 {
			x2, z2, x3, z3 = x3, z3, x2, z2
		}
		a := new(big.Int).Add(x2, z2)
		aa := new(big.Int).Mul(a, a)
		b := new(big.Int).Sub(x2, z2)
		bb := new(big.Int).Mul(b, b)
		e := new(big.Int).Sub(aa, bb)

		c := new(big.Int).Add(x3, z3)
		d := new(big.Int).Sub(x3, z3)
		da := new(big.Int).Mul(d, a)
		cb := new(big.Int).Mul(c, b)

		x3 = new(big.Int).Add(da, cb)
		x3.Mul(x3, x3)
		x3.Mod(x3, curve25519P)
		z3 = new(big.Int).Sub(da, cb)
		z3.Mul(z3, z3)
		z3.Mul(z3, x1)
		z3.Mod(z3, curve25519P)

		x2 = new(big.Int).Mul(aa, bb)
		x2.Mod(x2, curve25519P)
		z2 = new(big.Int).Mul(e, aa)
		z2.Add(z2, new(big.Int).Mul(new(big.Int).Mul(curve25519A24, e), e))
		z2.Mod(z2, curve25519P)

		if swap == 1 {
			x2, z2, x3, z3 = x3, z3, x2, z2
		}
	}

	// [8]u is the identity iff z2 == 0; u == 0 output is the order-2 point.
	return z2.Sign() == 0 || x2.Sign() == 0
}

// leToBig interprets b as a little-endian unsigned integer.
func leToBig(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(rev)
}

// bigToLE encodes a reduced to 32-byte little-endian bytes.
func bigToLE(masked []byte) []byte {
	// masked already holds the little-endian encoding with the high bit
	// cleared; reduce mod p so encodings >= p canonicalise like X25519 does.
	u := leToBig(masked)
	u.Mod(u, curve25519P)
	be := u.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[31-i] = be[i]
	}
	return out
}

// staticKeysEqual compares two 32-byte static keys in constant time.
func staticKeysEqual(a, b []byte) bool {
	return len(a) == 32 && len(b) == 32 && subtle.ConstantTimeCompare(a, b) == 1
}

// verifyRouterInfoStaticKeyError enforces the responder-side checks on the
// peer's Noise-authenticated static key: it must be a valid curve point
// (ntcp2.rst:1142) and must byte-match the RouterInfo's published s= option
// (identity binding). Split from the transport method so the check itself is
// unit-testable without a full RouterInfo fixture.
func verifyRouterInfoStaticKeyError(ntcp2Conn msg3PeerConn, publishedKey []byte) error {
	authenticatedKey := ntcp2Conn.PeerStaticKey()
	if _, err := ValidateNTCP2StaticKey(authenticatedKey); err != nil {
		return oops.Wrapf(err, "F107/ntcp2.rst:1142: peer Noise static key is not a valid curve point")
	}
	if !staticKeysEqual(authenticatedKey, publishedKey) {
		return oops.Errorf("F107: Noise-authenticated static key does not match RouterInfo 's' option")
	}
	return nil
}
