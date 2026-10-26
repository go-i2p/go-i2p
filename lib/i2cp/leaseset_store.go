package i2cp

import (
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/samber/oops"
)

// This file wires the "One byte type of lease set to follow" field of
// CreateLeaseSet2Message through to the behaviour the spec requires.
//
// i2cp.rst:666-677:
//
//	2. One byte type of lease set to follow.
//	  - Type 1 is a [LeaseSet]_ (deprecated)
//	  - Type 3 is a [LeaseSet2]_
//	  - Type 5 is a [EncryptedLeaseSet]_
//	  - Type 7 is a [MetaLeaseSet]_
//	3. [LeaseSet]_ or [LeaseSet2]_ or [EncryptedLeaseSet]_ or [MetaLeaseSet]_
//	4. One byte number of private keys to follow.
//	5. [PrivateKey]_ list. ... (Not present for Meta LS2)
//
// and i2cp.rst:660: "MetaLeaseSet is not yet supported via I2CP."
//
// The store type selects which structure follows, so it selects the framing, the
// validation, the NetDB record type and the key the record is published under.
// Framing and structural validation are delegated to the upstream go-i2p/common
// lease-set packages, which own each structure's wire format and minimum size.

// LeaseSetStoreType is the one-byte "type of lease set to follow" value.
type LeaseSetStoreType uint8

// LeaseSet store types accepted by CreateLeaseSet2 (i2cp.rst:668-671). These
// numbers are shared with the I2NP DatabaseStore type field, which lib/i2np
// already exports, so they are aliased rather than duplicated.
const (
	LeaseSetStoreTypeLeaseSet          = LeaseSetStoreType(i2np.DatabaseStoreTypeLeaseSet)          // 1 (deprecated)
	LeaseSetStoreTypeLeaseSet2         = LeaseSetStoreType(i2np.DatabaseStoreTypeLeaseSet2)         // 3
	LeaseSetStoreTypeEncryptedLeaseSet = LeaseSetStoreType(i2np.DatabaseStoreTypeEncryptedLeaseSet) // 5
	LeaseSetStoreTypeMetaLeaseSet      = LeaseSetStoreType(i2np.DatabaseStoreTypeMetaLeaseSet)      // 7
)

// errMetaLeaseSetUnsupportedViaI2CP is returned for store type 7: the spec lists
// MetaLeaseSet as a valid CreateLeaseSet2 payload but states it is not yet
// supported over I2CP (i2cp.rst:660), so accepting one would store a structure
// the router cannot use.
var errMetaLeaseSetUnsupportedViaI2CP = oops.Errorf("MetaLeaseSet is not yet supported via I2CP")

// leaseSetV1MinSize is the smallest possible type-1 LeaseSet: a 387-byte
// NULL-certificate destination plus the fixed 256-byte ElGamal encryption key
// plus the 1-byte lease count. Every component is an exported upstream constant.
const leaseSetV1MinSize = 387 + lease_set.LEASE_SET_PUBKEY_SIZE + 1

// minSize is the upstream minimum wire size for the structure.
func (st LeaseSetStoreType) minSize() (int, error) {
	switch st {
	case LeaseSetStoreTypeLeaseSet:
		return leaseSetV1MinSize, nil
	case LeaseSetStoreTypeLeaseSet2:
		return lease_set2.LEASESET2_MIN_SIZE, nil
	case LeaseSetStoreTypeEncryptedLeaseSet:
		return encrypted_leaseset.ENCRYPTED_LEASESET_MIN_SIZE, nil
	default:
		return 0, st.unknownErr()
	}
}

// name is the structure's spec name, used in logs and error messages.
func (st LeaseSetStoreType) name() string {
	switch st {
	case LeaseSetStoreTypeLeaseSet:
		return "LeaseSet"
	case LeaseSetStoreTypeLeaseSet2:
		return "LeaseSet2"
	case LeaseSetStoreTypeEncryptedLeaseSet:
		return "EncryptedLeaseSet"
	case LeaseSetStoreTypeMetaLeaseSet:
		return "MetaLeaseSet"
	default:
		return "unknown"
	}
}

// allowsPrivateKeys reports whether the private key list is present for this
// store type. i2cp.rst:677: "(Not present for Meta LS2)".
func (st LeaseSetStoreType) allowsPrivateKeys() bool {
	return st != LeaseSetStoreTypeMetaLeaseSet
}

// unknownErr is the rejection for a byte the spec does not define.
func (st LeaseSetStoreType) unknownErr() error {
	return oops.Errorf("unknown CreateLeaseSet2 lease set store type: %d", uint8(st))
}

// validate returns the store type's rejection: an undefined byte, or type 7,
// which the spec lists but excludes from I2CP.
func (st LeaseSetStoreType) validate() error {
	switch st {
	case LeaseSetStoreTypeLeaseSet, LeaseSetStoreTypeLeaseSet2, LeaseSetStoreTypeEncryptedLeaseSet:
		return nil
	case LeaseSetStoreTypeMetaLeaseSet:
		return oops.Wrapf(errMetaLeaseSetUnsupportedViaI2CP,
			"CreateLeaseSet2 store type %d (%s) is not supported via I2CP", uint8(st), st.name())
	default:
		return st.unknownErr()
	}
}

// frameLeaseSetByStoreType returns exactly the bytes of the lease set structure
// the store type says is next, plus whatever follows it (the private key list).
// Framing is delegated to the upstream reader for that structure.
func frameLeaseSetByStoreType(payload []byte, st LeaseSetStoreType) (leaseSetBytes []byte, remainder []byte, err error) {
	if err := st.validate(); err != nil {
		return nil, nil, err
	}

	minSize, err := st.minSize()
	if err != nil {
		return nil, nil, err
	}
	if len(payload) < minSize {
		return nil, nil, oops.Errorf("%s too short: got %d bytes, need at least %d",
			st.name(), len(payload), minSize)
	}

	switch st {
	case LeaseSetStoreTypeLeaseSet2:
		_, rest, err := lease_set2.ReadLeaseSet2(payload)
		if err != nil {
			return nil, nil, oops.Wrapf(err, "invalid LeaseSet2")
		}
		return payload[:len(payload)-len(rest)], rest, nil

	case LeaseSetStoreTypeEncryptedLeaseSet:
		_, rest, err := encrypted_leaseset.ReadEncryptedLeaseSet(payload)
		if err != nil {
			return nil, nil, oops.Wrapf(err, "invalid EncryptedLeaseSet")
		}
		return payload[:len(payload)-len(rest)], rest, nil

	case LeaseSetStoreTypeLeaseSet:
		return frameLeaseSetV1(payload)

	default:
		return nil, nil, st.unknownErr()
	}
}

// frameLeaseSetV1 measures a type-1 LeaseSet. Upstream lease_set.ReadLeaseSet
// rejects any trailing bytes because a standalone LeaseSet is not embedded in a
// larger structure, which is not the CreateLeaseSet2 case (the private key list
// follows), so the length is computed from the destination's key certificate.
// Each component size comes from exported upstream constants and accessors.
func frameLeaseSetV1(payload []byte) (leaseSetBytes []byte, remainder []byte, err error) {
	dest, rest, err := lease_set.ReadDestinationFromLeaseSet(payload)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "invalid LeaseSet")
	}

	keyCert := dest.KeyCertificate
	if keyCert == nil {
		return nil, nil, oops.Errorf("invalid LeaseSet: destination has no key certificate")
	}

	offset := len(payload) - len(rest)

	// fixed-size ElGamal encryption key, then the signing public key
	signingKeySize, err := keyCert.SigningPublicKeySizeOrError()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "invalid LeaseSet")
	}
	offset += lease_set.LEASE_SET_PUBKEY_SIZE + signingKeySize
	if offset >= len(payload) {
		return nil, nil, oops.Errorf("LeaseSet data too short for leases")
	}

	// 1-byte lease count followed by that many leases
	leaseCount := int(payload[offset])
	if leaseCount > lease_set.LEASE_SET_MAX_LEASES {
		return nil, nil, oops.Errorf("invalid lease count: %d (max %d)",
			leaseCount, lease_set.LEASE_SET_MAX_LEASES)
	}
	offset += 1 + leaseCount*lease.LEASE_SIZE
	if offset > len(payload) {
		return nil, nil, oops.Errorf("LeaseSet data too short for leases")
	}

	// trailing signature
	sigSize, err := keyCert.SignatureSizeOrError()
	if err != nil {
		return nil, nil, oops.Wrapf(err, "invalid LeaseSet")
	}
	offset += sigSize
	if offset > len(payload) {
		return nil, nil, oops.Errorf("LeaseSet data too short for signature")
	}

	return payload[:offset], payload[offset:], nil
}

// validateLeaseSetForSession validates a framed lease set according to its store
// type: the structure must parse and it must not be expired. The identity check
// differs per structure because only LeaseSet and LeaseSet2 carry a cleartext
// destination; an EncryptedLeaseSet's identity is its blinded key, which the
// router cannot derive for a client-managed session.
func validateLeaseSetForSession(session *Session, st LeaseSetStoreType, leaseSetBytes []byte) error {
	switch st {
	case LeaseSetStoreTypeLeaseSet2:
		return session.ValidateLeaseSet2Data(leaseSetBytes)

	case LeaseSetStoreTypeEncryptedLeaseSet:
		return validateEncryptedLeaseSetForSession(leaseSetBytes)

	case LeaseSetStoreTypeLeaseSet:
		return validateLeaseSetV1ForSession(session, leaseSetBytes)

	default:
		return st.validate()
	}
}

// validateEncryptedLeaseSetForSession checks an EncryptedLeaseSet: it must parse
// and its signature must verify. An EncryptedLeaseSet carries no cleartext
// destination — the inner LeaseSet2 is encrypted and the only identity in
// cleartext is the blinded key — so there is nothing here to compare against the
// session's (cleartext) destination. The blinded key hash is enforced as the
// NetDB lookup key by leaseSetPublicationKey, and re-checked by the NetDB store.
func validateEncryptedLeaseSetForSession(leaseSetBytes []byte) error {
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(leaseSetBytes)
	if err != nil {
		return oops.Wrapf(err, "invalid EncryptedLeaseSet")
	}

	// common-structures.rst: the EncryptedLeaseSet is signed by the blinded
	// signing key (or the transient key); a client-supplied one must verify.
	if err := els.Verify(); err != nil {
		return oops.Wrapf(err, "EncryptedLeaseSet signature verification failed")
	}

	if els.IsExpired() {
		return oops.Errorf("EncryptedLeaseSet is already expired (published: %v, expires offset: %d)",
			els.PublishedTime(), els.Expires())
	}

	return nil
}

// validateLeaseSetV1ForSession checks a deprecated type-1 LeaseSet: it must parse
// and its destination must be this session's.
func validateLeaseSetV1ForSession(session *Session, leaseSetBytes []byte) error {
	ls, err := lease_set.ReadLeaseSet(leaseSetBytes)
	if err != nil {
		return oops.Wrapf(err, "invalid LeaseSet")
	}

	if err := ls.Verify(); err != nil {
		return oops.Wrapf(err, "LeaseSet signature verification failed")
	}

	sessionDest := session.Destination()
	if sessionDest == nil {
		return oops.Errorf("session has no destination configured")
	}

	if err := matchDestinations(sessionDest, ls.Destination()); err != nil {
		return oops.Errorf("destination mismatch: %w", err)
	}
	return nil
}

// leaseSetPublicationKey computes the NetDB / DatabaseStore key for a framed
// lease set. An EncryptedLeaseSet is keyed under the hash of the blinded key it
// carries in cleartext; LeaseSet and LeaseSet2 are keyed under the hash of the
// contained destination (common-structures.rst:870-871, :1205-1207). This mirrors
// the checks the NetDB itself applies on store.
func leaseSetPublicationKey(st LeaseSetStoreType, leaseSetBytes []byte) (data.Hash, error) {
	switch st {
	case LeaseSetStoreTypeEncryptedLeaseSet:
		els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(leaseSetBytes)
		if err != nil {
			return data.Hash{}, oops.Wrapf(err, "invalid EncryptedLeaseSet")
		}
		// The NetDB keys an EncryptedLeaseSet under the hash of the blinded key
		// it carries in cleartext and enforces that on store
		// (lib/netdb verifyEncryptedLeaseSetHash), so publication must use the
		// same key or the store is rejected as a hash mismatch.
		return data.HashData(els.BlindedPublicKey()), nil

	case LeaseSetStoreTypeLeaseSet:
		dest, _, err := lease_set.ReadDestinationFromLeaseSet(leaseSetBytes)
		if err != nil {
			return data.Hash{}, oops.Wrapf(err, "invalid LeaseSet")
		}
		return destinationHash(&dest, st.name())

	case LeaseSetStoreTypeLeaseSet2:
		ls2, _, err := lease_set2.ReadLeaseSet2(leaseSetBytes)
		if err != nil {
			return data.Hash{}, oops.Wrapf(err, "invalid LeaseSet2")
		}
		dest := ls2.Destination()
		return destinationHash(&dest, st.name())

	default:
		return data.Hash{}, st.validate()
	}
}

// destinationHash hashes a destination's bytes, delegating serialisation to the
// upstream destination package.
func destinationHash(dest *destination.Destination, name string) (data.Hash, error) {
	destBytes, err := dest.Bytes()
	if err != nil {
		return data.Hash{}, oops.Errorf("failed to get %s destination bytes: %w", name, err)
	}
	return data.HashData(destBytes), nil
}
