package ssu2

import (
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/samber/oops"
)

// sendRouterInfoToPeer delivers a peer's RouterInfo to another peer over an
// existing SSU2 session as an I2NP DatabaseStore message.
//
// ssu2.rst §"Peer Test Process" makes this mandatory, twice: "Bob must send
// Alice's RI to Charlie prior to sending message 2" and "Bob must send
// Charlie's RI to Alice prior to sending message 4, if accepted (reason code
// 0)". The receiver needs the full RouterInfo -- not just the hash -- to build
// a session with the third party, so without it the peer test cannot be
// completed by a router that has not already fetched the RI from the netdb.
//
// The delivery vehicle is prescribed by §"RouterInfo", which is explicitly
// restricted to the Session Confirmed payload: "Pass Alice's RouterInfo to Bob.
// Used in Session Confirmed part 2 payload only. Not to be used in the data
// phase; use an I2NP DatabaseStore Message instead." §"Peer Test Process"
// agrees -- "RI may be sent either I2NP Database Store messages in I2NP blocks,
// or as RI blocks (if small enough)" -- and since the data-phase RI block is
// ruled out by its own section, the DatabaseStore is the form we use.
//
// A DatabaseStore we cannot build is not fatal to the peer test: the peer may
// already hold the RouterInfo. Callers log and continue, matching how the rest
// of this path degrades.
func (t *SSU2Transport) sendRouterInfoToPeer(session *SSU2Session, hash data.Hash) error {
	if session == nil {
		return oops.Errorf("no session for RouterInfo delivery")
	}
	cfg := t.config.Load()
	if cfg == nil || cfg.RouterLookupFunc == nil {
		return oops.Errorf("RouterLookupFunc not configured: cannot fetch RouterInfo %x", hash[:4])
	}
	// A zero hash means we never learned whose RI this is; sending a
	// DatabaseStore keyed on zeros would pollute the peer's netdb.
	if hash == (data.Hash{}) {
		return oops.Errorf("refusing to deliver RouterInfo for zero hash")
	}

	ri, err := cfg.RouterLookupFunc(hash)
	if err != nil {
		return oops.Wrapf(err, "netdb lookup failed for RouterInfo %x", hash[:4])
	}
	riBytes, err := ri.Bytes()
	if err != nil {
		return oops.Wrapf(err, "serialize RouterInfo %x", hash[:4])
	}
	if len(riBytes) == 0 {
		return oops.Errorf("RouterInfo %x serialized to zero bytes", hash[:4])
	}

	msg, err := buildRouterInfoDatabaseStore(hash, riBytes)
	if err != nil {
		return oops.Wrapf(err, "build DatabaseStore for RouterInfo %x", hash[:4])
	}
	return session.QueueSendI2NP(msg)
}

// buildRouterInfoDatabaseStore wraps RouterInfo bytes in a DatabaseStore.
// Delegates the framing to i2np, which owns the DatabaseStore wire format.
func buildRouterInfoDatabaseStore(hash data.Hash, riBytes []byte) (i2np.Message, error) {
	var key [32]byte
	copy(key[:], hash[:])
	// Reply fields are left zero, which means the recipient replies directly
	// rather than through a tunnel -- correct for a point-to-point data-phase
	// delivery on an established session.
	return i2np.NewRouterInfoDatabaseStore(key, riBytes)
}
