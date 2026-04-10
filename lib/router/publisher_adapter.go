package router

import (
	"context"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// publisherNetDBAdapter wraps StdNetDB to satisfy the netdb.NetworkDatabase interface.
// The key difference is that StdNetDB.StoreRouterInfo takes (hash, data, type) while
// NetworkDatabase.StoreRouterInfo takes a RouterInfo directly.
type publisherNetDBAdapter struct {
	db *netdb.StdNetDB
}

// GetRouterInfo returns a channel that yields the RouterInfo associated with the given hash from the underlying NetDB.
func (a *publisherNetDBAdapter) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	return a.db.GetRouterInfo(hash)
}

// GetAllRouterInfos returns all RouterInfo entries currently stored in the underlying NetDB.
func (a *publisherNetDBAdapter) GetAllRouterInfos() []router_info.RouterInfo {
	return a.db.GetAllRouterInfos()
}

// StoreRouterInfo adapts StdNetDB's signature to match NetworkDatabase interface.
// It serializes the RouterInfo, computes its identity hash, and stores it.
func (a *publisherNetDBAdapter) StoreRouterInfo(ri router_info.RouterInfo) {
	hash, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "publisherNetDBAdapter.StoreRouterInfo",
			"reason": "failed to compute identity hash",
		}).Warn("cannot store RouterInfo without identity hash")
		return
	}
	data, err := ri.Bytes()
	if err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":     "publisherNetDBAdapter.StoreRouterInfo",
			"reason": "failed to serialize RouterInfo",
		}).Warn("cannot store RouterInfo")
		return
	}
	if err := a.db.StoreRouterInfoFromMessage(hash, data, 0); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"at":   "publisherNetDBAdapter.StoreRouterInfo",
			"hash": hash.String(),
		}).Warn("failed to store RouterInfo in NetDB")
	}
}

// Reseed delegates to the underlying NetDB to reseed from the given bootstrap source until at least minRouters are known.
func (a *publisherNetDBAdapter) Reseed(b bootstrap.Bootstrap, minRouters int) error {
	return a.db.Reseed(b, minRouters)
}

// Size returns the number of RouterInfo entries stored in the underlying NetDB.
func (a *publisherNetDBAdapter) Size() int {
	return a.db.Size()
}

// RecalculateSize recalculates the cached size of the underlying NetDB by scanning stored entries.
func (a *publisherNetDBAdapter) RecalculateSize() error {
	return a.db.RecalculateSize()
}

// Ensure verifies that the underlying NetDB storage directory exists and is properly initialized.
func (a *publisherNetDBAdapter) Ensure() error {
	return a.db.Ensure()
}

// SelectFloodfillRouters returns up to count floodfill routers closest to the given target hash from the underlying NetDB.
func (a *publisherNetDBAdapter) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return a.db.SelectFloodfillRouters(targetHash, count)
}

// GetLeaseSetCount returns the number of LeaseSets stored in the underlying NetDB.
func (a *publisherNetDBAdapter) GetLeaseSetCount() int {
	return a.db.GetLeaseSetCount()
}

// GetAllLeaseSets returns all LeaseSet entries currently stored in the underlying NetDB.
func (a *publisherNetDBAdapter) GetAllLeaseSets() []netdb.LeaseSetEntry {
	return a.db.GetAllLeaseSets()
}

// Compile-time interface check
var _ netdb.NetworkDatabase = (*publisherNetDBAdapter)(nil)

// publisherTransportAdapter wraps transport.TransportMuxer to satisfy the
// netdb.TransportManager interface. The underlying GetSession returns a
// transport.TransportSession which already satisfies netdb.TransportSession
// (both have QueueSendI2NP).
type publisherTransportAdapter struct {
	muxer *transport.TransportMuxer
}

// GetSession returns an I2NP-capable session for the given router by delegating to the underlying transport muxer.
func (a *publisherTransportAdapter) GetSession(routerInfo router_info.RouterInfo) (netdb.I2NPSender, error) {
	session, err := a.muxer.GetSession(routerInfo)
	if err != nil {
		return nil, err
	}
	// transport.TransportSession has QueueSendI2NP which satisfies netdb.TransportSession
	return session, nil
}

// Compile-time interface check
var _ netdb.SessionProvider = (*publisherTransportAdapter)(nil)

// floodfillTransportAdapter implements netdb.FloodfillTransport by routing
// I2NP messages via the TransportMuxer, resolving router addresses from StdNetDB.
type floodfillTransportAdapter struct {
	muxer *transport.TransportMuxer
	db    *netdb.StdNetDB
}

// SendI2NPMessage looks up the RouterInfo for routerHash in the local NetDB,
// obtains (or creates) a transport session to that router, and queues msg.
func (a *floodfillTransportAdapter) SendI2NPMessage(ctx context.Context, routerHash common.Hash, msg i2np.I2NPMessage) error {
	if a.muxer == nil || a.db == nil {
		return oops.Errorf("floodfill transport not ready")
	}

	// Resolve RouterInfo from local NetDB (channel-based API)
	riChan := a.db.GetRouterInfo(routerHash)
	var ri router_info.RouterInfo
	select {
	case ri = <-riChan:
	case <-ctx.Done():
		return ctx.Err()
	}

	session, err := a.muxer.GetSession(ri)
	if err != nil {
		return oops.Wrapf(err, "floodfill: get session for %x", routerHash[:8])
	}
	return session.QueueSendI2NP(msg)
}

// Compile-time interface check
var _ netdb.FloodfillTransport = (*floodfillTransportAdapter)(nil)
