package router

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	"github.com/go-i2p/logger"
)

// publisherNetDBAdapter wraps StdNetDB to satisfy the netdb.NetworkDatabase interface.
// The key difference is that StdNetDB.StoreRouterInfo takes (hash, data, type) while
// NetworkDatabase.StoreRouterInfo takes a RouterInfo directly.
type publisherNetDBAdapter struct {
	db *netdb.StdNetDB
}

func (a *publisherNetDBAdapter) GetRouterInfo(hash common.Hash) chan router_info.RouterInfo {
	return a.db.GetRouterInfo(hash)
}

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

func (a *publisherNetDBAdapter) Reseed(b bootstrap.Bootstrap, minRouters int) error {
	return a.db.Reseed(b, minRouters)
}

func (a *publisherNetDBAdapter) Size() int {
	return a.db.Size()
}

func (a *publisherNetDBAdapter) RecalculateSize() error {
	return a.db.RecalculateSize()
}

func (a *publisherNetDBAdapter) Ensure() error {
	return a.db.Ensure()
}

func (a *publisherNetDBAdapter) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	return a.db.SelectFloodfillRouters(targetHash, count)
}

func (a *publisherNetDBAdapter) GetLeaseSetCount() int {
	return a.db.GetLeaseSetCount()
}

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

func (a *publisherTransportAdapter) GetSession(routerInfo router_info.RouterInfo) (netdb.TransportSession, error) {
	session, err := a.muxer.GetSession(routerInfo)
	if err != nil {
		return nil, err
	}
	// transport.TransportSession has QueueSendI2NP which satisfies netdb.TransportSession
	return session, nil
}

// Compile-time interface check
var _ netdb.TransportManager = (*publisherTransportAdapter)(nil)
