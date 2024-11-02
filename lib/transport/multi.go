package transport

import (
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/util/logger"
)

var log = logger.GetGoI2PLogger()

// muxes multiple transports into 1 Transport
// implements transport.Transport
type TransportMuxer struct {
	// the underlying transports we are using in order of most prominant to least
	trans []Transport
}

// mux a bunch of transports together
func Mux(t ...Transport) (tmux *TransportMuxer) {
	log.WithField("transport_count", len(t)).Debug("Creating new TransportMuxer")
	tmux = new(TransportMuxer)
	tmux.trans = append(tmux.trans, t...)
	log.Debug("TransportMuxer created successfully")
	return
}

// set the identity for every transport
func (tmux *TransportMuxer) SetIdentity(ident router_identity.RouterIdentity) (err error) {
	log.WithField("identity", ident).Debug("TransportMuxer: Setting identity for all transports")
	for i, t := range tmux.trans {
		err = t.SetIdentity(ident)
		if err != nil {
			log.WithError(err).WithField("transport_index", i).Error("TransportMuxer: Failed to set identity for transport")
			// an error happened let's return and complain
			return
		}
		log.WithField("transport_index", i).Debug("TransportMuxer: Identity set successfully for transport")
	}
	log.Debug("TransportMuxer: Identity set successfully for all transports")
	return
}

// close every transport that this transport muxer has
func (tmux *TransportMuxer) Close() (err error) {
	log.Debug("TransportMuxer: Closing all transports")
	for i, t := range tmux.trans {
		err = t.Close()
		if t != nil {
			// TODO: handle error (?)
			log.WithError(err).WithField("transport_index", i).Warn("TransportMuxer: Error closing transport")
		} else {
			log.WithField("transport_index", i).Debug("TransportMuxer: Transport closed successfully")
		}
	}
	log.Debug("TransportMuxer: All transports closed")
	return
}

// the name of this transport with the names of all the ones that we mux
func (tmux *TransportMuxer) Name() string {
	log.Debug("TransportMuxer: Generating muxed transport name")
	name := "Muxed Transport: "
	for _, t := range tmux.trans {
		name += t.Name() + ", "
	}
	// return name[len(name)-3:]
	_name := name[len(name)-3:]
	log.WithField("name", _name).Debug("TransportMuxer: Muxed transport name generated")
	return _name
}

// get a transport session given a router info
// return session and nil if successful
// return nil and ErrNoTransportAvailable if we failed to get a session
func (tmux *TransportMuxer) GetSession(routerInfo router_info.RouterInfo) (s TransportSession, err error) {
	log.WithField("router_info", routerInfo.String()).Debug("TransportMuxer: Attempting to get session")
	for i, t := range tmux.trans {
		// pick the first one that is compatable
		if t.Compatible(routerInfo) {
			log.WithField("transport_index", i).Debug("TransportMuxer: Found compatible transport, attempting to get session")
			// try to get a session
			s, err = t.GetSession(routerInfo)
			if err != nil {
				log.WithError(err).WithField("transport_index", i).Warn("TransportMuxer: Failed to get session from compatible transport")
				// we could not get a session
				// try the next transport
				continue
			}
			// we got a session
			log.WithField("transport_index", i).Debug("TransportMuxer: Successfully got session from transport")
			return
		}
	}
	log.Error("TransportMuxer: Failed to get session, no compatible transport available")
	// we failed to get a session for this routerInfo
	err = ErrNoTransportAvailable
	return
}

// is there a transport that we mux that is compatable with this router info?
func (tmux *TransportMuxer) Compatible(routerInfo router_info.RouterInfo) (compat bool) {
	log.WithField("router_info", routerInfo.String()).Debug("TransportMuxer: Checking compatibility")
	for i, t := range tmux.trans {
		if t.Compatible(routerInfo) {
			log.WithField("transport_index", i).Debug("TransportMuxer: Found compatible transport")
			compat = true
			return
		}
	}
	log.Debug("TransportMuxer: No compatible transport found")
	return
}
