package transport

import (
	"context"
	"net"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
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
func (tmux *TransportMuxer) SetIdentity(ident router_info.RouterInfo) (err error) {
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
		// pick the first one that is compatible
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

// is there a transport that we mux that is compatible with this router info?
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

// AcceptWithTimeout accepts an incoming connection with a timeout.
// This method wraps the blocking Accept() call with a timeout context,
// enabling graceful shutdown of session monitoring loops.
// Returns the connection and nil on success.
// Returns nil and context.DeadlineExceeded if the timeout expires.
// Returns nil and any other error from the underlying transport Accept().
func (tmux *TransportMuxer) AcceptWithTimeout(timeout time.Duration) (net.Conn, error) {
	log.WithField("timeout", timeout).Debug("TransportMuxer: Accepting connection with timeout")

	// Create context with timeout for the accept operation
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Channel to receive accept result
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resultChan := make(chan acceptResult, 1)

	// Run Accept in a goroutine to allow timeout
	go func() {
		// Use the first transport (primary) for accepting connections
		if len(tmux.trans) == 0 {
			resultChan <- acceptResult{conn: nil, err: ErrNoTransportAvailable}
			return
		}

		conn, err := tmux.trans[0].Accept()
		resultChan <- acceptResult{conn: conn, err: err}
	}()

	// Wait for either accept to complete or context timeout
	select {
	case res := <-resultChan:
		if res.err != nil {
			log.WithError(res.err).Debug("TransportMuxer: Accept failed")
		} else {
			log.Debug("TransportMuxer: Accept succeeded")
		}
		return res.conn, res.err
	case <-ctx.Done():
		log.Debug("TransportMuxer: Accept timed out")
		return nil, ctx.Err()
	}
}
