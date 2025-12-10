package transport

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/logger"
)

// muxes multiple transports into 1 Transport
// implements transport.Transport
type TransportMuxer struct {
	// the underlying transports we are using in order of most prominant to least
	trans []Transport
}

// mux a bunch of transports together
func Mux(t ...Transport) (tmux *TransportMuxer) {
	log.WithFields(logger.Fields{
		"at":              "Mux",
		"reason":          "initialization",
		"transport_count": len(t),
	}).Debug("creating new TransportMuxer")
	tmux = new(TransportMuxer)
	tmux.trans = append(tmux.trans, t...)
	log.WithFields(logger.Fields{
		"at":     "Mux",
		"reason": "created_successfully",
	}).Debug("TransportMuxer created")
	return
}

// set the identity for every transport
func (tmux *TransportMuxer) SetIdentity(ident router_info.RouterInfo) (err error) {
	identHash, _ := ident.IdentHash()
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) SetIdentity",
		"reason":          "configure_all_transports",
		"identity_hash":   fmt.Sprintf("%x...", identHash[:8]),
		"transport_count": len(tmux.trans),
	}).Debug("setting identity for all transports")
	for i, t := range tmux.trans {
		err = t.SetIdentity(ident)
		if err != nil {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) SetIdentity",
				"reason":          "transport_rejected_identity",
				"transport_index": i,
				"error":           err.Error(),
			}).Error("failed to set identity for transport")
			// an error happened let's return and complain
			return
		}
		log.WithFields(logger.Fields{
			"at":              "(TransportMuxer) SetIdentity",
			"reason":          "transport_configured",
			"transport_index": i,
		}).Debug("identity set for transport")
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) SetIdentity",
		"reason": "all_transports_configured",
	}).Debug("identity set for all transports")
	return
}

// close every transport that this transport muxer has
func (tmux *TransportMuxer) Close() (err error) {
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) Close",
		"reason":          "shutdown_requested",
		"transport_count": len(tmux.trans),
	}).Debug("closing all transports")
	for i, t := range tmux.trans {
		err = t.Close()
		if err != nil {
			// Log error but continue closing remaining transports
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) Close",
				"reason":          "transport_close_failed",
				"transport_index": i,
				"error":           err.Error(),
			}).Warn("error closing transport")
		} else {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) Close",
				"reason":          "transport_closed",
				"transport_index": i,
			}).Debug("transport closed successfully")
		}
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Close",
		"reason": "all_transports_closed",
	}).Debug("all transports closed")
	return
}

// the name of this transport with the names of all the ones that we mux
func (tmux *TransportMuxer) Name() string {
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Name",
		"reason": "generating_composite_name",
	}).Debug("generating muxed transport name")
	name := "Muxed Transport: "
	for _, t := range tmux.trans {
		name += t.Name() + ", "
	}
	_name := name[len(name)-3:]
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Name",
		"reason": "name_generated",
		"name":   _name,
	}).Debug("muxed transport name generated")
	return _name
}

// get a transport session given a router info
// return session and nil if successful
// return nil and ErrNoTransportAvailable if we failed to get a session
func (tmux *TransportMuxer) GetSession(routerInfo router_info.RouterInfo) (s TransportSession, err error) {
	peerHash, _ := routerInfo.IdentHash()
	log.WithFields(logger.Fields{
		"at":             "(TransportMuxer) GetSession",
		"reason":         "attempting_peer_connection",
		"peer_hash":      fmt.Sprintf("%x...", peerHash[:8]),
		"num_transports": len(tmux.trans),
	}).Debug("attempting to get session")
	for i, t := range tmux.trans {
		// pick the first one that is compatible
		if t.Compatible(routerInfo) {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) GetSession",
				"reason":          "compatible_transport_found",
				"transport_index": i,
			}).Debug("found compatible transport, attempting session")
			// try to get a session
			s, err = t.GetSession(routerInfo)
			if err != nil {
				log.WithFields(logger.Fields{
					"at":              "(TransportMuxer) GetSession",
					"reason":          "session_creation_failed",
					"transport_index": i,
					"error":           err.Error(),
				}).Debug("failed to get session from compatible transport, trying next")
				// we could not get a session
				// try the next transport
				continue
			}
			// we got a session
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) GetSession",
				"reason":          "session_established",
				"transport_index": i,
			}).Debug("successfully got session from transport")
			return
		}
	}
	log.WithFields(logger.Fields{
		"at":             "(TransportMuxer) GetSession",
		"reason":         "no_compatible_transport",
		"num_transports": len(tmux.trans),
	}).Error("failed to get session")
	// we failed to get a session for this routerInfo
	err = ErrNoTransportAvailable
	return
}

// is there a transport that we mux that is compatible with this router info?
func (tmux *TransportMuxer) Compatible(routerInfo router_info.RouterInfo) bool {
	peerHash, _ := routerInfo.IdentHash()
	log.WithFields(logger.Fields{
		"at":        "(TransportMuxer) Compatible",
		"reason":    "checking_compatibility",
		"peer_hash": fmt.Sprintf("%x...", peerHash[:8]),
	}).Debug("checking transport compatibility")
	for i, t := range tmux.trans {
		if t.Compatible(routerInfo) {
			log.WithFields(logger.Fields{
				"at":              "(TransportMuxer) Compatible",
				"reason":          "compatible_transport_found",
				"transport_index": i,
			}).Debug("found compatible transport")
			return true
		}
	}
	log.WithFields(logger.Fields{
		"at":     "(TransportMuxer) Compatible",
		"reason": "no_compatible_transport",
	}).Debug("no compatible transport found")
	return false
}

// AcceptWithTimeout accepts an incoming connection with a timeout.
// This method wraps the blocking Accept() call with a timeout context,
// enabling graceful shutdown of session monitoring loops.
// Returns the connection and nil on success.
// Returns nil and context.DeadlineExceeded if the timeout expires.
// Returns nil and any other error from the underlying transport Accept().
func (tmux *TransportMuxer) AcceptWithTimeout(timeout time.Duration) (net.Conn, error) {
	log.WithFields(logger.Fields{
		"at":              "(TransportMuxer) Accept",
		"reason":          "awaiting_connection",
		"timeout_ms":      timeout.Milliseconds(),
		"transport_count": len(tmux.trans),
	}).Debug("accepting connection with timeout")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultChan := tmux.startAcceptGoroutine()
	return tmux.waitForAcceptResult(ctx, resultChan)
}

func (tmux *TransportMuxer) startAcceptGoroutine() chan acceptResult {
	resultChan := make(chan acceptResult, 1)

	go func() {
		if len(tmux.trans) == 0 {
			resultChan <- acceptResult{conn: nil, err: ErrNoTransportAvailable}
			return
		}

		conn, err := tmux.trans[0].Accept()
		resultChan <- acceptResult{conn: conn, err: err}
	}()

	return resultChan
}

func (tmux *TransportMuxer) waitForAcceptResult(ctx context.Context, resultChan chan acceptResult) (net.Conn, error) {
	select {
	case res := <-resultChan:
		return tmux.handleAcceptResult(res)
	case <-ctx.Done():
		log.WithFields(logger.Fields{
			"at":     "(TransportMuxer) Accept",
			"reason": "timeout_exceeded",
		}).Debug("accept timed out")
		return nil, ctx.Err()
	}
}

func (tmux *TransportMuxer) handleAcceptResult(res acceptResult) (net.Conn, error) {
	if res.err != nil {
		log.WithFields(logger.Fields{
			"at":     "(TransportMuxer) Accept",
			"reason": "accept_error",
			"error":  res.err.Error(),
		}).Debug("accept failed")
	} else {
		log.WithFields(logger.Fields{
			"at":     "(TransportMuxer) Accept",
			"reason": "connection_accepted",
		}).Debug("accept succeeded")
	}
	return res.conn, res.err
}

type acceptResult struct {
	conn net.Conn
	err  error
}
