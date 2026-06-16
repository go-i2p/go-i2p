package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/netdb"
	"github.com/go-i2p/go-i2p/lib/transport"
	ntcp "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

// ensureNetDBReady validates NetDB state and performs reseed if needed.
// Returns an error if the router's StdNetDB is nil (e.g. during shutdown).

// processSessionMessages reads and processes I2NP messages from a single session.
// This method runs in a dedicated goroutine for each active session,
// continuously reading messages until the session closes or the router stops.
// Message processing errors are logged but don't terminate the session.
func (r *Router) processSessionMessages(session i2npReader, peer AuthenticatedPeer) {
	if peer == nil || !peer.HandshakeComplete() {
		log.WithField("at", "processSessionMessages").Warn("Refusing to start session message processor for unauthenticated peer")
		return
	}

	peerHash := peer.PeerHash()
	defer log.WithField("peer_hash", logutil.HashPrefix(peerHash)).Debug("Session message processor stopped")

	for r.shouldContinueMonitoring() {
		if !r.processSessionMessageSafely(session, peerHash) {
			return
		}
	}
}

// processSessionMessageSafely processes a single inbound message and recovers
// from parser/dispatcher panics so one malicious payload cannot crash the router.
func (r *Router) processSessionMessageSafely(session i2npReader, peerHash common.Hash) (keepProcessing bool) {
	keepProcessing = true
	defer func() {
		if rec := recover(); rec != nil {
			log.WithFields(logger.Fields{
				"peer_hash": logutil.HashPrefix(peerHash),
				"panic":     fmt.Sprintf("%v", rec),
			}).Error("Recovered from panic in I2NP dispatch; dropping session")
			keepProcessing = false
		}
	}()

	msg := r.readNextMessage(session, peerHash)
	if msg == nil {
		return false
	}
	r.handleIncomingMessage(msg, peerHash)
	return true
}

// readNextMessage reads the next I2NP message from the session.
// Returns nil if an error occurs or the session is closed.
func (r *Router) readNextMessage(session i2npReader, peerHash common.Hash) i2np.Message {
	msg, err := session.ReadNextI2NP()
	if err != nil {
		r.logReadError(err, peerHash)
		return nil
	}
	r.logInboundI2NPIngress(msg, peerHash, session)
	return msg
}

// logInboundI2NPIngress records transport-to-I2NP ingress metadata for every
// inbound message so reply-path audits can verify where messages are lost.
func (r *Router) logInboundI2NPIngress(msg i2np.Message, peerHash common.Hash, session i2npReader) {
	i2np.RecordExploratoryReplyStage(i2np.ExploratoryReplyStageInboundI2NPReceived)
	log.WithFields(logger.Fields{
		"at":           "readNextMessage",
		"message_type": msg.Type(),
		"message_size": estimateI2NPMessageSize(msg),
		"source_peer":  logutil.HashPrefix(peerHash),
		"session_id":   fmt.Sprintf("%T:%p", session, session),
	}).Debug("Inbound I2NP ingress")
}

func estimateI2NPMessageSize(msg i2np.Message) int {
	encoded, err := msg.MarshalBinary()
	if err == nil {
		return len(encoded)
	}

	if carrier, ok := msg.(i2np.DataCarrier); ok {
		return len(carrier.GetData())
	}

	return -1
}

// logReadError logs the appropriate error message based on error type.
func (r *Router) logReadError(err error, peerHash common.Hash) {
	peerHashStr := logutil.HashPrefix(peerHash)

	if isBenignReadError(err) {
		log.WithField("peer_hash", peerHashStr).Debug("Session closed normally")
		return
	}

	if isFramingOrLengthViolation(err) {
		if shouldLogReadWarn(peerHashStr) {
			log.WithError(err).WithField("peer_hash", peerHashStr).Warn("Error reading I2NP message from session")
		} else {
			log.WithError(err).WithField("peer_hash", peerHashStr).Debug("Suppressed repeated read warning for noisy peer")
		}
	} else {
		log.WithError(err).WithField("peer_hash", peerHashStr).Debug("Session read ended with non-framing error")
	}
}

func isBenignReadError(err error) bool {
	return errors.Is(err, ntcp.ErrSessionClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

func isFramingOrLengthViolation(err error) bool {
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "frame") ||
		strings.Contains(errText, "framing") ||
		strings.Contains(errText, "length") ||
		strings.Contains(errText, "payload")
}

var (
	readWarnLimiterMu       sync.Mutex
	readWarnLastByPeer      = make(map[string]time.Time)
	readWarnMinInterval     = 5 * time.Second
	readWarnCleanupInterval = 1 * time.Minute  // How often to cleanup stale entries
	readWarnMaxAge          = 10 * time.Minute // Remove entries not updated for this duration
)

func shouldLogReadWarn(peerHash string) bool {
	readWarnLimiterMu.Lock()
	defer readWarnLimiterMu.Unlock()

	now := time.Now()
	last, ok := readWarnLastByPeer[peerHash]
	if ok && now.Sub(last) < readWarnMinInterval {
		return false
	}
	readWarnLastByPeer[peerHash] = now
	return true
}

// cleanupReadWarnLastByPeer removes stale entries from readWarnLastByPeer map.
// This prevents unbounded memory growth by evicting entries that haven't been
// updated for readWarnMaxAge. Called periodically by startReadWarnLimiterCleanup.
// Thread-safe for concurrent access via readWarnLimiterMu.
func cleanupReadWarnLastByPeer() {
	readWarnLimiterMu.Lock()
	defer readWarnLimiterMu.Unlock()

	now := time.Now()
	evicted := 0
	for peerHash, lastWarn := range readWarnLastByPeer {
		if now.Sub(lastWarn) > readWarnMaxAge {
			delete(readWarnLastByPeer, peerHash)
			evicted++
		}
	}

	if evicted > 0 {
		log.WithFields(logger.Fields{
			"at":      "cleanupReadWarnLastByPeer",
			"evicted": evicted,
			"mapSize": len(readWarnLastByPeer),
		}).Debug("Read warn limiter map cleanup")
	}
}

// startReadWarnLimiterCleanup launches a background goroutine that periodically
// removes stale entries from the readWarnLastByPeer map to prevent unbounded growth.
// Entries not updated for readWarnMaxAge are evicted on each cleanup cycle.
// Called from mainloop to ensure proper lifecycle management and shutdown.
func (r *Router) startReadWarnLimiterCleanup() {
	r.startPeriodicTask("startReadWarnLimiterCleanup", readWarnCleanupInterval, func() {
		cleanupReadWarnLastByPeer()
	})
}

// handleIncomingMessage routes the message and logs any routing errors.
func (r *Router) handleIncomingMessage(msg i2np.Message, peerHash common.Hash) {
	if err := r.routeMessage(msg, peerHash); err != nil {
		log.WithError(err).WithFields(logger.Fields{
			"message_type": msg.Type(),
			"message_id":   msg.MessageID(),
			"peer_hash":    logutil.HashPrefix(peerHash),
		}).Error("Failed to route I2NP message")
	}
}

// routeMessage routes an I2NP message to the appropriate handler based on its type.
// This method serves as the main dispatch point for all incoming I2NP messages,
// directing them to the correct processing subsystem (database, tunnel, or general).
// Returns an error if the message type is unsupported or routing fails.
func (r *Router) routeMessage(msg i2np.Message, fromPeer common.Hash) (err error) {
	messageType, messageID := safeMessageMetadata(msg)
	defer func() {
		if rec := recover(); rec != nil {
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, false)
			err = oops.Errorf("panic while routing I2NP message type %d: %v", messageType, rec)
			log.WithError(err).WithFields(logger.Fields{
				"message_type": messageType,
				"message_id":   messageID,
				"from_peer":    logutil.HashPrefix(fromPeer),
				"panic":        fmt.Sprintf("%v", rec),
				"stack":        string(buf[:n]),
			}).Error("Recovered from panic in routeMessage")
		}
	}()

	log.WithFields(logger.Fields{
		"message_type": messageType,
		"message_id":   messageID,
		"from_peer":    logutil.HashPrefix(fromPeer),
	}).Debug("Routing I2NP message")

	mr, fs := r.getRoutingComponents()
	if mr == nil {
		return oops.Errorf("message router not available (router may be shutting down)")
	}

	return r.dispatchByMessageType(msg, mr, fs, fromPeer)
}

func safeMessageMetadata(msg i2np.Message) (messageType, messageID int) {
	return safeMessageType(msg), safeMessageID(msg)
}

func safeMessageType(msg i2np.Message) (messageType int) {
	defer func() {
		if rec := recover(); rec != nil {
			messageType = -1
		}
	}()
	return msg.Type()
}

func safeMessageID(msg i2np.Message) (messageID int) {
	defer func() {
		if rec := recover(); rec != nil {
			messageID = -1
		}
	}()
	return msg.MessageID()
}

// getRoutingComponents returns the message router and floodfill server under lock.
func (r *Router) getRoutingComponents() (*i2np.I2NPMessageDispatcher, *netdb.FloodfillServer) {
	r.runMux.RLock()
	defer r.runMux.RUnlock()
	return r.messageRouter, r.floodfillServer
}

// dispatchByMessageType routes a message to the appropriate handler based on type.
func (r *Router) dispatchByMessageType(msg i2np.Message, mr *i2np.I2NPMessageDispatcher, fs *netdb.FloodfillServer, fromPeer common.Hash) error {
	switch msg.Type() {
	case i2np.I2NPMessageTypeDatabaseStore:
		return r.routeDatabaseStore(msg, mr, fromPeer)
	case i2np.I2NPMessageTypeDatabaseLookup:
		return r.routeDatabaseLookup(msg, mr, fs)
	case i2np.I2NPMessageTypeDatabaseSearchReply:
		return mr.RouteDatabaseMessage(msg)
	case i2np.I2NPMessageTypeData, i2np.I2NPMessageTypeDeliveryStatus,
		i2np.I2NPMessageTypeGarlic, i2np.I2NPMessageTypeTunnelData,
		i2np.I2NPMessageTypeTunnelGateway:
		return mr.RouteMessage(msg)
	case i2np.I2NPMessageTypeTunnelBuild, i2np.I2NPMessageTypeTunnelBuildReply,
		i2np.I2NPMessageTypeVariableTunnelBuild, i2np.I2NPMessageTypeVariableTunnelBuildReply,
		i2np.I2NPMessageTypeShortTunnelBuild, i2np.I2NPMessageTypeShortTunnelBuildReply:
		return mr.GetProcessor().ProcessMessage(msg)
	default:
		return oops.Errorf("unsupported message type: %d", msg.Type())
	}
}

// routeDatabaseStore handles DatabaseStore message routing.
func (r *Router) routeDatabaseStore(msg i2np.Message, mr *i2np.I2NPMessageDispatcher, fromPeer common.Hash) error {
	dbStore, err := r.parseDatabaseStoreMessage(msg)
	if err != nil {
		return oops.Wrapf(err, "failed to parse DatabaseStore message")
	}
	return mr.RouteDatabaseMessageFromPeer(dbStore, &fromPeer)
}

// routeDatabaseLookup handles DatabaseLookup message routing with optional floodfill handling.
func (r *Router) routeDatabaseLookup(msg i2np.Message, mr *i2np.I2NPMessageDispatcher, fs *netdb.FloodfillServer) error {
	if fs != nil {
		if lookup, err := r.parseDatabaseLookupMessage(msg); err == nil {
			if err := fs.HandleDatabaseLookup(lookup); err != nil {
				log.WithError(err).Debug("Floodfill server lookup handling failed (non-fatal)")
			}
		}
	}
	return mr.RouteDatabaseMessage(msg)
}

// parseDatabaseStoreMessage extracts and parses DatabaseStore data from a BaseI2NPMessage.
// This converts the raw I2NP message into a structured DatabaseStore that implements
// the DatabaseWriter interface for NetDB storage.
func (r *Router) parseDatabaseStoreMessage(msg i2np.Message) (*i2np.DatabaseStore, error) {
	// Extract raw message data from BaseI2NPMessage
	dataCarrier, ok := msg.(i2np.DataCarrier)
	if !ok {
		return nil, oops.Errorf("message does not implement DataCarrier interface")
	}

	// Create DatabaseStore and unmarshal the payload
	dbStore := &i2np.DatabaseStore{}
	if err := dbStore.UnmarshalBinary(dataCarrier.GetData()); err != nil {
		return nil, oops.Wrapf(err, "failed to unmarshal DatabaseStore")
	}

	log.WithFields(logger.Fields{
		"message_id": msg.MessageID(),
		"store_type": dbStore.GetStoreType(),
		"key":        dbStore.GetStoreKey().String(),
	}).Info("Parsed DatabaseStore message from peer")

	return dbStore, nil
}

// parseDatabaseLookupMessage extracts and parses a DatabaseLookup from a BaseI2NPMessage.
func (r *Router) parseDatabaseLookupMessage(msg i2np.Message) (*i2np.DatabaseLookup, error) {
	dataCarrier, ok := msg.(i2np.DataCarrier)
	if !ok {
		return nil, oops.Errorf("message does not implement DataCarrier interface")
	}
	dl, err := i2np.ReadDatabaseLookup(dataCarrier.GetData())
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse DatabaseLookup")
	}
	return &dl, nil
}

// Session Management Methods

// addSession registers a new active session by peer hash.
// This method is called when a new NTCP2 connection is established,
// allowing the router to track active sessions for message routing.
// Thread-safe for concurrent access. No-ops if the session map is nil (after shutdown).
func (r *Router) addSession(peerHash common.Hash, session transport.TransportSession) {
	r.sessionMutex.Lock()
	defer r.sessionMutex.Unlock()

	if r.activeSessions == nil {
		log.WithField("peer_hash", logutil.HashPrefix(peerHash)).Warn("Cannot add session: router is shutting down")
		return
	}

	r.activeSessions[peerHash] = session
	log.WithField("peer_hash", logutil.HashPrefix(peerHash)).Debug("Added active session")
}
