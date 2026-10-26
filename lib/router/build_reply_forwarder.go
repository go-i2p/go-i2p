package router

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/go-i2p/lib/util/logutil"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// transportBuildReplyForwarder forwards tunnel build replies via the router's transport layer.
// It implements i2np.BuildReplyForwarder by obtaining transport sessions through the
// router's SessionProvider interface and sending I2NP messages to the appropriate peer.
type transportBuildReplyForwarder struct {
	sessionProvider i2np.SessionProvider
}

// ForwardBuildReplyToRouter forwards a build reply message directly to a router.
// inputMessageType determines the output type: type 25 ShortTunnelBuild sends a
// type 26 OutboundTunnelBuildReply.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the TunnelBuildReply format.
func (f *transportBuildReplyForwarder) ForwardBuildReplyToRouter(routerHash common.Hash, messageID int, encryptedRecords []byte, inputMessageType int) error {
	msg := f.createReplyMessage(messageID, encryptedRecords, inputMessageType)

	session, err := f.sessionProvider.GetSessionByHash(routerHash)
	if err != nil {
		return oops.Wrapf(err, "failed to get session for build reply to %x", routerHash[:8])
	}

	if err := session.QueueSendI2NP(msg); err != nil {
		return oops.Wrapf(err, "failed to send build reply to router %x", routerHash[:8])
	}

	log.WithFields(logger.Fields{
		"at":         "ForwardBuildReplyToRouter",
		"peer":       logutil.HashPrefix(routerHash),
		"message_id": messageID,
	}).Debug("forwarded build reply to router")
	return nil
}

// ForwardBuildReplyThroughTunnel forwards a build reply message through a reply tunnel.
// inputMessageType determines the output type: type 25 ShortTunnelBuild sends a
// type 26 OutboundTunnelBuildReply.
// See [I2P Spec: I2NP](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/i2np.rst) for the TunnelBuildReply format.
func (f *transportBuildReplyForwarder) ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, messageID int, encryptedRecords []byte, inputMessageType int) error {
	innerMsg := f.createReplyMessage(messageID, encryptedRecords, inputMessageType)
	innerBytes, err := innerMsg.MarshalBinary()
	if err != nil {
		return oops.Wrapf(err, "failed to marshal build reply for tunnel %d", tunnelID)
	}
	gwMsg := i2np.NewTunnelGatewayMessage(tunnelID, innerBytes)

	session, err := f.sessionProvider.GetSessionByHash(gatewayHash)
	if err != nil {
		return oops.Wrapf(err, "failed to get session for build reply via tunnel %d at %x", tunnelID, gatewayHash[:8])
	}

	if err := session.QueueSendI2NP(gwMsg); err != nil {
		return oops.Wrapf(err, "failed to send build reply through tunnel %d at %x", tunnelID, gatewayHash[:8])
	}

	log.WithFields(logger.Fields{
		"at":         "ForwardBuildReplyThroughTunnel",
		"gateway":    logutil.HashPrefix(gatewayHash),
		"tunnel_id":  tunnelID,
		"message_id": messageID,
	}).Debug("forwarded build reply through tunnel")
	return nil
}

// createReplyMessage creates the appropriate I2NP message type for the build reply.
// Reply message type is always inputMessageType + 1: type 25 ShortTunnelBuild
// produces a type 26 OutboundTunnelBuildReply. This arithmetic relationship is
// guaranteed by the I2P protocol spec.
func (f *transportBuildReplyForwarder) createReplyMessage(messageID int, encryptedRecords []byte, inputMessageType int) i2np.Message {
	msgType := inputMessageType + 1
	msg := i2np.NewBaseI2NPMessage(msgType)
	msg.SetMessageID(messageID)
	msg.SetData(encryptedRecords)
	return msg
}

// ForwardBuildRequestToRouter relays the transformed build message onward to the
// next hop as a ShortTunnelBuild (type 25) over a direct transport session to
// routerHash (the record's NextIdent). A build request is always delivered
// hop-to-hop directly; the record's NextTunnel field carries the next hop's
// receive tunnel ID as data, not a delivery tunnel, so it is never wrapped in a
// TunnelGateway here. This is how non-endpoint hops telescope the build toward
// the OBEP (outbound) or back to the creator (inbound) per the I2P spec "Message
// Flow". See [I2P Spec: Tunnel Creation ECIES](https://github.com/i2p/i2p.www/blob/master/i2p2www/spec/tunnel-creation-ecies.rst).
func (f *transportBuildReplyForwarder) ForwardBuildRequestToRouter(routerHash common.Hash, messageID int, body []byte) error {
	msg := i2np.NewBaseI2NPMessage(i2np.I2NPMessageTypeShortTunnelBuild)
	msg.SetMessageID(messageID)
	msg.SetData(body)

	session, err := f.sessionProvider.GetSessionByHash(routerHash)
	if err != nil {
		return oops.Wrapf(err, "failed to get session to relay build request to %x", routerHash[:8])
	}

	if err := session.QueueSendI2NP(msg); err != nil {
		return oops.Wrapf(err, "failed to relay build request to router %x", routerHash[:8])
	}

	log.WithFields(logger.Fields{
		"at":         "ForwardBuildRequestToRouter",
		"peer":       logutil.HashPrefix(routerHash),
		"message_id": messageID,
	}).Debug("relayed STBM build request to next hop")
	return nil
}
