package router

import (
	"fmt"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/go-i2p/go-i2p/lib/tunnel"
	"github.com/go-i2p/logger"
)

// transportBuildReplyForwarder forwards tunnel build replies via the router's transport layer.
// It implements i2np.BuildReplyForwarder by obtaining transport sessions through the
// router's SessionProvider interface and sending I2NP messages to the appropriate peer.
type transportBuildReplyForwarder struct {
	sessionProvider i2np.SessionProvider
}

// ForwardBuildReplyToRouter forwards a build reply message directly to a router.
func (f *transportBuildReplyForwarder) ForwardBuildReplyToRouter(routerHash common.Hash, messageID int, encryptedRecords []byte, isShortBuild bool) error {
	msg := f.createReplyMessage(messageID, encryptedRecords, isShortBuild)

	session, err := f.sessionProvider.GetSessionByHash(routerHash)
	if err != nil {
		return fmt.Errorf("failed to get session for build reply to %x: %w", routerHash[:8], err)
	}

	if err := session.QueueSendI2NP(msg); err != nil {
		return fmt.Errorf("failed to send build reply to router %x: %w", routerHash[:8], err)
	}

	log.WithFields(logger.Fields{
		"at":         "ForwardBuildReplyToRouter",
		"peer":       fmt.Sprintf("%x", routerHash[:8]),
		"message_id": messageID,
		"short":      isShortBuild,
	}).Debug("forwarded build reply to router")
	return nil
}

// ForwardBuildReplyThroughTunnel forwards a build reply message through a reply tunnel.
func (f *transportBuildReplyForwarder) ForwardBuildReplyThroughTunnel(gatewayHash common.Hash, tunnelID tunnel.TunnelID, messageID int, encryptedRecords []byte, isShortBuild bool) error {
	innerMsg := f.createReplyMessage(messageID, encryptedRecords, isShortBuild)
	innerBytes, err := innerMsg.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal build reply for tunnel %d: %w", tunnelID, err)
	}
	gwMsg := i2np.NewTunnelGatewayMessage(tunnelID, innerBytes)

	session, err := f.sessionProvider.GetSessionByHash(gatewayHash)
	if err != nil {
		return fmt.Errorf("failed to get session for build reply via tunnel %d at %x: %w", tunnelID, gatewayHash[:8], err)
	}

	if err := session.QueueSendI2NP(gwMsg); err != nil {
		return fmt.Errorf("failed to send build reply through tunnel %d at %x: %w", tunnelID, gatewayHash[:8], err)
	}

	log.WithFields(logger.Fields{
		"at":         "ForwardBuildReplyThroughTunnel",
		"gateway":    fmt.Sprintf("%x", gatewayHash[:8]),
		"tunnel_id":  tunnelID,
		"message_id": messageID,
		"short":      isShortBuild,
	}).Debug("forwarded build reply through tunnel")
	return nil
}

// createReplyMessage creates the appropriate I2NP message type for the build reply.
func (f *transportBuildReplyForwarder) createReplyMessage(messageID int, encryptedRecords []byte, isShortBuild bool) i2np.I2NPMessage {
	var msgType int
	if isShortBuild {
		msgType = i2np.I2NPMessageTypeShortTunnelBuildReply
	} else {
		msgType = i2np.I2NPMessageTypeVariableTunnelBuildReply
	}
	msg := i2np.NewBaseI2NPMessage(msgType)
	msg.SetMessageID(messageID)
	msg.SetData(encryptedRecords)
	return msg
}
