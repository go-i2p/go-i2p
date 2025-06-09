package i2np

import (
	"slices"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/session_key"
	"github.com/go-i2p/go-i2p/lib/tunnel"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

/*
I2P I2NP GarlicCloveDeliveryInstructions
https://geti2p.net/spec/i2np
Accurate for version 0.9.28

+----+----+----+----+----+----+----+----+
|flag|                                  |
+----+                                  +
|                                       |
+       Session Key (optional)          +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+--------------+
|    |                                  |
+----+                                  +
|                                       |
+         To Hash (optional)            +
|                                       |
+                                       +
|                                       |
+    +----+----+----+----+--------------+
|    |  Tunnel ID (opt)  |  Delay (opt)
+----+----+----+----+----+----+----+----+
     |
+----+

flag ::
       1 byte
       Bit order: 76543210
       bit 7: encrypted? Unimplemented, always 0
                If 1, a 32-byte encryption session key is included
       bits 6-5: delivery type
                0x0 = LOCAL, 0x01 = DESTINATION, 0x02 = ROUTER, 0x03 = TUNNEL
       bit 4: delay included?  Not fully implemented, always 0
                If 1, four delay bytes are included
       bits 3-0: reserved, set to 0 for compatibility with future uses

Session Key ::
       32 bytes
       Optional, present if encrypt flag bit is set.
       Unimplemented, never set, never present.

To Hash ::
       32 bytes
       Optional, present if delivery type is DESTINATION, ROUTER, or TUNNEL
          If DESTINATION, the SHA256 Hash of the destination
          If ROUTER, the SHA256 Hash of the router
          If TUNNEL, the SHA256 Hash of the gateway router

Tunnel ID :: TunnelId
       4 bytes
       Optional, present if delivery type is TUNNEL
       The destination tunnel ID, nonzero

Delay :: Integer
       4 bytes
       Optional, present if delay included flag is set
       Not fully implemented. Specifies the delay in seconds.

Total length: Typical length is:
       1 byte for LOCAL delivery;
       33 bytes for ROUTER / DESTINATION delivery;
       37 bytes for TUNNEL delivery
*/

type GarlicCloveDeliveryInstructions struct {
	Flag       byte
	SessionKey session_key.SessionKey
	Hash       common.Hash
	TunnelID   tunnel.TunnelID
	Delay      int
}

type DeliveryType int

const (
	LOCAL DeliveryType = iota
	DESTINATION
	ROUTER
	TUNNEL
)

var ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA = oops.Errorf("not enough i2np garlic clove delivery instructions data")

func ReadGarlicCloveDeliveryInstructions(data []byte) (GarlicCloveDeliveryInstructions, error) {
	log.Debug("Reading GarlicCloveDeliveryInstructions")
	garlicCloveDeliveryInstructions := GarlicCloveDeliveryInstructions{}

	length, flag, err := readGarlicCloveDeliveryInstructionsFlag(data)
	if err != nil {
		log.WithError(err).Error("Failed to read flag")
		return garlicCloveDeliveryInstructions, err
	}
	garlicCloveDeliveryInstructions.Flag = flag

	withSessionKey := (flag >> 7) & 1 == 1
	deliveryType := DeliveryType((flag >> 5) & 3)
	withDelay := (flag >> 4) & 1 == 1

	sessionKey := session_key.SessionKey{}
	if withSessionKey == true {
		length, sessionKey, err = readGarlicCloveDeliveryInstructionsSessionKey(length, data)
		if err != nil {
			log.WithError(err).Error("Failed to read session_key")
			return garlicCloveDeliveryInstructions, err
		}
	}
	garlicCloveDeliveryInstructions.SessionKey = sessionKey

	hash := common.Hash{}
	if slices.Contains([]DeliveryType{DESTINATION, ROUTER, TUNNEL}, deliveryType) {
		length, hash, err = readGarlicCloveDeliveryInstructionsHash(length, data)
		if err != nil {
			log.WithError(err).Error("Failed to read hash")
			return garlicCloveDeliveryInstructions, err
		}
	}
	garlicCloveDeliveryInstructions.Hash = hash

	tunnelID := tunnel.TunnelID(0)
	if deliveryType == TUNNEL {
		length, tunnelID, err = readGarlicCloveDeliveryInstructionsTunnelID(length, data)
		if err != nil {
			log.WithError(err).Error("Failed to read tunnel_id")
			return garlicCloveDeliveryInstructions, err
		}
	}
	garlicCloveDeliveryInstructions.TunnelID = tunnelID

	delay := 0
	if withDelay == true {
		length, delay, err = readGarlicCloveDeliveryInstructionsDelay(length, data)
		if err != nil {
			log.WithError(err).Error("Failed to read delay")
			return garlicCloveDeliveryInstructions, err
		}
	}
	garlicCloveDeliveryInstructions.Delay = delay

	log.Debug("GarlicCloveDeliveryInstructions read successfully")
	return garlicCloveDeliveryInstructions, nil
}

func readGarlicCloveDeliveryInstructionsFlag(data []byte) (int, byte, error) {
	if len(data) < 1 {
		return 0, byte(0), ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA
	}
	flag := data[0]

	log.WithFields(logrus.Fields{
		"at":   "i2np.garlic_clove_delivery_instructions.readGarlicCloveDeliveryInstructionsFlag",
		"flag": flag,
	}).Debug("parsed_garlic_clove_delivery_instructions_flag")
	return 1, flag, nil
}

func readGarlicCloveDeliveryInstructionsSessionKey(length int, data []byte) (int, session_key.SessionKey, error) {
	if len(data) < length+32 {
		return length, session_key.SessionKey{}, ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA
	}

	sessionKey := session_key.SessionKey(data[length : length+32])
	log.WithFields(logrus.Fields{
		"at":   "i2np.garlic_clove_delivery_instructions.readGarlicCloveDeliveryInstructionsSessionKey",
		"session_key": sessionKey,
	}).Debug("parsed_garlic_clove_delivery_instructions_session_key")
	return length + 32, sessionKey, nil
}

func readGarlicCloveDeliveryInstructionsHash(length int, data []byte) (int, common.Hash, error) {
	if len(data) < length+32 {
		return length, common.Hash{}, ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA
	}

	hash := common.Hash(data[length: length+32])
	log.WithFields(logrus.Fields{
		"at":   "i2np.garlic_clove_delivery_instructions.readGarlicCloveDeliveryInstructionsHash",
		"hash": hash,
	}).Debug("parsed_garlic_clove_delivery_instructions_hash")
	return length + 32, hash, nil
}

func readGarlicCloveDeliveryInstructionsTunnelID(length int, data []byte) (int, tunnel.TunnelID, error) {
	if len(data) < length+4 {
		return length, tunnel.TunnelID(0), ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA
	}

	tunnelID := tunnel.TunnelID(
		common.Integer(data[length: length + 4]).Int(),
	)
	log.WithFields(logrus.Fields{
		"at":        "i2np.garlic_clove_delivery_instructions.readGarlicCloveDeliveryInstructionsTunnelID",
		"tunnel_id": tunnelID,
	}).Debug("parsed_garlic_clove_delivery_instructions_tunnel_id")
	return length + 4, tunnelID, nil
}

func readGarlicCloveDeliveryInstructionsDelay(length int, data []byte) (int, int, error) {
	if len(data) < length+4 {
		return length, 0, ERR_GARLIC_CLOVE_DELIVERY_INSTRUCTIONS_NOT_ENOUGH_DATA
	}

	delay := common.Integer(data[length: length + 4]).Int()
	log.WithFields(logrus.Fields{
		"at":    "i2np.garlic_clove_delivery_instructions.readGarlicCloveDeliveryInstructionsTunnelID",
		"delay": delay,
	}).Debug("parsed_garlic_clove_delivery_instructions_delay")
	return length + 4, delay, nil
}

