package router

import (
	"fmt"
	"net"
	"time"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/go-i2p/lib/config"
	"github.com/go-i2p/go-i2p/lib/keys"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// resolveTransportPort returns a listen address string from transport config.
// Returns ":0" if the configured port is 0 (OS assigns a random port).
func resolveTransportPort(cfg *config.TransportDefaults, port int) string {
	p := 0
	if cfg != nil && port > 0 {
		p = port
	}
	return fmt.Sprintf(":%d", p)
}

// reSignAndVerifyRouterInfo re-signs the RouterInfo after a transport address
// has been added and verifies the new signature locally. It returns an error
// if the signing key has the wrong type, the re-signing operation fails, or
// the resulting signature does not verify.
func reSignAndVerifyRouterInfo(ri *router_info.RouterInfo, ks *keys.RouterInfoKeystore) error {
	privKey := ks.GetSigningPrivateKey()
	signingKey, ok := privKey.(types.SigningPrivateKey)
	if !ok {
		return oops.Errorf("router signing key does not implement SigningPrivateKey (got %T)", privKey)
	}
	pubTime := ks.GetCurrentTime().Round(time.Second)
	if err := ri.ReSign(pubTime, signingKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519); err != nil {
		return oops.Wrapf(err, "failed to re-sign RouterInfo")
	}
	if sigValid, sigErr := ri.VerifySignature(); !sigValid || sigErr != nil {
		riBytes, _ := ri.Bytes()
		log.WithFields(logger.Fields{
			"sig_valid":  sigValid,
			"sig_err":    fmt.Sprintf("%v", sigErr),
			"addr_count": ri.RouterAddressCount(),
			"ri_len":     len(riBytes),
		}).Error("Re-signed RouterInfo FAILED local verification")
		return oops.Errorf("re-signed RouterInfo failed verification: valid=%v err=%v", sigValid, sigErr)
	}
	riBytes, _ := ri.Bytes()
	log.WithFields(logger.Fields{
		"addr_count": ri.RouterAddressCount(),
		"ri_len":     len(riBytes),
	}).Info("Re-signed RouterInfo passes local verification")
	return nil
}

// validateAndAddTransportAddress validates that addr is non-nil, logs it, and calls addTransportAddress.
// This reduces code duplication between buildNTCP2Transport and buildSSU2Transport.
func validateAndAddTransportAddress(ri *router_info.RouterInfo, addr net.Addr, proto string, converter func() (*router_address.RouterAddress, error)) error {
	if addr == nil {
		log.WithFields(logger.Fields{"at": "validateAndAddTransportAddress"}).Error("Failed to get " + proto + " address")
		return oops.Errorf("failed to get %s address", proto)
	}
	log.WithFields(logger.Fields{"at": "validateAndAddTransportAddress"}).Debug(proto+" address:", addr)
	return addTransportAddress(ri, addr, proto, converter)
}

// addTransportAddress converts a transport's address to a RouterAddress via converter
// and appends it to ri. proto is used in log messages only.
func addTransportAddress(ri *router_info.RouterInfo, addr net.Addr, proto string, converter func() (*router_address.RouterAddress, error)) error {
	routerAddress, err := converter()
	if err != nil {
		log.WithError(err).Errorf("Failed to convert %s address to RouterAddress", proto)
		return oops.Wrapf(err, "failed to convert %s address", proto)
	}
	if err := ri.AddAddress(routerAddress); err != nil {
		log.WithError(err).Errorf("failed to add %s address to RouterInfo", proto)
		return oops.Wrapf(err, "failed to add %s address", proto)
	}
	log.WithFields(logger.Fields{
		"host": addr.String(),
		"cost": routerAddress.Cost(),
	}).Infof("%s address added to RouterInfo", proto)
	return nil
}
