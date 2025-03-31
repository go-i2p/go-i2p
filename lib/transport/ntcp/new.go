package ntcp

import (
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/noise"
	"github.com/go-i2p/go-i2p/lib/util/time/sntp"
	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

func NewNTCP2Transport(routerInfo *router_info.RouterInfo) (*NTCP2Transport, error) {
	defaultClient := &sntp.DefaultNTPClient{}
	timestamper := sntp.NewRouterTimestamper(defaultClient)
	n := &NTCP2Transport{
		NoiseTransport: &noise.NoiseTransport{
			RouterInfo: *routerInfo,
		},
		RouterTimestamper: timestamper,
		transportStyle:    NTCP_PROTOCOL_NAME,
	}
	return n, nil
}
