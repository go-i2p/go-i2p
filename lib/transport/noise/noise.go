package noise

import (
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
)

// wrapper around flynn/noise with just enough options exposed to enable configuring NTCP2
// possible and/or relatively intuitive
type Noise struct {
	noise.Config
	router_info.RouterInfo // always the local
	*noise.HandshakeState

	HandshakeStateResponsibility bool
	handshakeHash                []byte

	send, recv *noise.CipherState

	readMsgBuf  []byte
	writeMsgBuf []byte
	readBuf     []byte
}

var (
	ex_ns   net.Conn       = &NoiseConn{}
	ex_ns_l net.Listener   = &NoiseListener{}
	ex_ns_u net.PacketConn = &NoisePacketConn{}
)

// NewNoise creates a new Noise-based transport with only the config for our side of the connection.
// It accepts a RouterInfo which should always be our own RouterInfo.
func NewNoise(ri router_info.RouterInfo) (ns *Noise, err error) {
	ns = &Noise{}
	ns.RouterInfo = ri
	// sk, err := ra.StaticKey()
	if err != nil {
		return nil, err
	}
	ns.Config = noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXK,
		// StaticKeypair: ,
		// StaticKeypair: ,
		// EphemeralKeypair: ,
	}
	return
}

func (ns *Noise) LocalAddr() net.Addr {
	return &ns.RouterInfo
}

func (ns *Noise) Addr() net.Addr {
	return ns.LocalAddr()
}

// MatchAddr finds a transport suitable for an incoming RouterAddress
func (ns *Noise) MatchAddr(addr net.Addr) (*router_address.RouterAddress, error) {
	for index, address := range ns.RouterInfo.RouterAddresses() {
		log.Println("index", index, "address", address)
		if addr.Network() == address.Network() {
			return address, nil
		}
	}
	return nil, fmt.Errorf("no suitable address found for type %s from %s", addr.Network(), addr.String())
}

func dialWrapper(network, address string) (net.Conn, error) {
	switch network {
	case "SSU24":
		return net.Dial("udp4", address)
	case "SSU26":
		return net.Dial("udp6", address)
	case "NTCP2":
		return net.Dial("tcp", address)
	case "NTCP24":
		return net.Dial("tcp4", address)
	case "NTCP26":
		return net.Dial("tcp6", address)
	case "NTCP4":
		return net.Dial("tcp4", address)
	case "NTCP6":
		return net.Dial("tcp6", address)
	default:
		return nil, fmt.Errorf("unknown transport, cannot dial %s", network)
	}
}

func (ns Noise) DialNoise(addr router_address.RouterAddress) (net.Conn, error) {
	cfg := ns
	cfg.Initiator = false
	network := addr.Network()
	host, err := addr.Host()
	if err != nil {
		return nil, fmt.Errorf("host error: %s", err)
	}
	port, err := addr.Port()
	if err != nil {
		return nil, fmt.Errorf("port error: %s", err)
	}
	raddr := net.JoinHostPort(host.String(), port)
	var netConn net.Conn
	netConn, err = dialWrapper(network, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial error: %s", err)
	}
	cfg.HandshakeState, err = noise.NewHandshakeState(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("handshake state initialization error: %s", err)
	}
	laddr, err := ns.MatchAddr(&addr)
	if err != nil {
		return nil, fmt.Errorf("transport mismatch error %s", err)
	}
	// cfg.Config.PeerEphemeral, err = AESDeObfuscateEphemeralKeys()
	return &NoiseConn{
		Noise: cfg,
		Conn:  netConn,
		raddr: addr,
		laddr: *laddr,
	}, nil
}

func (ns Noise) ListenNoise(addr router_address.RouterAddress) (list NoiseListener, err error) {
	cfg := ns
	cfg.Initiator = false
	network := "tcp"
	host, err := addr.Host()
	if err != nil {
		return
	}
	port, err := addr.Port()
	if err != nil {
		return
	}
	portNum, _ := strconv.Atoi(port)
	port = strconv.Itoa(portNum + 1)
	hostip := net.JoinHostPort(host.String(), port)
	listener, err := net.Listen(network, hostip)
	if err != nil {
		return
	}
	return NoiseListener{
		Noise:    cfg,
		Listener: listener,
	}, nil
}
