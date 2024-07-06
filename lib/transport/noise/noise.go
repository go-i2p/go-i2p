package noise

import (
	"net"
	"sync"

	"github.com/flynn/noise"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
)

// wrapper around flynn/noise with just enough options exposed to enable configuring NTCP2

type Noise struct {
	noise.Config
	router_address.RouterAddress // always the local addr
	*noise.HandshakeState
	sync.Mutex

	HandshakeStateResponsibility bool
	handshakeHash                []byte

	lock       bool
	send, recv *noise.CipherState

	readMsgBuf  []byte
	writeMsgBuf []byte
	readBuf     []byte
}

func (ns *Noise) unlockMutex() {
	if ns.lock {
		ns.lock = false
		ns.Mutex.Unlock()
	}
}

func (ns *Noise) lockMutex() {
	if !ns.lock {
		ns.lock = true
		ns.Mutex.Lock()
	}
}

var ex_ns net.Conn = &NoiseConn{}
var ex_ns_l net.Listener = &NoiseListener{}
var ex_ns_u net.PacketConn = &NoisePacketConn{}
//var ex_tc_up net.PacketConn = &NoiseConn{}

func NewNoise(ra router_address.RouterAddress) (ns *Noise, err error) {
	ns = &Noise{}
	ns.RouterAddress = ra
	ns.Config = noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXK,
		//StaticKeypair: ,
		//EphemeralKeypair: ,
	}
	return
}

func (ns *Noise) LocalAddr() net.Addr {
	return &ns.RouterAddress
}

func (ns *Noise) Addr() net.Addr {
	return ns.LocalAddr()
}

func (ns *Noise) DialNoise(addr router_address.RouterAddress) (conn NoiseConn, err error) {
	cfg := ns
	cfg.Initiator = false
	network := "tcp"
	if ns.UDP() {
		network = "udp"
	}
	host, err := ns.RouterAddress.Host()
	if err != nil {
		return
	}
	port, err := ns.RouterAddress.Port()
	if err != nil {
		return
	}
	raddr := net.JoinHostPort(host.String(), port)
	netConn, err := net.Dial(network, raddr)
	if err != nil {
		return
	}
	hs, err := noise.NewHandshakeState(cfg.Config)
	if err != nil {
		return
	}
	cfg.HandshakeState = hs
	return NoiseConn{
		Noise: cfg,
		Conn:  netConn,
	}, nil
}

func (ns *Noise) ListenNoise() (list NoiseListener, err error) {
	cfg := ns
	cfg.Initiator = false
	network := "tcp"
	host, err := ns.Host()
	if err != nil {
		return
	}
	port, err := ns.Port()
	if err != nil {
		return
	}
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
