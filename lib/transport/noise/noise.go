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
	*noise.HandshakeState
	sync.Mutex
	router_address.RouterAddress // always the local addr
	lock                         bool
	send, recv                   *noise.CipherState
}

var ex_ns net.Conn = &NoiseConn{}
var ex_ns_l net.Listener = &NoiseListener{}
var ex_ns_u net.PacketConn = &NoisePacketConn{}

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

func NewNoise(ra router_address.RouterAddress) (ns *Noise, err error) {
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

