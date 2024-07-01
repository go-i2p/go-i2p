package noise

import (
	"net"
	"sync"

	"github.com/flynn/noise"
)

// wrapper around flynn/noise with just enough options exposed to enable configuring NTCP2

type Noise struct {
	noise.Config
	*noise.HandshakeState
	sync.Mutex
	lock bool
	send, recv       *noise.CipherState
}

func NewNoise() (ns Noise, err error){
	ns.Config = noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern: noise.HandshakeXK,
		//StaticKeypair: ,
		//EphemeralKeypair: ,
	}
	return
}

func (ns *Noise) unlockMutex() {
	if (ns.lock){
		ns.lock = false
		ns.Mutex.Unlock()
	}
}

func (ns *Noise) lockMutex() {
	if (!ns.lock) {
		ns.lock = true
		ns.Mutex.Lock()
	}
}

func (ns *Noise) Dial(n, addr string) (conn net.Conn, err error) {
	ns.Config.Initiator = true
	ns.HandshakeState, err = noise.NewHandshakeState(ns.Config)
	if err != nil {
		return
	}
	conn, err = net.Dial(n, addr)
	if err != nil {
		return
	}
	return
}

func (ns *Noise) Listen(n, addr string) (list net.Listener, err error) {
	ns.Config.Initiator = false
	list, err = net.Listen(n, addr)
	if err != nil {
		return
	}
	return
}
