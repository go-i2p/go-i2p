# noise
--
    import "github.com/go-i2p/go-i2p/lib/transport/noise"


## Usage

```go
const FlushLimit = 640 * 1024
```

#### type Noise

```go
type Noise struct {
	noise.Config
	router_address.RouterAddress // always the local addr
	*noise.HandshakeState
	sync.Mutex

	HandshakeStateResponsibility bool
}
```

wrapper around flynn/noise with just enough options exposed to enable
configuring NTCP2 possible and/or relatively intuitive

#### func  NewNoise

```go
func NewNoise(ra router_address.RouterAddress) (ns *Noise, err error)
```

#### func (*Noise) Addr

```go
func (ns *Noise) Addr() net.Addr
```

#### func (*Noise) DialNoise

```go
func (ns *Noise) DialNoise(addr router_address.RouterAddress) (conn net.Conn, err error)
```

#### func (*Noise) ListenNoise

```go
func (ns *Noise) ListenNoise() (list NoiseListener, err error)
```

#### func (*Noise) LocalAddr

```go
func (ns *Noise) LocalAddr() net.Addr
```

#### type NoiseConn

```go
type NoiseConn struct {
	*Noise
	net.Conn
}
```


#### func (*NoiseConn) Close

```go
func (nc *NoiseConn) Close() error
```
Close implements net.Conn.

#### func (*NoiseConn) Frame

```go
func (nc *NoiseConn) Frame(header, body []byte) (err error)
```

#### func (*NoiseConn) HandshakeStateCreate

```go
func (nc *NoiseConn) HandshakeStateCreate(out, payload []byte) (by []byte, err error)
```

#### func (*NoiseConn) HandshakeStateRead

```go
func (nc *NoiseConn) HandshakeStateRead() (err error)
```
HandshakeStateRead reads a handshake's state off the socket for storage in the
NoiseConn.HandshakeState

#### func (*NoiseConn) LocalAddr

```go
func (nc *NoiseConn) LocalAddr() net.Addr
```
LocalAddr implements net.Conn.

#### func (*NoiseConn) Read

```go
func (nc *NoiseConn) Read(b []byte) (n int, err error)
```
Read implements net.Conn.

#### func (*NoiseConn) ReadMsg

```go
func (nc *NoiseConn) ReadMsg(b []byte) (by []byte, err error)
```

#### func (*NoiseConn) RemoteAddr

```go
func (nc *NoiseConn) RemoteAddr() net.Addr
```
RemoteAddr implements net.Conn.

#### func (*NoiseConn) SetCipherStates

```go
func (nc *NoiseConn) SetCipherStates(cs1, cs2 *noise.CipherState)
```

#### func (*NoiseConn) SetDeadline

```go
func (nc *NoiseConn) SetDeadline(t time.Time) error
```
SetDeadline implements net.Conn.

#### func (*NoiseConn) SetReadDeadline

```go
func (nc *NoiseConn) SetReadDeadline(t time.Time) error
```
SetReadDeadline implements net.Conn.

#### func (*NoiseConn) SetWriteDeadline

```go
func (nc *NoiseConn) SetWriteDeadline(t time.Time) error
```
SetWriteDeadline implements net.Conn.

#### func (*NoiseConn) Write

```go
func (nc *NoiseConn) Write(b []byte) (n int, err error)
```
Write implements net.Conn.

#### type NoiseListener

```go
type NoiseListener struct {
	*Noise
	net.Listener
}
```


#### func (*NoiseListener) Accept

```go
func (ns *NoiseListener) Accept() (net.Conn, error)
```
Accept implements net.Listener.

#### func (*NoiseListener) Addr

```go
func (ns *NoiseListener) Addr() net.Addr
```
Addr implements net.Listener.

#### func (*NoiseListener) Close

```go
func (ns *NoiseListener) Close() error
```
Close implements net.Listener.

#### type NoisePacketConn

```go
type NoisePacketConn struct {
	*Noise
	// this is always a actually a PacketConn
	net.Conn
}
```


#### func (*NoisePacketConn) Close

```go
func (n *NoisePacketConn) Close() error
```
Close implements net.PacketConn. Subtle: this method shadows the method
(Conn).Close of NoisePacketConn.Conn.

#### func (*NoisePacketConn) LocalAddr

```go
func (n *NoisePacketConn) LocalAddr() net.Addr
```
LocalAddr implements net.PacketConn.

#### func (*NoisePacketConn) Read

```go
func (*NoisePacketConn) Read(b []byte) (n int, err error)
```
Read implements net.Conn.

#### func (*NoisePacketConn) ReadFrom

```go
func (*NoisePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error)
```
ReadFrom implements net.PacketConn.

#### func (*NoisePacketConn) RemoteAddr

```go
func (n *NoisePacketConn) RemoteAddr() net.Addr
```
RemoteAddr implements net.Conn.

#### func (*NoisePacketConn) SetDeadline

```go
func (n *NoisePacketConn) SetDeadline(t time.Time) error
```
SetDeadline implements net.PacketConn. Subtle: this method shadows the method
(PacketConn).SetDeadline of NoisePacketConn.PacketConn.

#### func (*NoisePacketConn) SetReadDeadline

```go
func (n *NoisePacketConn) SetReadDeadline(t time.Time) error
```
SetReadDeadline implements net.PacketConn. Subtle: this method shadows the
method (PacketConn).SetReadDeadline of NoisePacketConn.PacketConn.

#### func (*NoisePacketConn) SetWriteDeadline

```go
func (n *NoisePacketConn) SetWriteDeadline(t time.Time) error
```
SetWriteDeadline implements net.PacketConn. Subtle: this method shadows the
method (PacketConn).SetWriteDeadline of NoisePacketConn.PacketConn.

#### func (*NoisePacketConn) Write

```go
func (*NoisePacketConn) Write(b []byte) (n int, err error)
```
Write implements net.Conn.

#### func (*NoisePacketConn) WriteTo

```go
func (*NoisePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error)
```
WriteTo implements net.PacketConn.
