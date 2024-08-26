# ntcp
--
    import "github.com/go-i2p/go-i2p/lib/transport/ntcp"


## Usage

```go
const (
	NTCP_PROTOCOL_VERSION = 2
	NTCP_PROTOCOL_NAME    = "NTCP2"
	NTCP_MESSAGE_MAX_SIZE = 65537
)
```

#### type Session

```go
type Session struct{}
```

Session implements TransportSession An established transport session

#### type Transport

```go
type Transport struct{}
```

Transport is an ntcp transport implementing transport.Transport interface
