# ntcp
--
    import "github.com/go-i2p/go-i2p/lib/transport/messages"


## Usage

```go
const (
	MessageTypeSessionRequest   = 0x00
	MessageTypeSessionCreated   = 0x01
	MessageTypeSessionConfirmed = 0x02
	MessageTypeData             = 0x03
)
```

#### type Message

```go
type Message interface {
	// Type returns the message type
	Type() MessageType
	// Payload returns the message payload
	Payload() []byte
	// PayloadSize returns the message payload size
	PayloadSize() int
}
```


#### type MessageType

```go
type MessageType uint8
```


#### type SessionRequest

```go
type SessionRequest struct {
	XContent []byte // 32-byte X value

	Padding []byte // padding of message 1
}
```


#### func (*SessionRequest) Payload

```go
func (sr *SessionRequest) Payload() []byte
```
Payload returns the message payload

#### func (*SessionRequest) PayloadSize

```go
func (sr *SessionRequest) PayloadSize() int
```
PayloadSize returns the message payload size

#### func (*SessionRequest) Type

```go
func (sr *SessionRequest) Type() MessageType
```
Type returns the message type
