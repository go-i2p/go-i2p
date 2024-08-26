# session_tag
--
    import "github.com/go-i2p/go-i2p/lib/common/session_tag"

Package session_tag implements the I2P SessionTag common data structure

## Usage

#### type SessionTag

```go
type SessionTag [32]byte
```

SessionTag is the represenation of an I2P SessionTag.

https://geti2p.net/spec/common-structures#session-tag

#### func  NewSessionTag

```go
func NewSessionTag(data []byte) (session_tag *SessionTag, remainder []byte, err error)
```
NewSessionTag creates a new *SessionTag from []byte using ReadSessionTag.
Returns a pointer to SessionTag unlike ReadSessionTag.

#### func  ReadSessionTag

```go
func ReadSessionTag(bytes []byte) (info SessionTag, remainder []byte, err error)
```
ReadSessionTag returns SessionTag from a []byte. The remaining bytes after the
specified length are also returned. Returns a list of errors that occurred
during parsing.
