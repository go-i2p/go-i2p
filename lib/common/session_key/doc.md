# session_key
--
    import "github.com/go-i2p/go-i2p/lib/common/session_key"

Package session_key implements the I2P SessionKey common data structure

## Usage

#### type SessionKey

```go
type SessionKey [32]byte
```

SessionKey is the represenation of an I2P SessionKey.

https://geti2p.net/spec/common-structures#sessionkey

#### func  NewSessionKey

```go
func NewSessionKey(data []byte) (session_key *SessionKey, remainder []byte, err error)
```
NewSessionKey creates a new *SessionKey from []byte using ReadSessionKey.
Returns a pointer to SessionKey unlike ReadSessionKey.

#### func  ReadSessionKey

```go
func ReadSessionKey(bytes []byte) (info SessionKey, remainder []byte, err error)
```
ReadSessionKey returns SessionKey from a []byte. The remaining bytes after the
specified length are also returned. Returns a list of errors that occurred
during parsing.
