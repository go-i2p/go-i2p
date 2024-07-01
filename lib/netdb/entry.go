package netdb

import (
	"io"

	"github.com/go-i2p/go-i2p/lib/common/lease_set"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
)

// netdb entry
// wraps a router info and provides serialization
type Entry struct {
	ri router_info.RouterInfo
	ls lease_set.LeaseSet
}

func (e *Entry) WriteTo(w io.Writer) (err error) {
	return
}

func (e *Entry) ReadFrom(r io.Reader) (err error) {
	return
}
