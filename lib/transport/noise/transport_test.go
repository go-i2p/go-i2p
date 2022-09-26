package noise

import (
	"net"
	"testing"
)

func TestTransport(t *testing.T) {
	ln, err := net.Listen("tcp", ":42069")
	if err != nil {
		t.Error(err)
	}
	nt := NewNoiseTransport(ln)
	t.Log(nt.Name())
}
