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
	go func() {
		for {
			conn, err := nt.Accept()
			if err != nil {
				t.Log(err)
			}
			_, err = conn.Write([]byte("World"))
			if err != nil {
				t.Error(err)
			}
		}
	}()
	lnn, err := net.Listen("tcp", ":42070")
	if err != nil {
		t.Error(err)
	}
	ntt := NewNoiseTransport(lnn)
	t.Log(ntt.Name())
	// ntt.GetSession()
}
