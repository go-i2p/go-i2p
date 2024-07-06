package noise

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-i2p/go-i2p/lib/common/router_info"
)

func TestEstablishment(t *testing.T) {
	//	assert := assert.New(t)

	if home, err := os.UserHomeDir(); err != nil {
		t.Error("ERROR", err)
	} else {
		riFile := filepath.Join(home, ".i2p", "router.info")
		if riBytes, err := os.ReadFile(riFile); err != nil {
			t.Error("ERROR", err)
		} else {
			if ri, rem, err := router_info.ReadRouterInfo(riBytes); err != nil {
				t.Error("ERROR", err)
			} else {
				if len(rem) != 0 {
					t.Error("ERROR", "Too much data", len(rem), string(rem))
				}
				ra := ri.RouterAddresses()[0]
				if ns, err := NewNoise(*ra); err != nil {
					t.Error("ERROR", err)
				} else {
					if host, err := ns.Host(); err != nil {
						t.Error("ERROR", err)
					} else {
						log.Println("NOISE TEST", host)
						if nl, err := ns.ListenNoise(); err != nil {
							t.Error("ERROR", err)
						} else {
							defer nl.Close()
						}
					}
				}
			}
		}
	}
	/*conn, err := ns.DialNoise()
	if err != nil {
		t.Error("ERROR", err)
	}
	log.Println("NOISE TEST")
	test := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AA")
	bytes, err := conn.Write(test)
	if err != nil {
		t.Error(err)
	}
	log.Println("NOISE TEST")
	log.Print(bytes)*/
}
