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
				log.Println(ri.String(), rem)
				if ns, err := NewNoise(ri); err != nil {
					t.Error("ERROR", err)
				} else {
					host := ns.LocalAddr()
					log.Println("NOISE TEST", host)
					if nl, err := ns.DialNoise(*ri.RouterAddresses()[0]); err != nil {
						t.Error("ERROR", err)
					} else {
						defer nl.Close()
					}
				}
			}
		}
	}
}
