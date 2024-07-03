package noise

import (
	"log"
	"strconv"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
)

func TestEstablishment(t *testing.T) {
	//	assert := assert.New(t)
	log.Println("NOISE TEST")
	i, err := data.NewIntegerFromInt(1, 1)
	if err != nil {
		t.Error(err)
	}
	unixDate := time.Now().UnixMilli() + time.Minute.Milliseconds()
	strDate := strconv.Itoa(int(unixDate))
	d, r, e := data.ReadDate([]byte(strDate))
	if e != nil {
		t.Error(e)
	}else if len(r) != 0 {
		log.Println("r should not be longer than 0")
	}
	trans, err := data.ToI2PString("NTCP2")
	if err != nil {
		t.Error(err)
	}
	ra := router_address.RouterAddress{
		TransportCost: i,
		ExpirationDate: &d,
		TransportType: &trans,
		TransportOptions: nil,
	}
	ns, err := NewNoise(ra)
	if err != nil {
		t.Error("ERROR", err)
	}
	log.Println("NOISE TEST")
	conn, err := ns.DialNoise("tcp", "[2604:a880:cad:d0::d2d:7001]:14433")
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
	log.Print(bytes)

}
