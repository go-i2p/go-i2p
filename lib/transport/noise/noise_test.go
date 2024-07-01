package noise

import (
	"log"
	"testing"
)

func TestEstablishment(t *testing.T) {
	//	assert := assert.New(t)
	log.Println("NOISE TEST")
	ns, err := NewNoise()
	if err != nil {
		t.Error("ERROR", err)
	}
	log.Println("NOISE TEST")
	conn, err := ns.Dial("tcp", "[2604:a880:cad:d0::d2d:7001]:14433")
	if err != nil {
		t.Error("ERROR", err)
	}
	log.Println("NOISE TEST")
	test := []byte("test-----------------------------------------------------------------------------------------------------------------------------------------------------------------test")
	bytes, err := conn.Write(test)
	if err != nil {
		t.Error(err)
	}
	log.Println("NOISE TEST")
	log.Print(bytes)


}
