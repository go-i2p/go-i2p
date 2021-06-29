package common

/*
I2P Integer
https://geti2p.net/spec/common-structures#integer
Accurate for version 0.9.24
*/

import (
	"encoding/binary"
	//	log "github.com/sirupsen/logrus"
	//	"errors"
)

// Total byte length of an I2P integer
const (
	INTEGER_SIZE = 8
)

type Integer []byte

func (i Integer) longBytes() (value [INTEGER_SIZE]byte) {
	value = [INTEGER_SIZE]byte{0, 0, 0, 0, 0, 0, 0, 0}
	for index, element := range []byte(i) {
		value[INTEGER_SIZE-1-index] = element
	}
	return value
}

func (i Integer) Value() int {
	r := i.longBytes()
	return int(binary.BigEndian.Uint64(r[:]))
	//	return int(binary.BigEndian.Int64(r[:]))
}

func (i Integer) Bytes() []byte {
	if len([]byte(i)) == 0 {
		return []byte{0}
	}
	r := []byte(i)
	return r
}

//
// Interpret a slice of bytes from length 0 to length 8 as a big-endian
// integer and return an int representation.
//
func NewInteger(number []byte) (value Integer, err error) {
	value = number //[INTEGER_SIZE]byte(number)
	//	for index, element := range number {
	//		value[INTEGER_SIZE-1-index] = element
	//	}
	/*length := len(number)
	if length < INTEGER_SIZE {
		log.WithFields(log.Fields{
			"at":           "(Integer) NewInteger",
			"length":     length,
			"required_len": INTEGER_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing Integer")
		err = errors.New("error parsing Integer, not enough data")
	}else if length > INTEGER_SIZE{
		log.WithFields(log.Fields{
			"at":           "(Integer) NewInteger",
			"length":     length,
			"required_len": INTEGER_SIZE,
			"reason":       "too much data",
		}).Error("error parsing Integer")
		err = errors.New("error parsing Integer, too much data")
	}else{
			err = nil
	}*/
	return
}
