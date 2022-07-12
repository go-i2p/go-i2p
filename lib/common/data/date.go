package data

/*
I2P Date
https://geti2p.net/spec/common-structures#date
Accurate for version 0.9.24
*/

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
)

const DATE_SIZE = 8

type Date [8]byte

//
// Time takes the value stored in date as an 8 byte big-endian integer representing the
// number of milliseconds since the beginning of unix time and converts it to a Go time.Time
// struct.
//
func (date Date) Time() (date_time time.Time) {
	seconds := Integer(date[:])
	date_time = time.Unix(0, int64(seconds.Int()*1000000))
	return
}

func ReadDate(data []byte) (date Date, remainder []byte, err error) {
	if len(data) < 8 {
		log.WithFields(log.Fields{
			"data": data,
		}).Error("ReadDate: data is too short")
		err = errors.New("ReadDate: data is too short")
		return
	}
	copy(date[:], data[:8])
	remainder = data[8:]
	return
}

func NewDate(data []byte) (date *Date, remainder []byte, err error) {
	objdate, remainder, err := ReadDate(data)
	date = &objdate
	return
}
