package common

/*
I2P Date
https://geti2p.net/spec/common-structures#date
Accurate for version 0.9.24
*/

import (
	"time"
	"errors"
	log "github.com/sirupsen/logrus"
)

type Date [8]byte

const DATE_SIZE = 8

//
// Time takes the value stored in date as an 8 byte big-endian integer representing the
// number of milliseconds since the beginning of unix time and converts it to a Go time.Time
// struct.
//
func (date Date) Time() (date_time time.Time) {
	seconds := Integer(date[:])
	date_time = time.Unix(0, int64(seconds*1000000))
	return
}

func ReadDate(data []byte) (h Date, remainder []byte, err error) {
	if len(data) < DATE_SIZE {
		log.WithFields(log.Fields{
			"at":           "(Date) ReadDate",
			"data_len":     len(data),
			"required_len": "8",
			"reason":       "date missing data",
		}).Error("date error")
		err = errors.New("error reading date, insufficient length")
		copy(h[:], data[0:len(data)-1])
	}else{
		copy(h[:], data[0:DATE_SIZE-1])
		copy(remainder, data[DATE_SIZE-1:])
	}
	return
}