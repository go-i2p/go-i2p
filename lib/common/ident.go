package common

/*
I2P Tunnel Identity Helpers
https://geti2p.net/spec/common-structures#ident
Accurate for version 0.9.24
*/

import (
	"errors"
	log "github.com/sirupsen/logrus"
)

type Ident [4]byte

const IDENT_SIZE = 4

func ReadIdent(data []byte) (h Ident, remainder []byte, err error) {
	if len(data) < IDENT_SIZE {
		log.WithFields(log.Fields{
			"at":           "(Ident) ReadIdent",
			"data_len":     len(data),
			"required_len": "8",
			"reason":       "ident missing data",
		}).Error("ident error")
		err = errors.New("error reading ident, insufficient length")
		copy(h[:], data[0:len(data)-1])
	}else{
		copy(h[:], data[0:IDENT_SIZE-1])
		copy(remainder, data[IDENT_SIZE-1:])
	}
	return
}