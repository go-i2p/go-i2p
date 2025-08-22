package i2np

import (
	"github.com/samber/oops"
)

// I2NP Message Type Constants
// Moved from: header.go
const (
	I2NP_MESSAGE_TYPE_DATABASE_STORE              = 1
	I2NP_MESSAGE_TYPE_DATABASE_LOOKUP             = 2
	I2NP_MESSAGE_TYPE_DATABASE_SEARCH_REPLY       = 3
	I2NP_MESSAGE_TYPE_DELIVERY_STATUS             = 10
	I2NP_MESSAGE_TYPE_GARLIC                      = 11
	I2NP_MESSAGE_TYPE_TUNNEL_DATA                 = 18
	I2NP_MESSAGE_TYPE_TUNNEL_GATEWAY              = 19
	I2NP_MESSAGE_TYPE_DATA                        = 20
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD                = 21
	I2NP_MESSAGE_TYPE_TUNNEL_BUILD_REPLY          = 22
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD       = 23
	I2NP_MESSAGE_TYPE_VARIABLE_TUNNEL_BUILD_REPLY = 24
)

// I2NP Error Constants
// Moved from: header.go, build_request_record.go, build_response_record.go, database_lookup.go
var (
	ERR_I2NP_NOT_ENOUGH_DATA                  = oops.Errorf("not enough i2np header data")
	ERR_BUILD_REQUEST_RECORD_NOT_ENOUGH_DATA  = oops.Errorf("not enough i2np build request record data")
	ERR_BUILD_RESPONSE_RECORD_NOT_ENOUGH_DATA = oops.Errorf("not enough i2np build request record data")
	ERR_DATABASE_LOOKUP_NOT_ENOUGH_DATA       = oops.Errorf("not enough i2np database lookup data")
)
