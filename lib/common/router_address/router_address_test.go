package router_address

import (
	"bytes"
	"testing"

	. "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/stretchr/testify/assert"
)

/*
func TestCheckValidReportsEmptySlice(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{})

	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing RouterAddress: no data", "correct error message should be returned")
	}
	err, exit := router_address.checkValid()
	assert.Equal(exit, true, "checkValid did not indicate to stop parsing on empty slice")
}

func TestCheckRouterAddressValidReportsDataMissing(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{0x01})

	if assert.NotNil(err) {
		assert.Equal(err.Error(), "warning parsing RouterAddress: data too small", "correct error message should be returned")
	}

	err, exit := router_address.checkValid()
	assert.Equal(exit, false, "checkValid indicates to stop parsing when some fields  may be present")
}

*/

func TestCheckRouterAddressValidNoErrWithValidData(t *testing.T) {
	assert := assert.New(t)

	router_address, _, _ := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	mapping, err := GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	assert.Nil(err, "GoMapToMapping() returned error with valid data")
	router_address.TransportOptions = mapping
	// router_address = append(router_address, mapping...)
	err, exit := router_address.checkValid()

	assert.Nil(err, "checkValid() reported error with valid data")
	assert.Equal(exit, false, "checkValid() indicated to stop parsing valid data")
}

func TestRouterAddressCostReturnsFirstByte(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	cost := router_address.Cost()

	assert.Nil(err, "Cost() returned error with valid data")
	assert.Equal(cost, 6, "Cost() returned wrong cost")
}

func TestRouterAddressExpirationReturnsCorrectData(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00})
	expiration := router_address.Expiration()

	assert.Nil(err, "Expiration() returned error with valid data")
	if bytes.Compare(expiration[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) != 0 {
		t.Fatal("Expiration did not return correct data:", expiration)
	}
}

func TestReadRouterAddressReturnsCorrectRemainderWithoutError(t *testing.T) {
	assert := assert.New(t)

	router_address_bytes := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	str, _ := ToI2PString("foo")
	mapping, _ := GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	router_address_bytes = append(router_address_bytes, []byte(str)...)
	router_address_bytes = append(router_address_bytes, mapping.Data()...)
	router_address_bytes = append(router_address_bytes, []byte{0x01, 0x02, 0x03}...)
	router_address, remainder, err := ReadRouterAddress(router_address_bytes)

	assert.Nil(err, "ReadRouterAddress() reported error with valid data:")
	assert.Equal(0, bytes.Compare(remainder, []byte{0x01, 0x02, 0x03}))

	err, exit := router_address.checkValid()
	assert.Nil(err, "checkValid() on address from ReadRouterAddress() reported error with valid data")
	assert.Equal(exit, false, "checkValid() on address from ReadRouterAddress() indicated to stop parsing valid data")
}

func TestCorrectsFuzzCrasher1(t *testing.T) {
	assert := assert.New(t)

	defer func() {
		if r := recover(); r != nil {
			assert.Equal(nil, r)
		}
	}()

	router_address_bytes := []byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x30, 0x30}
	ReadRouterAddress(router_address_bytes)
}
