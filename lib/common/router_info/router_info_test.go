package router_info

import (
	"bytes"
	"fmt"
	"testing"

	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_address"
	"github.com/go-i2p/go-i2p/lib/common/router_identity"
	"github.com/stretchr/testify/assert"
)

func buildRouterIdentity() router_identity.RouterIdentity {
	router_ident_data := make([]byte, 128+256)
	router_ident_data = append(router_ident_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	return_data, _, _ := router_identity.ReadRouterIdentity(router_ident_data)
	return return_data
}

func buildDate() []byte {
	date_data := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
	return date_data
}

func buildMapping() *common.Mapping {
	mapping, _ := common.GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	return mapping
}

func buildRouterAddress(transport string) router_address.RouterAddress {
	router_address_bytes := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	str, _ := common.ToI2PString(transport)
	router_address_bytes = append(router_address_bytes, []byte(str)...)
	router_address_bytes = append(router_address_bytes, buildMapping().Data()...)
	return_data, _, _ := router_address.ReadRouterAddress(router_address_bytes)
	return return_data
}

func buildFullRouterInfo(rid ...[]byte) (RouterInfo, error) {
	var ri RouterInfo
	var err error
	if rid == nil || len(rid) == 0 {
		router_info_data := make([]byte, 0)
		router_info_data = append(router_info_data, buildRouterIdentity().KeysAndCert.Bytes()...)
		router_info_data = append(router_info_data, buildDate()...)
		router_info_data = append(router_info_data, 0x01)
		router_info_data = append(router_info_data, buildRouterAddress("foo").Bytes()...)
		router_info_data = append(router_info_data, 0x00)
		router_info_data = append(router_info_data, buildMapping().Data()...)
		router_info_data = append(router_info_data, make([]byte, 40)...)
		ri, _, err = ReadRouterInfo(router_info_data)
	} else {
		ri, _, err = ReadRouterInfo(rid[0])
	}
	return ri, err
}

func TestPublishedReturnsCorrectDate(t *testing.T) {
	assert := assert.New(t)

	router_info, _ := buildFullRouterInfo()
	date := router_info.Published()
	assert.Equal(int64(86400), date.Time().Unix(), "RouterInfo.Published() did not return correct date")
}

func TestPublishedReturnsCorrectErrorWithPartialDate(t *testing.T) {
	assert := assert.New(t)

	router_info, err := buildFullRouterInfo()
	assert.Nil(err)
	bytes, err := router_info.Bytes()
	router_info, err = buildFullRouterInfo(bytes[:387+4])
	//_ := router_info.Published()
	if assert.NotNil(err) {
		assert.Equal("error parsing date: not enough data", err.Error())
	}
}

func TestPublishedReturnsCorrectErrorWithInvalidData(t *testing.T) {
	assert := assert.New(t)

	router_info, err := buildFullRouterInfo()
	if assert.Nil(err) {
		bytes, err := router_info.Bytes()
		router_info, err = buildFullRouterInfo(bytes[:56])
		if assert.NotNil(err) {
			assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
		}
	} else {
		assert.Fail("error building router info")
	}
}

func TestRouterAddressCountReturnsCorrectCount(t *testing.T) {
	assert := assert.New(t)

	router_info, _ := buildFullRouterInfo()
	count := router_info.RouterAddressCount()
	assert.Equal(1, count, "RouterInfo.RouterAddressCount() did not return correct count")
}

func TestRouterAddressCountReturnsCorrectErrorWithInvalidData(t *testing.T) {
	assert := assert.New(t)

	router_info, err := buildFullRouterInfo()
	if assert.Nil(err) {
		bytes, err := router_info.Bytes()
		router_info, err = buildFullRouterInfo(bytes[:387+8])

		count := router_info.RouterAddressCount()
		if assert.NotNil(err) {
			assert.Equal("error parsing router addresses: not enough data", err.Error())
		}
		assert.Equal(0, count)
	}
}

func TestRouterAddressesReturnsAddresses(t *testing.T) {
	assert := assert.New(t)

	router_info, err := buildFullRouterInfo()
	router_addresses := router_info.RouterAddresses()
	assert.Nil(err)
	if assert.Equal(1, len(router_addresses)) {
		assert.Equal(
			0,
			bytes.Compare(
				[]byte(buildRouterAddress("foo").Bytes()),
				[]byte(router_addresses[0].Bytes()),
			),
		)
	}

}

func TestRouterAddressesReturnsAddressesWithMultiple(t *testing.T) {
	assert := assert.New(t)

	router_info_data := make([]byte, 0)
	router_info_data = append(router_info_data, buildRouterIdentity().KeysAndCert.Bytes()...)
	router_info_data = append(router_info_data, buildDate()...)
	router_info_data = append(router_info_data, 0x03)
	router_info_data = append(router_info_data, buildRouterAddress("foo0").Bytes()...)
	router_info_data = append(router_info_data, buildRouterAddress("foo1").Bytes()...)
	router_info_data = append(router_info_data, buildRouterAddress("foo2").Bytes()...)
	router_info_data = append(router_info_data, 0x00)
	router_info_data = append(router_info_data, buildMapping().Data()...)
	router_info_data = append(router_info_data, make([]byte, 40)...)
	router_info, _, _ := ReadRouterInfo(router_info_data)

	count := router_info.RouterAddressCount()
	if assert.Equal(3, count) {
		router_addresses := router_info.RouterAddresses()
		for i := 0; i < 3; i++ {
			assert.Equal(
				0,
				bytes.Compare(
					[]byte(buildRouterAddress(fmt.Sprintf("foo%d", i)).Bytes()),
					[]byte(router_addresses[i].Bytes()),
				),
			)
		}
	}

}

func TestPeerSizeIsZero(t *testing.T) {
	assert := assert.New(t)

	router_info, _ := buildFullRouterInfo()
	size := router_info.PeerSize()
	assert.Equal(0, size, "RouterInfo.PeerSize() did not return 0")
}

func TestOptionsAreCorrect(t *testing.T) {
	assert := assert.New(t)

	router_info, _ := buildFullRouterInfo()
	options := router_info.Options()
	assert.Equal(
		0,
		bytes.Compare(
			[]byte(buildMapping().Data()),
			[]byte(options.Data()),
		),
	)
}

func TestSignatureIsCorrectSize(t *testing.T) {
	assert := assert.New(t)

	router_info, _ := buildFullRouterInfo()
	signature := router_info.Signature()
	assert.Equal(40, len(signature))
}

func TestRouterIdentityIsCorrect(t *testing.T) {
	assert := assert.New(t)

	router_info, _ := buildFullRouterInfo()
	router_identity := router_info.RouterIdentity()
	//assert.Nil(err)
	assert.Equal(
		0,
		bytes.Compare(
			[]byte(buildRouterIdentity().KeysAndCert.Bytes()),
			[]byte(router_identity.KeysAndCert.Bytes()),
		),
	)
}
