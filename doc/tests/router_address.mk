test-router-address-all: test-router-address-validation test-router-address-functionality test-router-address-fuzz

test-router-address-validation:
	go test -v ./lib/common/router_address -run TestCheckValidReportsEmptySlice
	go test -v ./lib/common/router_address -run TestCheckRouterAddressValidReportsDataMissing
	go test -v ./lib/common/router_address -run TestCheckRouterAddressValidNoErrWithValidData

test-router-address-functionality:
	go test -v ./lib/common/router_address -run TestRouterAddressCostReturnsFirstByte
	go test -v ./lib/common/router_address -run TestRouterAddressExpirationReturnsCorrectData
	go test -v ./lib/common/router_address -run TestReadRouterAddressReturnsCorrectRemainderWithoutError

test-router-address-fuzz:
	go test -v ./lib/common/router_address -run TestCorrectsFuzzCrasher1

.PHONY: test-router-address-all \
        test-router-address-validation \
        test-router-address-functionality \
        test-router-address-fuzz