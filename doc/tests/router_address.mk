test-router-address-all: test-router-address-validation test-router-address-functionality test-router-address-fuzz

test-router-address-validation:
	$(GO) test -v ./lib/common/router_address -run TestCheckValidReportsEmptySlice
	$(GO) test -v ./lib/common/router_address -run TestCheckRouterAddressValidReportsDataMissing
	$(GO) test -v ./lib/common/router_address -run TestCheckRouterAddressValidNoErrWithValidData

test-router-address-functionality:
	$(GO) test -v ./lib/common/router_address -run TestRouterAddressCostReturnsFirstByte
	$(GO) test -v ./lib/common/router_address -run TestRouterAddressExpirationReturnsCorrectData
	$(GO) test -v ./lib/common/router_address -run TestReadRouterAddressReturnsCorrectRemainderWithoutError

test-router-address-fuzz:
	$(GO) test -v ./lib/common/router_address -run TestCorrectsFuzzCrasher1

.PHONY: test-router-address-all \
        test-router-address-validation \
        test-router-address-functionality \
        test-router-address-fuzz