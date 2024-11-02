test-router-info-all: test-router-info-published test-router-info-addresses test-router-info-identity test-router-info-misc

test-router-info-published:
	go test -v ./lib/common/router_info -run TestPublishedReturnsCorrectDate
	go test -v ./lib/common/router_info -run TestPublishedReturnsCorrectErrorWithPartialDate
	go test -v ./lib/common/router_info -run TestPublishedReturnsCorrectErrorWithInvalidData

test-router-info-addresses:
	go test -v ./lib/common/router_info -run TestRouterAddressCountReturnsCorrectCount
	go test -v ./lib/common/router_info -run TestRouterAddressCountReturnsCorrectErrorWithInvalidData
	go test -v ./lib/common/router_info -run TestRouterAddressesReturnsAddresses
	go test -v ./lib/common/router_info -run TestRouterAddressesReturnsAddressesWithMultiple

test-router-info-identity:
	go test -v ./lib/common/router_info -run TestRouterIdentityIsCorrect

test-router-info-misc:
	go test -v ./lib/common/router_info -run TestPeerSizeIsZero
	go test -v ./lib/common/router_info -run TestOptionsAreCorrect
	go test -v ./lib/common/router_info -run TestSignatureIsCorrectSize

.PHONY: test-router-info-all \
        test-router-info-published \
        test-router-info-addresses \
        test-router-info-identity \
        test-router-info-misc
