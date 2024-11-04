test-router-info-all: test-router-info-published test-router-info-addresses test-router-info-identity test-router-info-misc

test-router-info-published:
	$(GO) test -v ./lib/common/router_info -run TestPublishedReturnsCorrectDate
	$(GO) test -v ./lib/common/router_info -run TestPublishedReturnsCorrectErrorWithPartialDate
	$(GO) test -v ./lib/common/router_info -run TestPublishedReturnsCorrectErrorWithInvalidData

test-router-info-addresses:
	$(GO) test -v ./lib/common/router_info -run TestRouterAddressCountReturnsCorrectCount
	$(GO) test -v ./lib/common/router_info -run TestRouterAddressCountReturnsCorrectErrorWithInvalidData
	$(GO) test -v ./lib/common/router_info -run TestRouterAddressesReturnsAddresses
	$(GO) test -v ./lib/common/router_info -run TestRouterAddressesReturnsAddressesWithMultiple

test-router-info-identity:
	$(GO) test -v ./lib/common/router_info -run TestRouterIdentityIsCorrect

test-router-info-misc:
	$(GO) test -v ./lib/common/router_info -run TestPeerSizeIsZero
	$(GO) test -v ./lib/common/router_info -run TestOptionsAreCorrect
	$(GO) test -v ./lib/common/router_info -run TestSignatureIsCorrectSize

.PHONY: test-router-info-all \
        test-router-info-published \
        test-router-info-addresses \
        test-router-info-identity \
        test-router-info-misc
