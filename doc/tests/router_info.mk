test-router-info-all: test-router-info-creation test-router-info-published-date test-router-info-identity test-router-info-addresses test-router-info-serialization test-router-info-signature test-router-info-capabilities test-router-info-version test-router-info-good-version test-router-info-uncongested test-router-info-reachable test-router-info-10k

test-router-info-creation:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoCreation
	$(GO) test -v ./lib/common/router_info -run TestCreateRouterInfo

test-router-info-published-date:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoPublishedDate

test-router-info-identity:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoRouterIdentity

test-router-info-addresses:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoAddresses

test-router-info-serialization:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoSerialization

test-router-info-signature:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoSignature

test-router-info-capabilities:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoCapabilities

test-router-info-version:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoVersion

test-router-info-good-version:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoGoodVersion

test-router-info-uncongested:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoUnCongested

test-router-info-reachable:
	$(GO) test -v ./lib/common/router_info -run TestRouterInfoReachable

test-router-info-10k:
	$(GO) test -v ./lib/common/router_info -run Test10K

.PHONY: test-router-info-all \
        test-router-info-creation \
        test-router-info-published-date \
        test-router-info-identity \
        test-router-info-addresses \
        test-router-info-serialization \
        test-router-info-signature \
        test-router-info-capabilities \
        test-router-info-version \
        test-router-info-good-version \
        test-router-info-uncongested \
        test-router-info-reachable \
        test-router-info-10k