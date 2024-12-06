test-lease2-all: test-lease2-tunnel-gateway \
                test-lease2-tunnel-id \
                test-lease2-end-date \
                test-lease2-read \
                test-lease2-new \
                test-lease2-string \
                test-lease2-from-bytes

test-lease2-tunnel-gateway:
	$(GO) test -v ./lib/common/lease2 -run TestLease2TunnelGateway

test-lease2-tunnel-id:
	$(GO) test -v ./lib/common/lease2 -run TestLease2TunnelID

test-lease2-end-date:
	$(GO) test -v ./lib/common/lease2 -run TestLease2EndDate

test-lease2-read:
	$(GO) test -v ./lib/common/lease2 -run TestReadLease2

test-lease2-new:
	$(GO) test -v ./lib/common/lease2 -run TestNewLease2

test-lease2-string:
	$(GO) test -v ./lib/common/lease2 -run TestLease2String

test-lease2-from-bytes:
	$(GO) test -v ./lib/common/lease2 -run TestNewLease2FromBytes

.PHONY: test-lease2-all \
       test-lease2-tunnel-gateway \
       test-lease2-tunnel-id \
       test-lease2-end-date \
       test-lease2-read \
       test-lease2-new \
       test-lease2-string \
       test-lease2-from-bytes