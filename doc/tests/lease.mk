test-lease-all: test-lease-tunnel-gateway test-lease-tunnel-id test-lease-date

test-lease-tunnel-gateway:
	$(GO) test -v ./lib/common/lease_set -run TestTunnelGateway

test-lease-tunnel-id:
	$(GO) test -v ./lib/common/lease_set -run TestTunnelID

test-lease-date:
	$(GO) test -v ./lib/common/lease_set -run TestDate

.PHONY: test-lease-all \
        test-lease-tunnel-gateway \
        test-lease-tunnel-id \
        test-lease-date
