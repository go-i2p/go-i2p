test-lease-set-all: test-lease-set-tunnel-gateway test-lease-set-tunnel-id test-lease-set-date

test-lease-set-tunnel-gateway:
	$(GO) test -v ./lib/common/lease_set -run TestTunnelGateway

test-lease-set-tunnel-id:
	$(GO) test -v ./lib/common/lease_set -run TestTunnelID

test-lease-set-date:
	$(GO) test -v ./lib/common/lease_set -run TestDate

.PHONY: test-lease-set-all \
        test-lease-set-tunnel-gateway \
        test-lease-set-tunnel-id \
        test-lease-set-date
