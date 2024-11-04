test-lease-set-all: test-lease-set-basic test-lease-set-leases test-lease-set-expiration

test-lease-set-basic:
	$(GO) test -v ./lib/common/lease_set -run TestDestinationIsCorrect
	$(GO) test -v ./lib/common/lease_set -run TestPublicKeyIsCorrect
	$(GO) test -v ./lib/common/lease_set -run TestSigningKeyIsCorrect
	$(GO) test -v ./lib/common/lease_set -run TestSignatureIsCorrect

test-lease-set-leases:
	$(GO) test -v ./lib/common/lease_set -run TestLeaseCountCorrect
	$(GO) test -v ./lib/common/lease_set -run TestLeaseCountCorrectWithMultiple
	$(GO) test -v ./lib/common/lease_set -run TestLeaseCountErrorWithTooMany
	$(GO) test -v ./lib/common/lease_set -run TestLeasesHaveCorrectData

test-lease-set-expiration:
	$(GO) test -v ./lib/common/lease_set -run TestNewestExpirationIsCorrect
	$(GO) test -v ./lib/common/lease_set -run TestOldestExpirationIsCorrect

.PHONY: test-lease-set-all \
        test-lease-set-basic \
        test-lease-set-leases \
        test-lease-set-expiration
