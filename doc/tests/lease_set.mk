test-lease-set-all: test-lease-set-basic test-lease-set-leases test-lease-set-expiration

test-lease-set-basic:
	go test -v ./lib/common/lease_set -run TestDestinationIsCorrect
	go test -v ./lib/common/lease_set -run TestPublicKeyIsCorrect
	go test -v ./lib/common/lease_set -run TestSigningKeyIsCorrect
	go test -v ./lib/common/lease_set -run TestSignatureIsCorrect

test-lease-set-leases:
	go test -v ./lib/common/lease_set -run TestLeaseCountCorrect
	go test -v ./lib/common/lease_set -run TestLeaseCountCorrectWithMultiple
	go test -v ./lib/common/lease_set -run TestLeaseCountErrorWithTooMany
	go test -v ./lib/common/lease_set -run TestLeasesHaveCorrectData

test-lease-set-expiration:
	go test -v ./lib/common/lease_set -run TestNewestExpirationIsCorrect
	go test -v ./lib/common/lease_set -run TestOldestExpirationIsCorrect

.PHONY: test-lease-set-all \
        test-lease-set-basic \
        test-lease-set-leases \
        test-lease-set-expiration
