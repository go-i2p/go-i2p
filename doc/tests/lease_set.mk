test-lease-set-all: test-lease-set-creation \
                    test-lease-set-validation \
                    test-lease-set-components \
                    test-lease-set-expirations \
                    test-lease-set-signature-verification
test-lease-set-creation:
	$(GO) test -v ./lib/common/lease_set -run TestLeaseSetCreation

test-lease-set-validation:
	$(GO) test -v ./lib/common/lease_set -run TestLeaseSetValidation

test-lease-set-components:
	$(GO) test -v ./lib/common/lease_set -run TestLeaseSetComponents

test-lease-set-expirations:
	$(GO) test -v ./lib/common/lease_set -run TestExpirations

test-lease-set-signature-verification:
	$(GO) test -v ./lib/common/lease_set -run TestSignatureVerification

.PHONY: test-lease-set-all \
        test-lease-set-creation \
        test-lease-set-validation \
        test-lease-set-components \
        test-lease-set-expirations \
        test-lease-set-signature-verification
