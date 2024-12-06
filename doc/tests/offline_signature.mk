test-offline-signature-all: test-offline-signature-lengths \
                          test-offline-signature-new \
                          test-offline-signature-bytes \
                          test-offline-signature-read \
                          test-offline-signature-read-short \
                          test-offline-signature-verify \
                          test-offline-signature-roundtrip

test-offline-signature-lengths:
	$(GO) test -v ./lib/common/offline_signature -run TestSigTypeKeyLengths

test-offline-signature-new:
	$(GO) test -v ./lib/common/offline_signature -run TestNewOfflineSignature

test-offline-signature-bytes:
	$(GO) test -v ./lib/common/offline_signature -run TestBytes

test-offline-signature-read:
	$(GO) test -v ./lib/common/offline_signature -run TestReadOfflineSignature

test-offline-signature-read-short:
	$(GO) test -v ./lib/common/offline_signature -run TestReadOfflineSignatureNotEnoughForFullStructure

test-offline-signature-verify:
	$(GO) test -v ./lib/common/offline_signature -run TestVerifyOfflineSignature

test-offline-signature-roundtrip:
	$(GO) test -v ./lib/common/offline_signature -run TestRoundTrip

.PHONY: test-offline-signature-all \
        test-offline-signature-lengths \
        test-offline-signature-new \
        test-offline-signature-bytes \
        test-offline-signature-read \
        test-offline-signature-read-short \
        test-offline-signature-verify \
        test-offline-signature-roundtrip