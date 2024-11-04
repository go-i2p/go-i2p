test-keys-cert-all: test-keys-cert-certificate test-keys-cert-public test-keys-cert-signing test-keys-cert-creation

test-keys-cert-certificate:
	$(GO) test -v ./lib/common/keys_and_cert -run TestCertificateWithValidData

test-keys-cert-public:
	$(GO) test -v ./lib/common/keys_and_cert -run TestPublicKeyWithBadData
	$(GO) test -v ./lib/common/keys_and_cert -run TestPublicKeyWithBadCertificate
	$(GO) test -v ./lib/common/keys_and_cert -run TestPublicKeyWithNullCertificate
	$(GO) test -v ./lib/common/keys_and_cert -run TestPublicKeyWithKeyCertificate

test-keys-cert-signing:
	$(GO) test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithBadData
	$(GO) test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithBadCertificate
	$(GO) test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithNullCertificate
	$(GO) test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithKeyCertificate

test-keys-cert-creation:
	$(GO) test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithMissingData
	$(GO) test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithMissingCertData
	$(GO) test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithCertificate
	$(GO) test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithoutCertificate
	$(GO) test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithCertificateAndRemainder
	$(GO) test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithoutCertificateAndRemainder

.PHONY: test-keys-cert-all \
        test-keys-cert-certificate \
        test-keys-cert-public \
        test-keys-cert-signing \
        test-keys-cert-creation