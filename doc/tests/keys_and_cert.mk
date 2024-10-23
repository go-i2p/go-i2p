test-keys-cert-all: test-keys-cert-certificate test-keys-cert-public test-keys-cert-signing test-keys-cert-creation

test-keys-cert-certificate:
	go test -v ./lib/common/keys_and_cert -run TestCertificateWithValidData

test-keys-cert-public:
	go test -v ./lib/common/keys_and_cert -run TestPublicKeyWithBadData
	go test -v ./lib/common/keys_and_cert -run TestPublicKeyWithBadCertificate
	go test -v ./lib/common/keys_and_cert -run TestPublicKeyWithNullCertificate
	go test -v ./lib/common/keys_and_cert -run TestPublicKeyWithKeyCertificate

test-keys-cert-signing:
	go test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithBadData
	go test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithBadCertificate
	go test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithNullCertificate
	go test -v ./lib/common/keys_and_cert -run TestSigningPublicKeyWithKeyCertificate

test-keys-cert-creation:
	go test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithMissingData
	go test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithMissingCertData
	go test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithCertificate
	go test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithoutCertificate
	go test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithCertificateAndRemainder
	go test -v ./lib/common/keys_and_cert -run TestNewKeysAndCertWithValidDataWithoutCertificateAndRemainder

.PHONY: test-keys-cert-all \
        test-keys-cert-certificate \
        test-keys-cert-public \
        test-keys-cert-signing \
        test-keys-cert-creation