test-key-cert-all: test-key-cert-signing test-key-cert-public test-key-cert-construct

test-key-cert-signing:
	$(GO) test -v ./lib/common/key_certificate -run TestSingingPublicKeyTypeReturnsCorrectInteger
	$(GO) test -v ./lib/common/key_certificate -run TestSingingPublicKeyTypeReportsWhenDataTooSmall
	$(GO) test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyReportsWhenDataTooSmall
	$(GO) test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithDSASHA1
	$(GO) test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithP256
	$(GO) test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithP384
	$(GO) test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithP521

test-key-cert-public:
	$(GO) test -v ./lib/common/key_certificate -run TestPublicKeyTypeReturnsCorrectInteger
	$(GO) test -v ./lib/common/key_certificate -run TestPublicKeyTypeReportsWhenDataTooSmall

test-key-cert-construct:
	$(GO) test -v ./lib/common/key_certificate -run TestConstructPublicKeyReportsWhenDataTooSmall
	$(GO) test -v ./lib/common/key_certificate -run TestConstructPublicKeyReturnsCorrectDataWithElg

.PHONY: test-key-cert-all \
        test-key-cert-signing \
        test-key-cert-public \
        test-key-cert-construct