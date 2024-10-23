test-key-cert-all: test-key-cert-signing test-key-cert-public test-key-cert-construct

test-key-cert-signing:
	go test -v ./lib/common/key_certificate -run TestSingingPublicKeyTypeReturnsCorrectInteger
	go test -v ./lib/common/key_certificate -run TestSingingPublicKeyTypeReportsWhenDataTooSmall
	go test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyReportsWhenDataTooSmall
	go test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithDSASHA1
	go test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithP256
	go test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithP384
	go test -v ./lib/common/key_certificate -run TestConstructSigningPublicKeyWithP521

test-key-cert-public:
	go test -v ./lib/common/key_certificate -run TestPublicKeyTypeReturnsCorrectInteger
	go test -v ./lib/common/key_certificate -run TestPublicKeyTypeReportsWhenDataTooSmall

test-key-cert-construct:
	go test -v ./lib/common/key_certificate -run TestConstructPublicKeyReportsWhenDataTooSmall
	go test -v ./lib/common/key_certificate -run TestConstructPublicKeyReturnsCorrectDataWithElg

.PHONY: test-key-cert-all \
        test-key-cert-signing \
        test-key-cert-public \
        test-key-cert-construct