test-crypto-aes-all: test-crypto-aes-core test-crypto-aes-validation test-crypto-aes-padding

test-crypto-aes-core:
	$(GO) test -v ./lib/crypto -run TestAESEncryptDecrypt

test-crypto-aes-validation:
	$(GO) test -v ./lib/crypto -run TestAESEncryptInvalidKey
	$(GO) test -v ./lib/crypto -run TestAESDecryptInvalidInput

test-crypto-aes-padding:
	$(GO) test -v ./lib/crypto -run TestPKCS7PadUnpad
	$(GO) test -v ./lib/crypto -run TestPKCS7UnpadInvalidInput

.PHONY: test-crypto-aes-all \
        test-crypto-aes-core \
        test-crypto-aes-validation \
        test-crypto-aes-padding