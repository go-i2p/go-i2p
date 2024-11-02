test-crypto-aes-all: test-crypto-aes-core test-crypto-aes-validation test-crypto-aes-padding

test-crypto-aes-core:
	go test -v ./lib/crypto -run TestAESEncryptDecrypt

test-crypto-aes-validation:
	go test -v ./lib/crypto -run TestAESEncryptInvalidKey
	go test -v ./lib/crypto -run TestAESDecryptInvalidInput

test-crypto-aes-padding:
	go test -v ./lib/crypto -run TestPKCS7PadUnpad
	go test -v ./lib/crypto -run TestPKCS7UnpadInvalidInput

.PHONY: test-crypto-aes-all \
        test-crypto-aes-core \
        test-crypto-aes-validation \
        test-crypto-aes-padding