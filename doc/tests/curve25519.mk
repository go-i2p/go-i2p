test-crypto-curve25519-all: test-crypto-curve25519-key \
                          test-crypto-curve25519-session \
                          test-crypto-curve25519-encrypt \
                          test-crypto-curve25519-no-padding

test-crypto-curve25519-key:
	$(GO) test -v ./lib/crypto -run TestCurve25519KeyCreation

test-crypto-curve25519-session:
	$(GO) test -v ./lib/crypto -run TestCurve25519EncryptionSession

test-crypto-curve25519-encrypt:
	$(GO) test -v ./lib/crypto -run TestCurve25519Encrypt

test-crypto-curve25519-no-padding:
	$(GO) test -v ./lib/crypto -run TestCurve25519EncryptNoPadding

.PHONY: test-crypto-curve25519-all \
       test-crypto-curve25519-key \
       test-crypto-curve25519-session \
       test-crypto-curve25519-encrypt \
       test-crypto-curve25519-no-padding