test-crypto-ed25519-all: test-crypto-ed25519

test-crypto-ed25519:
	$(GO) test -v ./lib/crypto -run TestEd25519

.PHONY: test-crypto-ed25519-all \
        test-crypto-ed25519
