test-crypto-hmac-all: test-crypto-hmac

test-crypto-hmac:
	$(GO) test -v ./lib/crypto -run Test_I2PHMAC

.PHONY: test-crypto-hmac-all \
        test-crypto-hmac
