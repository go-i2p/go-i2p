test-su3-all: test-su3-read test-su3-signature

test-su3-read:
	$(GO) test -v ./lib/su3 -run TestRead

test-su3-signature:
	$(GO) test -v ./lib/su3 -run TestReadSignatureFirst

.PHONY: test-su3-all \
        test-su3-read \
        test-su3-signature
