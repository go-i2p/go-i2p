test-su3-all: test-su3-read test-su3-signature

test-su3-read:
	go test -v ./lib/su3 -run TestRead

test-su3-signature:
	go test -v ./lib/su3 -run TestReadSignatureFirst

.PHONY: test-su3-all \
        test-su3-read \
        test-su3-signature
