test-signatures:
	$(GO) test -v ./lib/common/signature/ -run TestReadSignatureErrors
	$(GO) test -v ./lib/common/signature/ -run TestReadSignature
	$(GO) test -v ./lib/common/signature/ -run TestNewSignatureError
	$(GO) test -v ./lib/common/signature/ -run TestNewSignature

.PHONY: test-signatures
