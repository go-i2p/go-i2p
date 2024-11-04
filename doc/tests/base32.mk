test-base32-encode-decode-not-mangled:
	$(GO) test -v ./lib/common/base32 -run TestEncodeDecodeNotMangled

.PHONY: test-base32-encode-decode-not-mangled