test-base64-encode-decode-not-mangled:
	$(GO) test -v ./lib/common/base64 -run TestEncodeDecodeNotMangled

.PHONY: test-base64-encode-decode-not-mangled