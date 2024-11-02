test-base64-encode-decode-not-mangled:
	go test -v ./lib/common/base64 -run TestEncodeDecodeNotMangled

.PHONY: test-base64-encode-decode-not-mangled