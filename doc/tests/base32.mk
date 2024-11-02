test-base32-encode-decode-not-mangled:
	go test -v ./lib/common/base32 -run TestEncodeDecodeNotMangled

.PHONY: test-base32-encode-decode-not-mangled