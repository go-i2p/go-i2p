test-noise-transport-all: test-noise-packet-encryption test-noise-transport-connection test-noise-packet-obfuscation test-noise-packet-obfuscation-func

test-noise-packet-encryption:
	$(GO) test -v ./lib/transport/noise -run TestEncryptDecryptPacketOffline

test-noise-transport-connection:
	$(GO) test -v ./lib/transport/noise -run TestTransport

test-noise-packet-obfuscation:
	$(GO) test -v ./lib/transport/noise -run TestEncryptDecryptPacketObfsOffline

test-noise-packet-obfuscation-func:
	$(GO) test -v ./lib/transport/noise -run TestEncryptDecryptPacketObfsOfflineWithFunc

.PHONY: test-noise-transport-all \
        test-noise-packet-encryption \
        test-noise-transport-connection \
        test-noise-packet-obfuscation \
        test-noise-packet-obfuscation-func