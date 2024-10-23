test-noise-transport-all: test-noise-packet-encryption test-noise-transport-connection

test-noise-packet-encryption:
	go test -v ./lib/transport/noise -run TestEncryptDecryptPacketOffline

test-noise-transport-connection:
	go test -v ./lib/transport/noise -run TestTransport

.PHONY: test-noise-transport-all \
        test-noise-packet-encryption \
        test-noise-transport-connection
