test-crypto-elg-all: test-crypto-elg test-crypto-elg-benchmarks

test-crypto-elg: test-crypto-elg-basic test-crypto-elg-key-gen test-crypto-elg-pub-key \
                test-crypto-elg-priv-key test-crypto-elg-enc-session test-crypto-elg-integrity \
                test-crypto-elg-concurrent

test-crypto-elg-basic:
	$(GO) test -v ./lib/crypto -run TestElg$$

test-crypto-elg-key-gen:
	$(GO) test -v ./lib/crypto -run TestElgKeyGeneration

test-crypto-elg-pub-key:
	$(GO) test -v ./lib/crypto -run TestElgPublicKey

test-crypto-elg-priv-key:
	$(GO) test -v ./lib/crypto -run TestElgPrivateKey

test-crypto-elg-enc-session:
	$(GO) test -v ./lib/crypto -run TestElgEncryptionSession

test-crypto-elg-integrity:
	$(GO) test -v ./lib/crypto -run TestElgEncryptionIntegrity

test-crypto-elg-concurrent:
	$(GO) test -v ./lib/crypto -run TestElgamalConcurrentOperations

test-crypto-elg-benchmarks:
	$(GO) test -v ./lib/crypto -bench=Elg -run=^$$

# Individual benchmarks
test-crypto-elg-bench-generate:
	$(GO) test -v ./lib/crypto -bench=ElgGenerate -run=^$$

test-crypto-elg-bench-encrypt:
	$(GO) test -v ./lib/crypto -bench=ElgEncrypt -run=^$$

test-crypto-elg-bench-decrypt:
	$(GO) test -v ./lib/crypto -bench=ElgDecrypt -run=^$$

.PHONY: test-crypto-elg-all \
        test-crypto-elg \
        test-crypto-elg-basic \
        test-crypto-elg-key-gen \
        test-crypto-elg-pub-key \
        test-crypto-elg-priv-key \
        test-crypto-elg-enc-session \
        test-crypto-elg-integrity \
        test-crypto-elg-concurrent \
        test-crypto-elg-benchmarks \
        test-crypto-elg-bench-generate \
        test-crypto-elg-bench-encrypt \
        test-crypto-elg-bench-decrypt