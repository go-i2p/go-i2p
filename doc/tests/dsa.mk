test-crypto-dsa-all: test-crypto-dsa test-crypto-dsa-benchmarks

test-crypto-dsa:
	$(GO) test -v ./lib/crypto -run TestDSA

test-crypto-dsa-benchmarks:
	$(GO) test -v ./lib/crypto -bench=DSA -run=^$

# Individual benchmarks
test-crypto-dsa-bench-generate:
	$(GO) test -v ./lib/crypto -bench=DSAGenerate -run=^$

test-crypto-dsa-bench-sign-verify:
	$(GO) test -v ./lib/crypto -bench=DSASignVerify -run=^$

.PHONY: test-crypto-dsa-all \
        test-crypto-dsa \
        test-crypto-dsa-benchmarks \
        test-crypto-dsa-bench-generate \
        test-crypto-dsa-bench-sign-verify
