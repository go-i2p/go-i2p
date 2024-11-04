test-integer-all: test-integer-big-endian test-integer-one-byte test-integer-zero

test-integer-big-endian:
	$(GO) test -v ./lib/common/integer -run TestIntegerBigEndian

test-integer-one-byte:
	$(GO) test -v ./lib/common/integer -run TestWorksWithOneByte

test-integer-zero:
	$(GO) test -v ./lib/common/integer -run TestIsZeroWithNoData

.PHONY: test-integer-all \
        test-integer-big-endian \
        test-integer-one-byte \
        test-integer-zero
