test-string-all: test-string-length test-string-data test-string-conversion test-string-read

test-string-length:
	$(GO) test -v ./lib/common/data -run TestStringReportsCorrectLength
	$(GO) test -v ./lib/common/data -run TestI2PStringReportsLengthZeroError
	$(GO) test -v ./lib/common/data -run TestI2PStringReportsExtraDataError
	$(GO) test -v ./lib/common/data -run TestI2PStringDataReportsLengthZeroError

test-string-data:
	$(GO) test -v ./lib/common/data -run TestI2PStringDataReportsExtraDataError
	$(GO) test -v ./lib/common/data -run TestI2PStringDataEmptyWhenZeroLength
	$(GO) test -v ./lib/common/data -run TestI2PStringDataErrorWhenNonZeroLengthOnly

test-string-conversion:
	$(GO) test -v ./lib/common/data -run TestToI2PI2PStringFormatsCorrectly
	$(GO) test -v ./lib/common/data -run TestToI2PStringReportsOverflows

test-string-read:
	$(GO) test -v ./lib/common/data -run TestReadStringReadsLength
	$(GO) test -v ./lib/common/data -run TestReadI2PStringErrWhenEmptySlice
	$(GO) test -v ./lib/common/data -run TestReadI2PStringErrWhenDataTooShort

.PHONY: test-string-all \
        test-string-length \
        test-string-data \
        test-string-conversion \
        test-string-read
