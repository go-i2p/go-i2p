test-string-all: test-string-length test-string-data test-string-conversion test-string-read

test-string-length:
	go test -v ./lib/common/data -run TestStringReportsCorrectLength
	go test -v ./lib/common/data -run TestI2PStringReportsLengthZeroError
	go test -v ./lib/common/data -run TestI2PStringReportsExtraDataError
	go test -v ./lib/common/data -run TestI2PStringDataReportsLengthZeroError

test-string-data:
	go test -v ./lib/common/data -run TestI2PStringDataReportsExtraDataError
	go test -v ./lib/common/data -run TestI2PStringDataEmptyWhenZeroLength
	go test -v ./lib/common/data -run TestI2PStringDataErrorWhenNonZeroLengthOnly

test-string-conversion:
	go test -v ./lib/common/data -run TestToI2PI2PStringFormatsCorrectly
	go test -v ./lib/common/data -run TestToI2PStringReportsOverflows

test-string-read:
	go test -v ./lib/common/data -run TestReadStringReadsLength
	go test -v ./lib/common/data -run TestReadI2PStringErrWhenEmptySlice
	go test -v ./lib/common/data -run TestReadI2PStringErrWhenDataTooShort

.PHONY: test-string-all \
        test-string-length \
        test-string-data \
        test-string-conversion \
        test-string-read
