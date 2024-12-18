
test-i2np-header-all: test-i2np-type test-i2np-message test-i2np-expiration test-i2np-ntcp-components test-i2np-data test-i2np-regression test-i2np-build-request-record test-i2np-build-response-record

test-i2np-type:
	$(GO) test -v ./lib/i2np -run TestReadI2NPTypeWith

test-i2np-message:
	$(GO) test -v ./lib/i2np -run TestReadI2NPNTCPMessageID

test-i2np-expiration:
	$(GO) test -v ./lib/i2np -run TestReadI2NPNTCPMessageExpiration
	$(GO) test -v ./lib/i2np -run TestReadI2NPSSUMessageExpiration

test-i2np-ntcp-components:
	$(GO) test -v ./lib/i2np -run TestReadI2NPNTCPMessageSize
	$(GO) test -v ./lib/i2np -run TestReadI2NPNTCPMessageChecksum

test-i2np-data:
	$(GO) test -v ./lib/i2np -run TestReadI2NPNTCPData

test-i2np-regression:
	$(GO) test -v ./lib/i2np -run TestCrasherRegression123781

test-i2np-build-request-record:
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordReceiveTunnelTooLittleData
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordReceiveTunnelValidData
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordOurIdentTooLittleData
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordOurIdentValidData

test-i2np-build-response-record:
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordHashTooLittleData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordHashValidData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordRandomDataTooLittleData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordRandomDataValidData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordReplyTooLittleData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordReplyValidData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordTooLittleData
	$(GO) test -v ./lib/i2np -run TestReadBuildResponseRecordValidData

.PHONY: test-i2np-header-all \
        test-i2np-type \
        test-i2np-message \
        test-i2np-expiration \
        test-i2np-ntcp-components \
        test-i2np-data \
        test-i2np-regression \
        test-i2np-build-request-record \
        test-i2np-build-response-record
