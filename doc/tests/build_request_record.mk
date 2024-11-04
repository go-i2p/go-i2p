test-build-request-all: test-build-request-receive test-build-request-ident test-build-request-components

test-build-request-receive:
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordReceiveTunnel

test-build-request-ident:
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordOurIdent

test-build-request-components:
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordNextTunnel
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordNextIdent
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordLayerKey
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordIVKey
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordReplyKey
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordReplyIV
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordFlag
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordRequestTime
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordSendMessageID
	$(GO) test -v ./lib/i2np -run TestReadBuildRequestRecordPadding

.PHONY: test-build-request-all \
        test-build-request-receive \
        test-build-request-ident \
        test-build-request-components
