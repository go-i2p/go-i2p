test-build-request-all: test-build-request-receive test-build-request-ident test-build-request-components

test-build-request-receive:
	go test -v ./lib/i2np -run TestReadBuildRequestRecordReceiveTunnel

test-build-request-ident:
	go test -v ./lib/i2np -run TestReadBuildRequestRecordOurIdent

test-build-request-components:
	go test -v ./lib/i2np -run TestReadBuildRequestRecordNextTunnel
	go test -v ./lib/i2np -run TestReadBuildRequestRecordNextIdent
	go test -v ./lib/i2np -run TestReadBuildRequestRecordLayerKey
	go test -v ./lib/i2np -run TestReadBuildRequestRecordIVKey
	go test -v ./lib/i2np -run TestReadBuildRequestRecordReplyKey
	go test -v ./lib/i2np -run TestReadBuildRequestRecordReplyIV
	go test -v ./lib/i2np -run TestReadBuildRequestRecordFlag
	go test -v ./lib/i2np -run TestReadBuildRequestRecordRequestTime
	go test -v ./lib/i2np -run TestReadBuildRequestRecordSendMessageID
	go test -v ./lib/i2np -run TestReadBuildRequestRecordPadding

.PHONY: test-build-request-all \
        test-build-request-receive \
        test-build-request-ident \
        test-build-request-components
