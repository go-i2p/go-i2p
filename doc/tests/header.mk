
test-i2np-header-all: test-i2np-type test-i2np-message test-i2np-expiration test-i2np-ntcp-components test-i2np-data test-i2np-regression

test-i2np-type:
	go test -v ./lib/i2np -run TestReadI2NPTypeWith

test-i2np-message:
	go test -v ./lib/i2np -run TestReadI2NPNTCPMessageID

test-i2np-expiration:
	go test -v ./lib/i2np -run TestReadI2NPNTCPMessageExpiration
	go test -v ./lib/i2np -run TestReadI2NPSSUMessageExpiration

test-i2np-ntcp-components:
	go test -v ./lib/i2np -run TestReadI2NPNTCPMessageSize
	go test -v ./lib/i2np -run TestReadI2NPNTCPMessageChecksum

test-i2np-data:
	go test -v ./lib/i2np -run TestReadI2NPNTCPData

test-i2np-regression:
	go test -v ./lib/i2np -run TestCrasherRegression123781

.PHONY: test-i2np-header-all \
        test-i2np-type \
        test-i2np-message \
        test-i2np-expiration \
        test-i2np-ntcp-components \
        test-i2np-data \
        test-i2np-regression