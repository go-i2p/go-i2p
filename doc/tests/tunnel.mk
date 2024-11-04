test-tunnel-all: test-tunnel-delivery-instructions test-tunnel-message

# Tests from delivery_test.go
test-tunnel-delivery-instructions:
	$(GO) test -v ./lib/tunnel -run TestReadDeliveryInstructions

# Tests from message_test.go
test-tunnel-message: test-tunnel-message-padding test-tunnel-message-fragments

test-tunnel-message-padding:
	$(GO) test -v ./lib/tunnel -run TestDeliveryInstructionDataWithNoPadding
	$(GO) test -v ./lib/tunnel -run TestDeliveryInstructionDataWithSomePadding
	$(GO) test -v ./lib/tunnel -run TestDeliveryInstructionDataWithOnlyPadding

test-tunnel-message-fragments:
	$(GO) test -v ./lib/tunnel -run TestDeliveryInstructionsWithFragments

.PHONY: test-tunnel-all \
        test-tunnel-delivery-instructions \
        test-tunnel-message \
        test-tunnel-message-padding \
        test-tunnel-message-fragments
