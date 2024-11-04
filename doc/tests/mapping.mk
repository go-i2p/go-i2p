test-mapping-all: test-mapping-values test-mapping-duplicates test-mapping-conversion test-mapping-utils

test-mapping-values:
	$(GO) test -v ./lib/common/data -run TestValuesExclusesPairWithBadData
	$(GO) test -v ./lib/common/data -run TestValuesWarnsMissingData
	$(GO) test -v ./lib/common/data -run TestValuesWarnsExtraData
	$(GO) test -v ./lib/common/data -run TestValuesEnforcesEqualDelimitor
	$(GO) test -v ./lib/common/data -run TestValuesEnforcedSemicolonDelimitor
	$(GO) test -v ./lib/common/data -run TestValuesReturnsValues

test-mapping-duplicates:
	$(GO) test -v ./lib/common/data -run TestHasDuplicateKeysTrueWhenDuplicates
	$(GO) test -v ./lib/common/data -run TestHasDuplicateKeysFalseWithoutDuplicates
	$(GO) test -v ./lib/common/data -run TestReadMappingHasDuplicateKeys

test-mapping-conversion:
	$(GO) test -v ./lib/common/data -run TestGoMapToMappingProducesCorrectMapping
	$(GO) test -v ./lib/common/data -run TestFullGoMapToMappingProducesCorrectMapping

test-mapping-utils:
	$(GO) test -v ./lib/common/data -run TestStopValueRead
	$(GO) test -v ./lib/common/data -run TestBeginsWith

.PHONY: test-mapping-all \
        test-mapping-values \
        test-mapping-duplicates \
        test-mapping-conversion \
        test-mapping-utils