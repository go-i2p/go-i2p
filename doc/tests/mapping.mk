test-mapping-all: test-mapping-values test-mapping-duplicates test-mapping-conversion test-mapping-utils

test-mapping-values:
	go test -v ./lib/common/data -run TestValuesExclusesPairWithBadData
	go test -v ./lib/common/data -run TestValuesWarnsMissingData
	go test -v ./lib/common/data -run TestValuesWarnsExtraData
	go test -v ./lib/common/data -run TestValuesEnforcesEqualDelimitor
	go test -v ./lib/common/data -run TestValuesEnforcedSemicolonDelimitor
	go test -v ./lib/common/data -run TestValuesReturnsValues

test-mapping-duplicates:
	go test -v ./lib/common/data -run TestHasDuplicateKeysTrueWhenDuplicates
	go test -v ./lib/common/data -run TestHasDuplicateKeysFalseWithoutDuplicates
	go test -v ./lib/common/data -run TestReadMappingHasDuplicateKeys

test-mapping-conversion:
	go test -v ./lib/common/data -run TestGoMapToMappingProducesCorrectMapping
	go test -v ./lib/common/data -run TestFullGoMapToMappingProducesCorrectMapping

test-mapping-utils:
	go test -v ./lib/common/data -run TestStopValueRead
	go test -v ./lib/common/data -run TestBeginsWith

.PHONY: test-mapping-all \
        test-mapping-values \
        test-mapping-duplicates \
        test-mapping-conversion \
        test-mapping-utils