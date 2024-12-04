test-cert-all: test-cert-type test-cert-length test-cert-data test-cert-read test-cert-length-correct test-cert-length-too-short test-cert-length-data-short test-cert-data-correct test-cert-data-too-long test-cert-data-too-short test-cert-read-correct test-cert-read-short test-cert-read-remainder test-cert-read-invalid test-cert-new-null-type test-cert-new-null-payload test-cert-new-key-type test-cert-new-invalid-type test-cert-new-payload-too-long test-cert-bytes-serialization test-cert-fields-after-creation test-cert-zero-length-payload test-cert-new-deux test-cert-invalid-payload-length test-cert-excess-bytes test-cert-serialization test-cert-serialization-excess test-cert-serialization-empty test-cert-serialization-max

test-cert-type:
	$(GO) test -v ./lib/common/certificate -run TestCertificateTypeIsFirstByte

test-cert-length:
	$(GO) test -v ./lib/common/certificate -run TestCertificateLength

test-cert-data:
	$(GO) test -v ./lib/common/certificate -run TestCertificateData

test-cert-read:
	$(GO) test -v ./lib/common/certificate -run TestReadCertificate

test-cert-length-correct:
	$(GO) test -v ./lib/common/certificate -run TestCertificateLengthCorrect

test-cert-length-too-short:
	$(GO) test -v ./lib/common/certificate -run TestCertificateLengthErrWhenTooShort

test-cert-length-data-short:
	$(GO) test -v ./lib/common/certificate -run TestCertificateLengthErrWhenDataTooShort

test-cert-data-correct:
	$(GO) test -v ./lib/common/certificate -run TestCertificateDataWhenCorrectSize

test-cert-data-too-long:
	$(GO) test -v ./lib/common/certificate -run TestCertificateDataWhenTooLong

test-cert-data-too-short:
	$(GO) test -v ./lib/common/certificate -run TestCertificateDataWhenTooShort

test-cert-read-correct:
	$(GO) test -v ./lib/common/certificate -run TestReadCertificateWithCorrectData

test-cert-read-short:
	$(GO) test -v ./lib/common/certificate -run TestReadCertificateWithDataTooShort

test-cert-read-remainder:
	$(GO) test -v ./lib/common/certificate -run TestReadCertificateWithRemainder

test-cert-read-invalid:
	$(GO) test -v ./lib/common/certificate -run TestReadCertificateWithInvalidLength

test-cert-new-null-type:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificateNullType

test-cert-new-null-payload:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificateNullTypeWithPayload

test-cert-new-key-type:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificateKeyType

test-cert-new-invalid-type:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificateInvalidType

test-cert-new-payload-too-long:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificatePayloadTooLong

test-cert-bytes-serialization:
	$(GO) test -v ./lib/common/certificate -run TestCertificateBytesSerialization

test-cert-fields-after-creation:
	$(GO) test -v ./lib/common/certificate -run TestCertificateFieldsAfterCreation

test-cert-zero-length-payload:
	$(GO) test -v ./lib/common/certificate -run TestCertificateWithZeroLengthPayload

test-cert-new-deux:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificateDeuxFunction

test-cert-invalid-payload-length:
	$(GO) test -v ./lib/common/certificate -run TestNewCertificateWithInvalidPayloadLength

test-cert-excess-bytes:
	$(GO) test -v ./lib/common/certificate -run TestCertificateExcessBytes

test-cert-serialization:
	$(GO) test -v ./lib/common/certificate -run TestCertificateSerializationDeserialization

test-cert-serialization-excess:
	$(GO) test -v ./lib/common/certificate -run TestCertificateSerializationDeserializationWithExcessBytes

test-cert-serialization-empty:
	$(GO) test -v ./lib/common/certificate -run TestCertificateSerializationDeserializationEmptyPayload

test-cert-serialization-max:
	$(GO) test -v ./lib/common/certificate -run TestCertificateSerializationDeserializationMaxPayload

.PHONY: test-cert-all \
        test-cert-type \
        test-cert-length \
        test-cert-data \
        test-cert-read \
        test-cert-length-correct \
        test-cert-length-too-short \
        test-cert-length-data-short \
        test-cert-data-correct \
        test-cert-data-too-long \
        test-cert-data-too-short \
        test-cert-read-correct \
        test-cert-read-short \
        test-cert-read-remainder \
        test-cert-read-invalid \
        test-cert-new-null-type \
        test-cert-new-null-payload \
        test-cert-new-key-type \
        test-cert-new-invalid-type \
        test-cert-new-payload-too-long \
        test-cert-bytes-serialization \
        test-cert-fields-after-creation \
        test-cert-zero-length-payload \
        test-cert-new-deux \
        test-cert-invalid-payload-length \
        test-cert-excess-bytes \
        test-cert-serialization \
        test-cert-serialization-excess \
        test-cert-serialization-empty \
        test-cert-serialization-max