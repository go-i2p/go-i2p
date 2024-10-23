
test-cert-all: test-cert-type test-cert-length test-cert-data test-cert-read test-cert-length-correct test-cert-length-too-short test-cert-length-data-short test-cert-data-correct test-cert-data-too-long test-cert-data-too-short test-cert-read-correct test-cert-read-short test-cert-read-remainder test-cert-read-invalid

test-cert-type:
	go test -v ./lib/common/certificate -run TestCertificateTypeIsFirstByte

test-cert-length:
	go test -v ./lib/common/certificate -run TestCertificateLength

test-cert-data:
	go test -v ./lib/common/certificate -run TestCertificateData

test-cert-read:
	go test -v ./lib/common/certificate -run TestReadCertificate

test-cert-length-correct:
	go test -v ./lib/common/certificate -run TestCertificateLengthCorrect

test-cert-length-too-short:
	go test -v ./lib/common/certificate -run TestCertificateLengthErrWhenTooShort

test-cert-length-data-short:
	go test -v ./lib/common/certificate -run TestCertificateLengthErrWhenDataTooShort

test-cert-data-correct:
	go test -v ./lib/common/certificate -run TestCertificateDataWhenCorrectSize

test-cert-data-too-long:
	go test -v ./lib/common/certificate -run TestCertificateDataWhenTooLong

test-cert-data-too-short:
	go test -v ./lib/common/certificate -run TestCertificateDataWhenTooShort

test-cert-read-correct:
	go test -v ./lib/common/certificate -run TestReadCertificateWithCorrectData

test-cert-read-short:
	go test -v ./lib/common/certificate -run TestReadCertificateWithDataTooShort

test-cert-read-remainder:
	go test -v ./lib/common/certificate -run TestReadCertificateWithRemainder

test-cert-read-invalid:
	go test -v ./lib/common/certificate -run TestReadCertificateWithInvalidLength

# Declare all targets as PHONY
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
        test-cert-read-invalid