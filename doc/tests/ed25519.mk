test-crypto-ed25519-all: test-crypto-ed25519 \
                        test-crypto-ed25519-key-generation \
                        test-crypto-ed25519-signing-verification \
                        test-crypto-ed25519-invalid-signature \
                        test-crypto-ed25519-encryption \
                        test-crypto-ed25519-encryption-too-big \
                        test-crypto-ed25519-create-public-key \
                        test-crypto-ed25519-signer-verify-hash \
                        test-crypto-ed25519-verifier-invalid-data \
                        test-crypto-ed25519-encrypt-decrypt-padding \
                        test-crypto-ed25519-encrypt-padding-edge-cases \
                        test-crypto-ed25519-padding-zero-nonzero \
                        test-crypto-ed25519-encrypt-padding-invalid \
                        test-crypto-ed25519-verifier-invalid-key \
                        test-crypto-ed25519-signer-invalid-key \
                        test-crypto-ed25519-encrypt-not-implemented \
                        test-crypto-ed25519-verify-tampered-sig \
                        test-crypto-ed25519-verify-different-message \
                        test-crypto-ed25519-encrypt-padding-edge-data \
                        test-crypto-ed25519-padding-consistency \
                        test-crypto-ed25519-padding-integrity \
                        test-crypto-ed25519-padding-hash-consistency

test-crypto-ed25519:
	$(GO) test -v ./lib/crypto -run TestEd25519

test-crypto-ed25519-key-generation:
	$(GO) test -v ./lib/crypto -run TestEd25519KeyGeneration

test-crypto-ed25519-signing-verification:
	$(GO) test -v ./lib/crypto -run TestEd25519SigningVerification

test-crypto-ed25519-invalid-signature:
	$(GO) test -v ./lib/crypto -run TestEd25519InvalidSignature

test-crypto-ed25519-encryption:
	$(GO) test -v ./lib/crypto -run TestEd25519Encryption

test-crypto-ed25519-encryption-too-big:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptionTooBig

test-crypto-ed25519-create-public-key:
	$(GO) test -v ./lib/crypto -run TestEd25519CreatePublicKeyFromBytes

test-crypto-ed25519-signer-verify-hash:
	$(GO) test -v ./lib/crypto -run TestEd25519SignerSignAndVerifyHash

test-crypto-ed25519-verifier-invalid-data:
	$(GO) test -v ./lib/crypto -run TestEd25519VerifierVerifyInvalidData

test-crypto-ed25519-encrypt-decrypt-padding:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptDecryptPadding

test-crypto-ed25519-encrypt-padding-edge-cases:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptPaddingEdgeCases

test-crypto-ed25519-padding-zero-nonzero:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptionPaddingZeroAndNonZero

test-crypto-ed25519-encrypt-padding-invalid:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptPaddingInvalidInput

test-crypto-ed25519-verifier-invalid-key:
	$(GO) test -v ./lib/crypto -run TestEd25519VerifierInvalidKeySize

test-crypto-ed25519-signer-invalid-key:
	$(GO) test -v ./lib/crypto -run TestEd25519SignerInvalidKeySize

test-crypto-ed25519-encrypt-not-implemented:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptionEncryptNotImplemented

test-crypto-ed25519-verify-tampered-sig:
	$(GO) test -v ./lib/crypto -run TestEd25519VerifierVerifyWithTamperedSignature

test-crypto-ed25519-verify-different-message:
	$(GO) test -v ./lib/crypto -run TestEd25519VerifierVerifyWithDifferentMessage

test-crypto-ed25519-encrypt-padding-edge-data:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptionEncryptPaddingEdgeCaseData

test-crypto-ed25519-padding-consistency:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptionEncryptionPaddingConsistency

test-crypto-ed25519-padding-integrity:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptPaddingIntegrity

test-crypto-ed25519-padding-hash-consistency:
	$(GO) test -v ./lib/crypto -run TestEd25519EncryptionEncryptPaddingHashConsistency

.PHONY: test-crypto-ed25519-all \
        test-crypto-ed25519 \
        test-crypto-ed25519-key-generation \
        test-crypto-ed25519-signing-verification \
        test-crypto-ed25519-invalid-signature \
        test-crypto-ed25519-encryption \
        test-crypto-ed25519-encryption-too-big \
        test-crypto-ed25519-create-public-key \
        test-crypto-ed25519-signer-verify-hash \
        test-crypto-ed25519-verifier-invalid-data \
        test-crypto-ed25519-encrypt-decrypt-padding \
        test-crypto-ed25519-encrypt-padding-edge-cases \
        test-crypto-ed25519-padding-zero-nonzero \
        test-crypto-ed25519-encrypt-padding-invalid \
        test-crypto-ed25519-verifier-invalid-key \
        test-crypto-ed25519-signer-invalid-key \
        test-crypto-ed25519-encrypt-not-implemented \
        test-crypto-ed25519-verify-tampered-sig \
        test-crypto-ed25519-verify-different-message \
        test-crypto-ed25519-encrypt-padding-edge-data \
        test-crypto-ed25519-padding-consistency \
        test-crypto-ed25519-padding-integrity \
        test-crypto-ed25519-padding-hash-consistency