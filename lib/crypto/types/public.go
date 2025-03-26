package types

type PublicKey interface {
	Len() int
	Bytes() []byte
}

type RecievingPublicKey interface {
	Len() int
	Bytes() []byte
	NewEncrypter() (Encrypter, error)
}
