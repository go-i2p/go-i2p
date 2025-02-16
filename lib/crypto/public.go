package crypto

type PublicKey interface {
	Len() int
	Bytes() []byte
}
