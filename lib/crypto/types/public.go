package types

type PublicKey interface {
	Len() int
	Bytes() []byte
}
