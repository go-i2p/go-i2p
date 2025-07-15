package handshake

// KeyTransformer defines operations for transforming keys during handshake
type KeyTransformer interface {
	ObfuscateKey(publicKey []byte) ([]byte, error)
	DeobfuscateKey(obfuscatedKey []byte) ([]byte, error)
}

// NoOpTransformer is a default implementation that doesn't transform keys
type NoOpTransformer struct{}

func (t *NoOpTransformer) ObfuscateKey(publicKey []byte) ([]byte, error) {
	return publicKey, nil
}

func (t *NoOpTransformer) DeobfuscateKey(obfuscatedKey []byte) ([]byte, error) {
	return obfuscatedKey, nil
}
