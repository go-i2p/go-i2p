package ntcp

import "github.com/go-i2p/go-i2p/lib/transport/obfs"

// ObfuscateEphemeral implements NTCP2's key obfuscation using AES-256-CBC
func (s *NTCP2Session) ObfuscateEphemeral(ephemeralKey []byte) ([]byte, error) {
	AESStaticKey, err := s.buildAesStaticKey()
	if err != nil {
		return nil, err
	}

	return obfs.ObfuscateEphemeralKey(ephemeralKey, AESStaticKey)
}

// DeobfuscateEphemeral reverses the key obfuscation
func (s *NTCP2Session) DeobfuscateEphemeral(obfuscatedEphemeralKey []byte) ([]byte, error) {
	AESStaticKey, err := s.buildAesStaticKey()
	if err != nil {
		return nil, err
	}

	return obfs.DeobfuscateEphemeralKey(obfuscatedEphemeralKey, AESStaticKey)
}
