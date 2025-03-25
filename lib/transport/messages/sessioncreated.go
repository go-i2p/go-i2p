package messages

import "github.com/go-i2p/go-i2p/lib/common/data"

/**
	2) SessionCreated
	------------------

	Bob sends to Alice.

	Noise content: Bob's ephemeral key Y
	Noise payload: 16 byte option block
	Non-noise payload: Random padding

	(Payload Security Properties)

	XK(s, rs):           Authentication   Confidentiality
		<- e, ee                  2                1

		Authentication: 2.
		Sender authentication resistant to key-compromise impersonation (KCI).
		The sender authentication is based on an ephemeral-static DH ("es" or "se")
		between the sender's static key pair and the recipient's ephemeral key pair.
		Assuming the corresponding private keys are secure, this authentication cannot be forged.

		Confidentiality: 1.
		Encryption to an ephemeral recipient.
		This payload has forward secrecy, since encryption involves an ephemeral-ephemeral DH ("ee").
		However, the sender has not authenticated the recipient,
		so this payload might be sent to any party, including an active attacker.


		"e": Bob generates a new ephemeral key pair and stores it in the e variable,
		writes the ephemeral public key as cleartext into the message buffer,
		and hashes the public key along with the old h to derive a new h.

		"ee": A DH is performed between the Bob's ephemeral key pair and the Alice's ephemeral key pair.
		The result is hashed along with the old ck to derive a new ck and k, and n is set to zero.


	The Y value is encrypted to ensure payload indistinguishably and uniqueness,
	which are necessary DPI countermeasures.  We use AES encryption to achieve
	this, rather than more complex and slower alternatives such as elligator2.
	Asymmetric encryption to Alice's router public key would be far too slow.  AES
	encryption uses Bob's router hash as the key and the AES state from message 1
	(which was initialized with Bob's IV as published in the network database).

	AES encryption is for DPI resistance only.  Any party knowing Bob's router hash
	and IV, which are published in the network database, and captured the first 32
	bytes of message 1, may decrypt the Y value in this message.


	Raw contents:

	+----+----+----+----+----+----+----+----+
	|                                       |
	+        obfuscated with RH_B           +
	|       AES-CBC-256 encrypted Y         |
	+              (32 bytes)               +
	|                                       |
	+                                       +
	|                                       |
	+----+----+----+----+----+----+----+----+
	|   ChaChaPoly frame                    |
	+   Encrypted and authenticated data    +
	|   32 bytes                            |
	+   k defined in KDF for message 2      +
	|   n = 0; see KDF for associated data  |
	+                                       +
	|                                       |
	+----+----+----+----+----+----+----+----+
	|     unencrypted authenticated         |
	+         padding (optional)            +
	|     length defined in options block   |
	~               .   .   .               ~
	|                                       |
	+----+----+----+----+----+----+----+----+

	Y :: 32 bytes, AES-256-CBC encrypted X25519 ephemeral key, little endian
			key: RH_B
			iv: Using AES state from message 1


	Unencrypted data (Poly1305 auth tag not shown):

	+----+----+----+----+----+----+----+----+
	|                                       |
	+                                       +
	|                  Y                    |
	+              (32 bytes)               +
	|                                       |
	+                                       +
	|                                       |
	+----+----+----+----+----+----+----+----+
	|               options                 |
	+              (16 bytes)               +
	|                                       |
	+----+----+----+----+----+----+----+----+
	|     unencrypted authenticated         |
	+         padding (optional)            +
	|     length defined in options block   |
	~               .   .   .               ~
	|                                       |
	+----+----+----+----+----+----+----+----+

	Y :: 32 bytes, X25519 ephemeral key, little endian

	options :: options block, 16 bytes, see below

	padding :: Random data, 0 or more bytes.
				Total message length must be 65535 bytes or less.
				Alice and Bob will use the padding data in the KDF for message 3 part 1.
				It is authenticated so that any tampering will cause the
				next message to fail.


	Notes
	`````

	- Alice must validate that Bob's ephemeral key is a valid point on the curve
	here.

	- Padding should be limited to a reasonable amount.
	Alice may reject connections with excessive padding.
	Alice will specify her padding options in message 3.
	Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
	(Distribution is implementation-dependent)

	- On any error, including AEAD, DH, timestamp, apparent replay, or key
	validation failure, Alice must halt further message processing and close the
	connection without responding.  This should be an abnormal close (TCP RST).

	- To facilitate rapid handshaking, implementations must ensure that Bob buffers
	and then flushes the entire contents of the first message at once, including
	the padding.  This increases the likelihood that the data will be contained
	in a single TCP packet (unless segmented by the OS or middleboxes), and
	received all at once by Alice.  This is also for efficiency and to ensure the
	effectiveness of the random padding.

	- Alice must fail the connection if any incoming data remains after validating
	message 2 and reading in the padding. There should be no extra data from Bob,
	as Alice has not responded with message 3 yet.


	Options block:
	Note: All fields are big-endian.

	+----+----+----+----+----+----+----+----+
	| Rsvd(0) | padLen  |   Reserved (0)    |
	+----+----+----+----+----+----+----+----+
	|        tsB        |   Reserved (0)    |
	+----+----+----+----+----+----+----+----+

	Reserved :: 10 bytes total, set to 0 for compatibility with future options

	padLen :: 2 bytes, big endian, length of the padding, 0 or more
				Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
				(Distribution is implementation-dependent)

	tsB :: 4 bytes, big endian, Unix timestamp, unsigned seconds.
			Wraps around in 2106


	Notes
	`````
	- Alice must reject connections where the timestamp value is too far off from
	the current time. Call the maximum delta time "D".  Alice must maintain a
	local cache of previously-used handshake values and reject duplicates, to
	prevent replay attacks. Values in the cache must have a lifetime of at least
	2*D.  The cache values are implementation-dependent, however the 32-byte Y
	value (or its encrypted equivalent) may be used.

	Issues
	``````
	- Include min/max padding options here?



	Encryption for for handshake message 3 part 1, using message 2 KDF)
	-------------------------------------------------------------------

		// take h saved from message 2 KDF
	// MixHash(ciphertext)
	h = SHA256(h || 24 byte encrypted payload from message 2)

	// MixHash(padding)
	// Only if padding length is nonzero
	h = SHA256(h || random padding from message 2)
	// h is used as the associated data for the AEAD in message 3 part 1, below

	This is the "s" message pattern:

	Define s = Alice's static public key, 32 bytes

	// EncryptAndHash(s.publickey)
	// EncryptWithAd(h, s.publickey)
	// AEAD_ChaCha20_Poly1305(key, nonce, associatedData, data)
	// k is from handshake message 1
	// n is 1
	ciphertext = AEAD_ChaCha20_Poly1305(k, n++, h, s.publickey)
	// MixHash(ciphertext)
	// || below means append
	h = SHA256(h || ciphertext);

	// h is used as the associated data for the AEAD in message 3 part 2

	End of "s" message pattern.



	Key Derivation Function (KDF) (for handshake message 3 part 2)
	--------------------------------------------------------------

	This is the "se" message pattern:

	// DH(s, re) == DH(e, rs)
	Define input_key_material = 32 byte DH result of Alice's static key and Bob's ephemeral key
	Set input_key_material = X25519 DH result
	// overwrite Bob's ephemeral key in memory, no longer needed
	// Alice:
	re = (all zeros)
	// Bob:
	e(public and private) = (all zeros)

	// MixKey(DH())

	Define temp_key = 32 bytes
	Define HMAC-SHA256(key, data) as in [RFC-2104]
	// Generate a temp key from the chaining key and DH result
	// ck is the chaining key, from the KDF for handshake message 1
	temp_key = HMAC-SHA256(ck, input_key_material)
	// overwrite the DH result in memory, no longer needed
	input_key_material = (all zeros)

	// Output 1
	// Set a new chaining key from the temp key
	// byte() below means a single byte
	ck =       HMAC-SHA256(temp_key, byte(0x01)).

	// Output 2
	// Generate the cipher key k
	Define k = 32 bytes
	// || below means append
	// byte() below means a single byte
	k =        HMAC-SHA256(temp_key, ck || byte(0x02)).

	// h from message 3 part 1 is used as the associated data for the AEAD in message 3 part 2

	// EncryptAndHash(payload)
	// EncryptWithAd(h, payload)
	// AEAD_ChaCha20_Poly1305(key, nonce, associatedData, data)
	// n is 0
	ciphertext = AEAD_ChaCha20_Poly1305(k, n++, h, payload)
	// MixHash(ciphertext)
	// || below means append
	h = SHA256(h || ciphertext);

	// retain the chaining key ck for the data phase KDF
	// retain the hash h for the data phase Additional Symmetric Key (SipHash) KDF

	End of "se" message pattern.

	// overwrite the temp_key in memory, no longer needed
	temp_key = (all zeros)
**/

type SessionCreated struct {
	YContent [32]byte        // 32 bytes ephemeral key Y
	Options  *CreatedOptions // Options block
	Padding  []byte          // Random padding
}

// Payload implements Message.
func (s *SessionCreated) Payload() []byte {
	panic("unimplemented")
}

// PayloadSize implements Message.
func (s *SessionCreated) PayloadSize() int {
	panic("unimplemented")
}

// Type implements Message.
func (s *SessionCreated) Type() MessageType {
	panic("unimplemented")
}

var exampleSessionCreated Message = &SessionCreated{}

// CreatedOptions is the options block for SessionCreated.
// It is 16 bytes long.
// It contains the following fields:
// - 2 bytes padding length
// - 4 bytes timestamp
// - 10 bytes reserved
type CreatedOptions struct {
	PaddingLength *data.Integer
	Timestamp     *data.Date
}

// Data implements Options.
func (c *CreatedOptions) Data() []byte {
	data := make([]byte, 16)
	copy(data[0:2], c.PaddingLength.Bytes())
	copy(data[2:6], c.Timestamp.Bytes())
	return data
}

var exampleCreatedOptions Options = &CreatedOptions{}
