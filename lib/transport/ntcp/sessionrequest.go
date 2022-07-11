package ntcp

/**
	1) SessionRequest
	------------------

	Alice sends to Bob.

	Noise content: Alice's ephemeral key X
	Noise payload: 16 byte option block
	Non-noise payload: Random padding

	(Payload Security Properties)

	XK(s, rs):           Authentication   Confidentiality
		-> e, es                  0                2

		Authentication: None (0).
		This payload may have been sent by any party, including an active attacker.

		Confidentiality: 2.
		Encryption to a known recipient, forward secrecy for sender compromise
		only, vulnerable to replay.  This payload is encrypted based only on DHs
		involving the recipient's static key pair.  If the recipient's static
		private key is compromised, even at a later date, this payload can be
		decrypted.  This message can also be replayed, since there's no ephemeral
		contribution from the recipient.

		"e": Alice generates a new ephemeral key pair and stores it in the e
			variable, writes the ephemeral public key as cleartext into the
			message buffer, and hashes the public key along with the old h to
			derive a new h.

		"es": A DH is performed between the Alice's ephemeral key pair and the
			Bob's static key pair.  The result is hashed along with the old ck to
			derive a new ck and k, and n is set to zero.


	The X value is encrypted to ensure payload indistinguishably
	and uniqueness, which are necessary DPI countermeasures.
	We use AES encryption to achieve this,
	rather than more complex and slower alternatives such as elligator2.
	Asymmetric encryption to Bob's router public key would be far too slow.
	AES encryption uses Bob's router hash as the key and Bob's IV as published
	in the network database.

	AES encryption is for DPI resistance only.
	Any party knowing Bob's router hash, and IV, which are published in the network database,
	may decrypt the X value in this message.

	The padding is not encrypted by Alice.
	It may be necessary for Bob to decrypt the padding,
	to inhibit timing attacks.


	Raw contents:

	+----+----+----+----+----+----+----+----+
	|                                       |
	+        obfuscated with RH_B           +
	|       AES-CBC-256 encrypted X         |
	+             (32 bytes)                +
	|                                       |
	+                                       +
	|                                       |
	+----+----+----+----+----+----+----+----+
	|                                       |
	+                                       +
	|   ChaChaPoly frame                    |
	+             (32 bytes)                +
	|   k defined in KDF for message 1      |
	+   n = 0                               +
	|   see KDF for associated data         |
	+----+----+----+----+----+----+----+----+
	|     unencrypted authenticated         |
	~         padding (optional)            ~
	|     length defined in options block   |
	+----+----+----+----+----+----+----+----+

	X :: 32 bytes, AES-256-CBC encrypted X25519 ephemeral key, little endian
			key: RH_B
			iv: As published in Bobs network database entry

	padding :: Random data, 0 or more bytes.
				Total message length must be 65535 bytes or less.
				Total message length must be 287 bytes or less if
				Bob is publishing his address as NTCP
				(see Version Detection section below).
				Alice and Bob will use the padding data in the KDF for message 2.
				It is authenticated so that any tampering will cause the
				next message to fail.


	Unencrypted data (Poly1305 authentication tag not shown):

	+----+----+----+----+----+----+----+----+
	|                                       |
	+                                       +
	|                   X                   |
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

	X :: 32 bytes, X25519 ephemeral key, little endian

	options :: options block, 16 bytes, see below

	padding :: Random data, 0 or more bytes.
				Total message length must be 65535 bytes or less.
				Total message length must be 287 bytes or less if
				Bob is publishing his address as "NTCP"
				(see Version Detection section below)
				Alice and Bob will use the padding data in the KDF for message 2.
				It is authenticated so that any tampering will cause the
				next message to fail.


	Options block:
	Note: All fields are big-endian.

	+----+----+----+----+----+----+----+----+
	| id | ver|  padLen | m3p2len | Rsvd(0) |
	+----+----+----+----+----+----+----+----+
	|        tsA        |   Reserved (0)    |
	+----+----+----+----+----+----+----+----+

	id :: 1 byte, the network ID (currently 2, except for test networks)
			As of 0.9.42. See proposal 147.

	ver :: 1 byte, protocol version (currently 2)

	padLen :: 2 bytes, length of the padding, 0 or more
				Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
				(Distribution is implementation-dependent)

	m3p2Len :: 2 bytes, length of the the second AEAD frame in SessionConfirmed
				(message 3 part 2) See notes below

	Rsvd :: 2 bytes, set to 0 for compatibility with future options

	tsA :: 4 bytes, Unix timestamp, unsigned seconds.
			Wraps around in 2106

	Reserved :: 4 bytes, set to 0 for compatibility with future options


	Notes
	`````
	- When the published address is "NTCP", Bob supports both NTCP and NTCP2 on the
	same port. For compatibility, when initiating a connection to an address
	published as "NTCP", Alice must limit the maximum size of this message,
	including padding, to 287 bytes or less.  This facilitates automatic protocol
	identification by Bob.  When published as "NTCP2", there is no size
	restriction.  See the Published Addresses and Version Detection sections
	below.

	- The unique X value in the initial AES block ensure that the ciphertext is
	different for every session.

	- Bob must reject connections where the timestamp value is too far off from the
	current time. Call the maximum delta time "D".  Bob must maintain a local
	cache of previously-used handshake values and reject duplicates, to prevent
	replay attacks. Values in the cache must have a lifetime of at least 2*D.
	The cache values are implementation-dependent, however the 32-byte X value
	(or its encrypted equivalent) may be used.

	- Diffie-Hellman ephemeral keys may never be reused, to prevent cryptographic attacks,
	and reuse will be rejected as a replay attack.

	- The "KE" and "auth" options must be compatible, i.e. the shared secret K must
	be of the appropriate size. If more "auth" options are added, this could
	implicitly change the meaning of the "KE" flag to use a different KDF or a
	different truncation size.

	- Bob must validate that Alice's ephemeral key is a valid point on the curve
	here.

	- Padding should be limited to a reasonable amount.  Bob may reject connections
	with excessive padding.  Bob will specify his padding options in message 2.
	Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
	(Distribution is implementation-dependent)

	- On any error, including AEAD, DH, timestamp, apparent replay, or key
	validation failure, Bob must halt further message processing and close the
	connection without responding.  This should be an abnormal close (TCP RST).
	For probing resistance, after an AEAD failure, Bob should
	set a random timeout (range TBD) and then read a random number of bytes (range TBD),
	before closing the socket.

	- DoS Mitigation: DH is a relatively expensive operation. As with the previous NTCP protocol,
	routers should take all necessary measures to prevent CPU or connection exhaustion.
	Place limits on maximum active connections and maximum connection setups in progress.
	Enforce read timeouts (both per-read and total for "slowloris").
	Limit repeated or simultaneous connections from the same source.
	Maintain blacklists for sources that repeatedly fail.
	Do not respond to AEAD failure.

	- To facilitate rapid version detection and handshaking, implementations must
	ensure that Alice buffers and then flushes the entire contents of the first
	message at once, including the padding.  This increases the likelihood that
	the data will be contained in a single TCP packet (unless segmented by the OS
	or middleboxes), and received all at once by Bob.  Additionally,
	implementations must ensure that Bob buffers and then flushes the entire
	contents of the second message at once, including the padding.  and that Bob
	buffers and then flushes the entire contents of the third message at once.
	This is also for efficiency and to ensure the effectiveness of the random
	padding.

	- "ver" field: The overall Noise protocol, extensions, and NTCP protocol
	including payload specifications, indicating NTCP2.
	This field may be used to indicate support for future changes.

	- Message 3 part 2 length: This is the size of the second AEAD frame (including 16-byte MAC)
	containing Alice's Router Info and optional padding that will be sent in
	the SessionConfirmed message. As routers periodically regenerate and republish
	their Router Info, the size of the current Router Info may change before
	message 3 is sent. Implementations must choose one of two strategies:
	a) save the current Router Info to be sent in message 3, so the size is known,
	and optionally add room for padding;
	b) increase the specified size enough to allow for possible increase in
	the Router Info size, and always add padding when message 3 is actually sent.
	In either case, the "m3p2len" length included in message 1 must be exactly the
	size of that frame when sent in message 3.

	- Bob must fail the connection if any incoming data remains after validating
	message 1 and reading in the padding. There should be no extra data from Alice,
	as Bob has not responded with message 2 yet.

	- The network ID field is used to quickly identify cross-network connections.
	If this field is nonzero, and does not match Bob's network ID,
	Bob should disconnect and block future connections.
	Any connections from test networks should have a different ID and will fail the test.
	As of 0.9.42. See proposal 147 for more information.




	Key Derivation Function (KDF) (for handshake message 2 and message 3 part 1)
	----------------------------------------------------------------------------

		// take h saved from message 1 KDF
	// MixHash(ciphertext)
	h = SHA256(h || 32 byte encrypted payload from message 1)

	// MixHash(padding)
	// Only if padding length is nonzero
	h = SHA256(h || random padding from message 1)

	This is the "e" message pattern:

	Bob generates his ephemeral DH key pair e.

	// h is from KDF for handshake message 1
	// Bob ephemeral key Y
	// MixHash(e.pubkey)
	// || below means append
	h = SHA256(h || e.pubkey);

	// h is used as the associated data for the AEAD in message 2
	// Retain the Hash h for the message 3 KDF

	End of "e" message pattern.

	This is the "ee" message pattern:

	// DH(e, re)
	Define input_key_material = 32 byte DH result of Alice's ephemeral key and Bob's ephemeral key
	Set input_key_material = X25519 DH result
	// overwrite Alice's ephemeral key in memory, no longer needed
	// Alice:
	e(public and private) = (all zeros)
	// Bob:
	re = (all zeros)

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
	// overwrite the temp_key in memory, no longer needed
	temp_key = (all zeros)

	// retain the chaining key ck for message 3 KDF

	End of "ee" message pattern.
**/
