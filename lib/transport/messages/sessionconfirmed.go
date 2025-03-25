package messages

import (
	"github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
)

/**
	3) SessionConfirmed
	--------------------

	Alice sends to Bob.

	Noise content: Alice's static key
	Noise payload: Alice's RouterInfo and random padding
	Non-noise payload: none

	(Payload Security Properties)


	XK(s, rs):           Authentication   Confidentiality
		-> s, se                  2                5

		Authentication: 2.
		Sender authentication resistant to key-compromise impersonation (KCI).  The
		sender authentication is based on an ephemeral-static DH ("es" or "se")
		between the sender's static key pair and the recipient's ephemeral key
		pair.  Assuming the corresponding private keys are secure, this
		authentication cannot be forged.

		Confidentiality: 5.
		Encryption to a known recipient, strong forward secrecy.  This payload is
		encrypted based on an ephemeral-ephemeral DH as well as an ephemeral-static
		DH with the recipient's static key pair.  Assuming the ephemeral private
		keys are secure, and the recipient is not being actively impersonated by an
		attacker that has stolen its static private key, this payload cannot be
		decrypted.

		"s": Alice writes her static public key from the s variable into the
		message buffer, encrypting it, and hashes the output along with the old h
		to derive a new h.

		"se": A DH is performed between the Alice's static key pair and the Bob's
		ephemeral key pair.  The result is hashed along with the old ck to derive a
		new ck and k, and n is set to zero.


	This contains two ChaChaPoly frames.
	The first is Alice's encrypted static public key.
	The second is the Noise payload: Alice's encrypted RouterInfo, optional
	options, and optional padding.  They use different keys, because the MixKey()
	function is called in between.


	Raw contents:

	+----+----+----+----+----+----+----+----+
	|                                       |
	+   ChaChaPoly frame (48 bytes)         +
	|   Encrypted and authenticated         |
	+   Alice static key S                  +
	|      (32 bytes)                       |
	+                                       +
	|     k defined in KDF for message 2    |
	+     n = 1                             +
	|     see KDF for associated data       |
	+                                       +
	|                                       |
	+----+----+----+----+----+----+----+----+
	|                                       |
	+     Length specified in message 1     +
	|                                       |
	+   ChaChaPoly frame                    +
	|   Encrypted and authenticated         |
	+                                       +
	|       Alice RouterInfo                |
	+       using block format 2            +
	|       Alice Options (optional)        |
	+       using block format 1            +
	|       Arbitrary padding               |
	+       using block format 254          +
	|                                       |
	+                                       +
	| k defined in KDF for message 3 part 2 |
	+     n = 0                             +
	|     see KDF for associated data       |
	~               .   .   .               ~
	|                                       |
	+----+----+----+----+----+----+----+----+

	S :: 32 bytes, ChaChaPoly encrypted Alice's X25519 static key, little endian
		inside 48 byte ChaChaPoly frame


	Unencrypted data (Poly1305 auth tags not shown):

	+----+----+----+----+----+----+----+----+
	|                                       |
	+                                       +
	|              S                        |
	+       Alice static key                +
	|          (32 bytes)                   |
	+                                       +
	|                                       |
	+                                       +
	+----+----+----+----+----+----+----+----+
	|                                       |
	+                                       +
	|                                       |
	+                                       +
	|       Alice RouterInfo block          |
	~               .   .   .               ~
	|                                       |
	+----+----+----+----+----+----+----+----+
	|                                       |
	+       Optional Options block          +
	|                                       |
	~               .   .   .               ~
	|                                       |
	+----+----+----+----+----+----+----+----+
	|                                       |
	+       Optional Padding block          +
	|                                       |
	~               .   .   .               ~
	|                                       |
	+----+----+----+----+----+----+----+----+

	S :: 32 bytes, Alice's X25519 static key, little endian



	Notes
	`````
	- Bob must perform the usual Router Info validation.
	Ensure the signature type is supported, verify the signature,
	verify the timestamp is within bounds, and any other checks necessary.

	- Bob must verify that Alice's static key received in the first frame matches
	the static key in the Router Info. Bob must first search the Router Info for
	a NTCP or NTCP2 Router Address with a matching version (v) option.
	See Published Router Info and Unpublished Router Info sections below.

	- If Bob has an older version of Alice's RouterInfo in his netdb, verify
	that the static key in the router info is the same in both, if present,
	and if the older version is less than XXX old (see key rotate time below)

	- Bob must validate that Alice's static key is a valid point on the curve here.

	- Options should be included, to specify padding parameters.

	- On any error, including AEAD, RI, DH, timestamp, or key validation failure,
	Bob must halt further message processing and close the connection without
	responding.  This should be an abnormal close (TCP RST).

	- To facilitate rapid handshaking, implementations must ensure that Alice
	buffers and then flushes the entire contents of the third message at once,
	including both AEAD frames.
	This increases the likelihood that the data will be contained in a single TCP
	packet (unless segmented by the OS or middleboxes), and received all at once
	by Bob.  This is also for efficiency and to ensure the effectiveness of the
	random padding.

	- Message 3 part 2 frame length: The length of this frame (including MAC) is
	sent by Alice in message 1. See that message for important notes on allowing
	enough room for padding.

	- Message 3 part 2 frame content: This format of this frame is the same as the
	format of data phase frames, except that the length of the frame is sent
	by Alice in message 1. See below for the data phase frame format.
	The frame must contain 1 to 3 blocks in the following order:
	1) Alice's Router Info block (required)
	2) Options block (optional)
	3) Padding block (optional)
	This frame must never contain any other block type.

	- Message 3 part 2 padding is not required if Alice appends a data phase frame
	(optionally containing padding) to the end of message 3 and sends both at once,
	as it will appear as one big stream of bytes to an observer.
	As Alice will generally, but not always, have an I2NP message to send to Bob
	(that's why she connected to him), this is the recommended implementation,
	for efficiency and to ensure the effectiveness of the random padding.

	- Total length of both Message 3 AEAD frames (parts 1 and 2) is 65535 bytes;
	part 1 is 48 bytes so part 2 max frame length is 65487;
	part 2 max plaintext length excluding MAC is 65471.


	Key Derivation Function (KDF) (for data phase)
	----------------------------------------------

	The data phase uses a zero-length associated data input.


	The KDF generates two cipher keys k_ab and k_ba from the chaining key ck,
	using HMAC-SHA256(key, data) as defined in [RFC-2104].
	This is the Split() function, exactly as defined in the Noise spec.

	ck = from handshake phase

	// k_ab, k_ba = HKDF(ck, zerolen)
	// ask_master = HKDF(ck, zerolen, info="ask")

	// zerolen is a zero-length byte array
	temp_key = HMAC-SHA256(ck, zerolen)
	// overwrite the chaining key in memory, no longer needed
	ck = (all zeros)

	// Output 1
	// cipher key, for Alice transmits to Bob (Noise doesn't make clear which is which, but Java code does)
	k_ab =   HMAC-SHA256(temp_key, byte(0x01)).

	// Output 2
	// cipher key, for Bob transmits to Alice (Noise doesn't make clear which is which, but Java code does)
	k_ba =   HMAC-SHA256(temp_key, k_ab || byte(0x02)).


	KDF for SipHash for length field:
	Generate an Additional Symmetric Key (ask) for SipHash
	SipHash uses two 8-byte keys (big endian) and 8 byte IV for first data.

	// "ask" is 3 bytes, US-ASCII, no null termination
	ask_master = HMAC-SHA256(temp_key, "ask" || byte(0x01))
	// sip_master = HKDF(ask_master, h || "siphash")
	// "siphash" is 7 bytes, US-ASCII, no null termination
	// overwrite previous temp_key in memory
	// h is from KDF for message 3 part 2
	temp_key = HMAC-SHA256(ask_master, h || "siphash")
	// overwrite ask_master in memory, no longer needed
	ask_master = (all zeros)
	sip_master = HMAC-SHA256(temp_key, byte(0x01))

	Alice to Bob SipHash k1, k2, IV:
	// sipkeys_ab, sipkeys_ba = HKDF(sip_master, zerolen)
	// overwrite previous temp_key in memory
	temp_key = HMAC-SHA256(sip_master, zerolen)
	// overwrite sip_master in memory, no longer needed
	sip_master = (all zeros)

	sipkeys_ab = HMAC-SHA256(temp_key, byte(0x01)).
	sipk1_ab = sipkeys_ab[0:7], little endian
	sipk2_ab = sipkeys_ab[8:15], little endian
	sipiv_ab = sipkeys_ab[16:23]

	Bob to Alice SipHash k1, k2, IV:

	sipkeys_ba = HMAC-SHA256(temp_key, sipkeys_ab || byte(0x02)).
	sipk1_ba = sipkeys_ba[0:7], little endian
	sipk2_ba = sipkeys_ba[8:15], little endian
	sipiv_ba = sipkeys_ba[16:23]

	// overwrite the temp_key in memory, no longer needed
	temp_key = (all zeros)
**/

type SessionConfirmed struct {
	// ChaChaPoly encrypted Alice's X25519 static key
	StaticKey [32]byte
	// Alice RouterInfo block
	RouterInfo *router_info.RouterInfo
	// Alice Options (optional)
	Options *ConfirmedOptions
	// Arbitrary padding (optional)
	Padding []byte
}

// Payload implements Message.
func (s *SessionConfirmed) Payload() []byte {
	panic("unimplemented")
}

// PayloadSize implements Message.
func (s *SessionConfirmed) PayloadSize() int {
	panic("unimplemented")
}

// Type implements Message.
func (s *SessionConfirmed) Type() MessageType {
	panic("unimplemented")
}

var exampleSessionConfirmed Message = &SessionConfirmed{}

// ConfirmedOptions is the interface for SessionConfirmed options.
// It is 16 bytes long.
// It contains the following fields:
// - 1 byte: padding length
// - 15 bytes: reserved
type ConfirmedOptions struct {
	PaddingLength *data.Integer
}

// Data implements Options.
func (c *ConfirmedOptions) Data() []byte {
	data := make([]byte, 16)
	copy(data[0:1], c.PaddingLength.Bytes())
	return data
}

var exampleConfirmedOptions Options = &ConfirmedOptions{}
