======
NTCP 2
======
.. meta::
    :category: Transports
    :lastupdated: 2026-01
    :accuratefor: 0.9.66

.. contents::


Overview
========

NTCP2 is an authenticated key agreement protocol that improves the
resistance of [NTCP]_ to various forms of automated identification and attacks.

NTCP2 is designed for flexibility and coexistence with NTCP.
It may be supported on the same port as NTCP, or a different port, or without simultaneous NTCP support at all.
See the Published Router Info section below for details.

As with other I2P transports, NTCP2 is defined solely
for point-to-point (router-to-router) transport of I2NP messages.
It is not a general-purpose data pipe.

NTCP2 is supported as of version 0.9.36.
See [Prop111]_ for the original proposal, including background discussion and additional information.



Noise Protocol Framework
========================

NTCP2 uses the Noise Protocol Framework
[NOISE]_ (Revision 33, 2017-10-04).
Noise has similar properties to the Station-To-Station protocol
[STS]_, which is the basis for the [SSU]_ protocol.  In Noise parlance, Alice
is the initiator, and Bob is the responder.

NTCP2 is based on the Noise protocol Noise_XK_25519_ChaChaPoly_SHA256.
(The actual identifier for the initial key derivation function
is "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
to indicate I2P extensions - see KDF 1 section below)
This Noise protocol uses the following primitives:

- Handshake Pattern: XK
  Alice transmits her key to Bob (X)
  Alice knows Bob's static key already (K)

- DH Function: X25519
  X25519 DH with a key length of 32 bytes as specified in [RFC-7748]_.

- Cipher Function: ChaChaPoly
  AEAD_CHACHA20_POLY1305 as specified in [RFC-7539]_ section 2.8.
  12 byte nonce, with the first 4 bytes set to zero.

- Hash Function: SHA256
  Standard 32-byte hash, already used extensively in I2P.


Additions to the Framework
==========================

NTCP2 defines the following enhancements to
Noise_XK_25519_ChaChaPoly_SHA256.  These generally follow the guidelines in
[NOISE]_ section 13.

1) Cleartext ephemeral keys are obfuscated with AES encryption using a known
   key and IV.

2) Random cleartext padding is added to messages 1 and 2.
   The cleartext padding is included in the handshake hash (MixHash) calculation.
   See the KDF sections below for message 2 and message 3 part 1.
   Random AEAD padding is added to message 3 and data phase messages.

3) A two-byte frame length field is added, as is required for Noise over TCP,
   and as in obfs4. This is used in the data phase messages only.
   Message 1 and 2 AEAD frames are fixed length.
   Message 3 part 1 AEAD frame is fixed length.
   Message 3 part 2 AEAD frame length is specified in message 1.

4) The two-byte frame length field is obfuscated with SipHash-2-4,
   as in obfs4.

5) The payload format is defined for messages 1,2,3, and the data phase.
   Of course, these are not defined in the framework.



Messages
========

All NTCP2 messages are less than or equal to 65537 bytes in length. The message
format is based on Noise messages, with modifications for framing and indistinguishability.
Implementations using standard Noise libraries may need to pre-process received
messages to/from the Noise message format. All encrypted fields are AEAD
ciphertexts.


The establishment sequence is as follows:

.. raw:: html

  {% highlight %}
Alice                           Bob

  SessionRequest ------------------->
  <------------------- SessionCreated
  SessionConfirmed ----------------->
{% endhighlight %}

Using Noise terminology, the establishment and data sequence is as follows:
(Payload Security Properties from [Noise]_ )

.. raw:: html

  {% highlight lang='text' %}
XK(s, rs):           Authentication   Confidentiality
    <- s
    ...
    -> e, es                  0                2
    <- e, ee                  2                1
    -> s, se                  2                5
    <-                        2                5
{% endhighlight %}


Once a session has been established, Alice and Bob can exchange Data messages.

All message types (SessionRequest, SessionCreated, SessionConfirmed, Data and
TimeSync) are specified in this section.

Some notations::

  - RH_A = Router Hash for Alice (32 bytes)
  - RH_B = Router Hash for Bob (32 bytes)


Authenticated Encryption
------------------------

There are three separate authenticated encryption instances (CipherStates).
One during the handshake phase, and two (transmit and receive) for the data phase.
Each has its own key from a KDF.

Encrypted/authenticated data will be represented as 

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   Encrypted and authenticated data    |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+
{% endhighlight %}


ChaCha20/Poly1305
`````````````````

Encrypted and authenticated data format.

Inputs to the encryption/decryption functions:

.. raw:: html

  {% highlight lang='dataspec' %}

k :: 32 byte cipher key, as generated from KDF

  nonce :: Counter-based nonce, 12 bytes.
           Starts at 0 and incremented for each message.
           First four bytes are always zero.
           Last eight bytes are the counter, little-endian encoded.
           Maximum value is 2**64 - 2.
           Connection must be dropped and restarted after
           it reaches that value.
           The value 2**64 - 1 must never be sent.

  ad :: In handshake phase:
        Associated data, 32 bytes.
        The SHA256 hash of all preceding data.
        In data phase:
        Zero bytes

  data :: Plaintext data, 0 or more bytes

{% endhighlight %}

Output of the encryption function, input to the decryption function:

.. raw:: html

  {% highlight lang='dataspec' %}

+----+----+----+----+----+----+----+----+
  |Obfs Len |                             |
  +----+----+                             +
  |       ChaCha20 encrypted data         |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +              (MAC)                    +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  Obfs Len :: Length of (encrypted data + MAC) to follow, 16 - 65535
              Obfuscation using SipHash (see below)
              Not used in message 1 or 2, or message 3 part 1, where the length is fixed
              Not used in message 3 part 1, as the length is specified in message 1

  encrypted data :: Same size as plaintext data, 0 - 65519 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}

For ChaCha20, what is described here corresponds to [RFC-7539]_, which is also
used similarly in TLS [RFC-7905]_.

Notes
`````
- Since ChaCha20 is a stream cipher, plaintexts need not be padded.
  Additional keystream bytes are discarded.

- The key for the cipher (256 bits) is agreed upon by means of the SHA256 KDF.
  The details of the KDF for each message are in separate sections below.

- ChaChaPoly frames for messages 1, 2, and the first part of message 3,
  are of known size. Starting with the second part of message 3,
  frames are of variable size. The message 3 part 1 size is specified in message 1.
  Starting with the data phase, frames are prepended with a two-byte length
  obfuscated with SipHash as in obfs4.

- Padding is outside the authenticated data frame for messages 1 and 2.
  The padding is used in the KDF for the next message so tampering will
  be detected. Starting in message 3, padding is inside the authenticated
  data frame.


AEAD Error Handling
```````````````````
- In messages 1, 2, and message 3 parts 1 and 2, the AEAD message size is known in advance.
  On an AEAD authentication failure, recipient must halt further message processing and close the
  connection without responding.  This should be an abnormal close (TCP RST).

- For probing resistance, in message 1, after an AEAD failure, Bob should
  set a random timeout (range TBD) and then read a random number of bytes (range TBD)
  before closing the socket. Bob should maintain a blacklist of IPs with
  repeated failures.

- In the data phase, the AEAD message size is "encrypted" (obfuscated) with SipHash.
  Care must be taken to avoid creating a decryption oracle.
  On a data phase AEAD authentication failure, the recipient should
  set a random timeout (range TBD) and then read a random number of bytes (range TBD).
  After the read, or on read timeout, the recipient should send a payload
  with a termination block containing an "AEAD failure" reason code,
  and close the connection.

- Take the same error action for an invalid length field value in the data phase.


Key Derivation Function (KDF) (for handshake message 1)
-------------------------------------------------------

The KDF generates a handshake phase cipher key k from the DH result,
using HMAC-SHA256(key, data) as defined in [RFC-2104]_.
These are the InitializeSymmetric(), MixHash(), and MixKey() functions,
exactly as defined in the Noise spec.

.. raw:: html

  {% highlight lang='text' %}

This is the "e" message pattern:

  // Define protocol_name.
  Set protocol_name = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
   (48 bytes, US-ASCII encoded, no NULL termination).

  // Define Hash h = 32 bytes
  h = SHA256(protocol_name);

  Define ck = 32 byte chaining key. Copy the h data to ck.
  Set ck = h

  Define rs = Bob's 32-byte static key as published in the RouterInfo

  // MixHash(null prologue)
  h = SHA256(h);

  // up until here, can all be precalculated by Alice for all outgoing connections

  // Alice must validate that Bob's static key is a valid point on the curve here.

  // Bob static key
  // MixHash(rs)
  // || below means append
  h = SHA256(h || rs);

  // up until here, can all be precalculated by Bob for all incoming connections

  This is the "e" message pattern:

  Alice generates her ephemeral DH key pair e.

  // Alice ephemeral key X
  // MixHash(e.pubkey)
  // || below means append
  h = SHA256(h || e.pubkey);

  // h is used as the associated data for the AEAD in message 1
  // Retain the Hash h for the message 2 KDF


  End of "e" message pattern.

  This is the "es" message pattern:

  // DH(e, rs) == DH(s, re)
  Define input_key_material = 32 byte DH result of Alice's ephemeral key and Bob's static key
  Set input_key_material = X25519 DH result

  // MixKey(DH())

  Define temp_key = 32 bytes
  Define HMAC-SHA256(key, data) as in [RFC-2104]_
  // Generate a temp key from the chaining key and DH result
  // ck is the chaining key, defined above
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

  // retain the chaining key ck for message 2 KDF


  End of "es" message pattern.

{% endhighlight %}




1) SessionRequest
------------------

Alice sends to Bob.

Noise content: Alice's ephemeral key X
Noise payload: 16 byte option block
Non-noise payload: Random padding

(Payload Security Properties from [Noise]_ )

.. raw:: html

  {% highlight lang='text' %}
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


{% endhighlight %}

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

.. raw:: html

  {% highlight lang='dataspec' %}
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

{% endhighlight %}

Unencrypted data (Poly1305 authentication tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
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

{% endhighlight %}

Options block:
Note: All fields are big-endian.

.. raw:: html

  {% highlight lang='dataspec' %}
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

{% endhighlight %}

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
  Java implementations currently limit padding to 256 bytes max.

- On any error, including AEAD, DH, timestamp, apparent replay, or key
  validation failure, Bob must halt further message processing and close the
  connection without responding.  This should be an abnormal close (TCP RST).
  For probing resistance, after an AEAD failure, Bob should
  set a random timeout (range TBD) and then read a random number of bytes (range TBD),
  before closing the socket.

- Bob may do a fast MSB check for a valid key (X[31] & 0x80 == 0) before
  attempting decryption. If the high bit is set, implement probing resistance
  as for AEAD failures.

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

.. raw:: html

  {% highlight lang='text' %}

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
  Define HMAC-SHA256(key, data) as in [RFC-2104]_
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

{% endhighlight %}


2) SessionCreated
------------------

Bob sends to Alice.

Noise content: Bob's ephemeral key Y
Noise payload: 16 byte option block
Non-noise payload: Random padding

(Payload Security Properties from [Noise]_ )

.. raw:: html

  {% highlight lang='text' %}
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

{% endhighlight %}

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

.. raw:: html

  {% highlight lang='dataspec' %}
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

{% endhighlight %}

Unencrypted data (Poly1305 auth tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
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

{% endhighlight %}

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

.. raw:: html

  {% highlight lang='dataspec' %}

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

{% endhighlight %}

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

.. raw:: html

  {% highlight lang='text' %}

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

{% endhighlight %}


Key Derivation Function (KDF) (for handshake message 3 part 2)
--------------------------------------------------------------

.. raw:: html

  {% highlight lang='text' %}

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
  Define HMAC-SHA256(key, data) as in [RFC-2104]_
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

{% endhighlight %}


3) SessionConfirmed
--------------------

Alice sends to Bob.

Noise content: Alice's static key
Noise payload: Alice's RouterInfo and random padding
Non-noise payload: none

(Payload Security Properties from [Noise]_ )


.. raw:: html

  {% highlight lang='text' %}
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

{% endhighlight %}

This contains two ChaChaPoly frames.
The first is Alice's encrypted static public key.
The second is the Noise payload: Alice's encrypted RouterInfo, optional
options, and optional padding.  They use different keys, because the MixKey()
function is called in between.


Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
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

{% endhighlight %}

Unencrypted data (Poly1305 auth tags not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
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


{% endhighlight %}


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
using HMAC-SHA256(key, data) as defined in [RFC-2104]_.
This is the Split() function, exactly as defined in the Noise spec.

.. raw:: html

  {% highlight lang='text' %}

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

{% endhighlight %}




4) Data Phase
-------------

Noise payload: As defined below, including random padding
Non-noise payload: none

Starting with the 2nd part of message 3, all messages are inside
an authenticated and encrypted ChaChaPoly "frame"
with a prepended two-byte obfuscated length.
All padding is inside the frame.
Inside the frame is a standard format with zero or more "blocks".
Each block has a one-byte type and a two-byte length.
Types include date/time, I2NP message, options, termination, and padding.

Note: Bob may, but is not required, to send his RouterInfo to Alice as
his first message to Alice in the data phase.

(Payload Security Properties from [Noise]_ )


.. raw:: html

  {% highlight lang='text' %}
XK(s, rs):           Authentication   Confidentiality
    <-                        2                5
    ->                        2                5

    Authentication: 2.
    Sender authentication resistant to key-compromise impersonation (KCI).
    The sender authentication is based on an ephemeral-static DH ("es" or "se")
    between the sender's static key pair and the recipient's ephemeral key pair.
    Assuming the corresponding private keys are secure, this authentication cannot be forged.

    Confidentiality: 5.
    Encryption to a known recipient, strong forward secrecy.
    This payload is encrypted based on an ephemeral-ephemeral DH as well as
    an ephemeral-static DH with the recipient's static key pair.
    Assuming the ephemeral private keys are secure, and the recipient is not being actively impersonated
    by an attacker that has stolen its static private key, this payload cannot be decrypted.

{% endhighlight %}

Notes
`````
- For efficiency and to minimize identification of the length field,
  implementations must ensure that the sender buffers and then flushes the entire contents
  of data messages at once, including the length field and the AEAD frame.
  This increases the likelihood that the data will be contained in a single TCP packet
  (unless segmented by the OS or middleboxes), and received all at once the other party.
  This is also for efficiency and to ensure the effectiveness of the random padding.

- The router may choose to terminate the session on AEAD error, or may continue to attempt communications.
  If continuing, the router should terminate after repeated errors.



SipHash obfuscated length
`````````````````````````
Reference: [SipHash]_

Once both sides have completed the handshake, they transfer payloads
that are then encrypted and authenticated in ChaChaPoly "frames".

Each frame is preceded by a two-byte length, big endian.
This length specifies the number of encrypted frame bytes to follow,
including the MAC.
To avoid transmitting identifiable length fields in stream, the frame length
is obfuscated by XORing a mask derived from SipHash, as initialized
from the data phase KDF.
Note that the two directions have unique SipHash keys and IVs from the KDF.

.. raw:: html

  {% highlight lang='text' %}
      sipk1, sipk2 = The SipHash keys from the KDF.  (two 8-byte long integers)
      IV[0] = sipiv = The SipHash IV from the KDF. (8 bytes)
      length is big endian.
      For each frame:
        IV[n] = SipHash-2-4(sipk1, sipk2, IV[n-1])
        Mask[n] = First 2 bytes of IV[n]
        obfuscatedLength = length ^ Mask[n]

      The first length output will be XORed with with IV[1].

{% endhighlight %}

The receiver has the identical SipHash keys and IV.
Decoding the length is done by deriving the mask used to obfsucate the length and XORing the truncated
digest to obtain the length of the frame.
The frame length is the total length of the encrypted frame including the MAC.

Notes
`````
- If you use a SipHash library function that returns an unsigned long integer,
  use the least significant two bytes as the Mask.
  Convert the long integer to the next IV as little endian.



Raw contents
````````````

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |obf size |                             |
  +----+----+                             +
  |                                       |
  +   ChaChaPoly frame                    +
  |   Encrypted and authenticated         |
  +   key is k_ab for Alice to Bob        +
  |   key is k_ba for Bob to Alice        |
  +   as defined in KDF for data phase    +
  |   n starts at 0 and increments        |
  +   for each frame in that direction    +
  |   no associated data                  |
  +   16 bytes minimum                    +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  obf size :: 2 bytes length obfuscated with SipHash
              when de-obfuscated: 16 - 65535

  Minimum size including length field is 18 bytes.
  Maximum size including length field is 65537 bytes.
  Obfuscated length is 2 bytes.
  Maximum ChaChaPoly frame is 65535 bytes.

{% endhighlight %}

Notes
`````
- As the receiver must get the entire frame to check the MAC,
  it is recommended that the sender limit frames to a few KB
  rather than maximizing the frame size.
  This will minimize latency at the receiver.



Unencrypted data
````````````````
There are zero or more blocks in the encrypted frame.
Each block contains a one-byte identifier, a two-byte length,
and zero or more bytes of data.

For extensibility, receivers must ignore blocks with unknown identifiers,
and treat them as padding.

Encrypted data is 65535 bytes max, including a 16-byte authentication header,
so the max unencrypted data is 65519 bytes.

(Poly1305 auth tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |blk |  size   |       data             |
  +----+----+----+                        +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |blk |  size   |       data             |
  +----+----+----+                        +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  ~               .   .   .               ~

  blk :: 1 byte
         0 for datetime
         1 for options
         2 for RouterInfo
         3 for I2NP message
         4 for termination
         224-253 reserved for experimental features
         254 for padding
         255 reserved for future extension
  size :: 2 bytes, big endian, size of data to follow, 0 - 65516
  data :: the data

  Maximum ChaChaPoly frame is 65535 bytes.
  Poly1305 tag is 16 bytes
  Maximum total block size is 65519 bytes
  Maximum single block size is 65519 bytes
  Block type is 1 byte
  Block length is 2 bytes
  Maximum single block data size is 65516 bytes.

{% endhighlight %}


Block Ordering Rules
````````````````````
In the handshake message 3 part 2, order must be:
RouterInfo, followed by Options if present, followed by Padding if present.
No other blocks are allowed.

In the data phase, order is unspecified, except for the
following requirements:
Padding, if present, must be the last block.
Termination, if present, must be the last block except for Padding.

There may be multiple I2NP blocks in a single frame.
Multiple Padding blocks are not allowed in a single frame.
Other block types probably won't have multiple blocks in
a single frame, but it is not prohibited.



DateTime
````````
Special case for time synchronization:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+
  | 0  |    4    |     timestamp     |
  +----+----+----+----+----+----+----+

  blk :: 0
  size :: 2 bytes, big endian, value = 4
  timestamp :: Unix timestamp, unsigned seconds.
               Wraps around in 2106

{% endhighlight %}

NOTE: Implementations must round to the nearest second to prevent clock bias in the network.

Options
```````
Pass updated options.
Options include: Min and max padding.

Options block will be variable length.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 1  |  size   |tmin|tmax|rmin|rmax|tdmy|
  +----+----+----+----+----+----+----+----+
  |tdmy|  rdmy   |  tdelay |  rdelay |    |
  ~----+----+----+----+----+----+----+    ~
  |              more_options             |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 1
  size :: 2 bytes, big endian, size of options to follow, 12 bytes minimum

  tmin, tmax, rmin, rmax :: requested padding limits
      tmin and rmin are for desired resistance to traffic analysis.
      tmax and rmax are for bandwidth limits.
      tmin and tmax are the transmit limits for the router sending this options block.
      rmin and rmax are the receive limits for the router sending this options block.
      Each is a 4.4 fixed-point float representing 0 to 15.9375
      (or think of it as an unsigned 8-bit integer divided by 16.0).
      This is the ratio of padding to data. Examples:
      Value of 0x00 means no padding
      Value of 0x01 means add 6 percent padding
      Value of 0x10 means add 100 percent padding
      Value of 0x80 means add 800 percent (8x) padding
      Alice and Bob will negotiate the minimum and maximum in each direction.
      These are guidelines, there is no enforcement.
      Sender should honor receiver's maximum.
      Sender may or may not honor receiver's minimum, within bandwidth constraints.

  tdmy: Max dummy traffic willing to send, 2 bytes big endian, bytes/sec average
  rdmy: Requested dummy traffic, 2 bytes big endian, bytes/sec average
  tdelay: Max intra-message delay willing to insert, 2 bytes big endian, msec average
  rdelay: Requested intra-message delay, 2 bytes big endian, msec average

  Padding distribution specified as additional parameters?
  Random delay specified as additional parameters?

  more_options :: Format TBD

{% endhighlight %}


Options Issues
``````````````
- Options format is TBD.
- Options negotiation is TBD.


RouterInfo
``````````
Pass Alice's RouterInfo to Bob.
Used in handshake message 3 part 2.
Pass Alice's RouterInfo to Bob, or Bob's to Alice.
Used optionally in the data phase.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 2  |  size   |flg |    RouterInfo     |
  +----+----+----+----+                   +
  | (Alice RI in handshake msg 3 part 2)  |
  ~ (Alice, Bob, or third-party           ~
  |  RI in data phase)                    |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 2
  size :: 2 bytes, big endian, size of flag + router info to follow
  flg :: 1 byte flags
         bit order: 76543210
         bit 0: 0 for local store, 1 for flood request
         bits 7-1: Unused, set to 0 for future compatibility
  routerinfo :: Alice's or Bob's RouterInfo


{% endhighlight %}

Notes
`````
- When used in the data phase, receiver (Alice or Bob) shall validate that
  it's the same Router Hash as originally sent (for Alice) or sent to (for Bob).
  Then, treat it as a local I2NP DatabaseStore Message. Validate signature,
  validate more recent timestamp, and store in the local netdb.
  If the flag bit 0 is 1, and the receiving party is floodfill,
  treat it as a DatabaseStore Message with a nonzero reply token,
  and flood it to the nearest floodfills.

- The Router Info is NOT compressed with gzip
  (unlike in a DatabaseStore Message, where it is)

- Flooding must not be requested unless there are published
  RouterAddresses in the RouterInfo. The receiving router
  must not flood the RouterInfo unless there are published
  RouterAddresses in it.

- Implementers must ensure that when reading a block,
  malformed or malicious data will not cause reads to
  overrun into the next block.

- This protocol does not provide an acknowledgement that the RouterInfo
  was received, stored, or flooded (either in the handshake or data phase).
  If acknowledgement is desired, and the receiver is floodfill,
  the sender should instead send a standard I2NP DatabaseStoreMessage
  with a reply token.


Issues
``````
- Could also be used in data phase, instead of a I2NP DatabaseStoreMessage.
  For example, Bob could use it to start off the data phase.

- Is it allowed for this to contain the RI for routers other than the
  originator, as a general replacement for DatabaseStoreMessages,
  e.g. for flooding by floodfills?


I2NP Message
````````````

An single I2NP message with a modified header.
I2NP messages may not be fragmented across blocks or
across ChaChaPoly frames.

This uses the first 9 bytes from the standard NTCP I2NP header,
and removes the last 7 bytes of the header, as follows:
shorten the expiration from 8 to 4 bytes
(seconds instead of milliseconds, same as for SSU),
remove the 2 byte length (use the block size - 9),
and remove the one-byte SHA256 checksum.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 3  |  size   |type|    msg id         |
  +----+----+----+----+----+----+----+----+
  |   short exp       |     message       |
  +----+----+----+----+                   +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 3
  size :: 2 bytes, big endian, size of type + msg id + exp + message to follow
          I2NP message body size is (size - 9).
  type :: 1 byte, I2NP msg type, see I2NP spec
  msg id :: 4 bytes, big endian, I2NP message ID
  short exp :: 4 bytes, big endian, I2NP message expiration, Unix timestamp, unsigned seconds.
               Wraps around in 2106
  message :: I2NP message body

{% endhighlight %}

Notes
`````
- Implementers must ensure that when reading a block,
  malformed or malicious data will not cause reads to
  overrun into the next block.



Termination
```````````
Noise recommends an explicit termination message.
Original NTCP doesn't have one.
Drop the connection.
This must be the last non-padding block in the frame.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 4  |  size   |    valid data frames   |
  +----+----+----+----+----+----+----+----+
      received   | rsn|     addl data     |
  +----+----+----+----+                   +
  ~               .   .   .               ~
  +----+----+----+----+----+----+----+----+

  blk :: 4
  size :: 2 bytes, big endian, value = 9 or more
  valid data frames received :: The number of valid AEAD data phase frames received
                                (current receive nonce value)
                                0 if error occurs in handshake phase
                                8 bytes, big endian
  rsn :: reason, 1 byte:
         0: normal close or unspecified
         1: termination received
         2: idle timeout
         3: router shutdown
         4: data phase AEAD failure
         5: incompatible options
         6: incompatible signature type
         7: clock skew
         8: padding violation
         9: AEAD framing error
         10: payload format error
         11: message 1 error
         12: message 2 error
         13: message 3 error
         14: intra-frame read timeout
         15: RI signature verification fail
         16: s parameter missing, invalid, or mismatched in RouterInfo
         17: banned
  addl data :: optional, 0 or more bytes, for future expansion, debugging,
               or reason text.
               Format unspecified and may vary based on reason code.

{% endhighlight %}

Notes
`````
Not all reasons may actually be used, implementation dependent.
Handshake failures will generally result in a close with TCP RST instead.
See notes in handshake message sections above.
Additional reasons listed are for consistency, logging, debugging, or if policy changes.




Padding
```````
This is for padding inside AEAD frames.
Padding for messages 1 and 2 are outside AEAD frames.
All padding for message 3 and the data phase are inside AEAD frames.

Padding inside AEAD should roughly adhere to the negotiated parameters.
Bob sent his requested tx/rx min/max parameters in message 2.
Alice sent her requested tx/rx min/max parameters in message 3.
Updated options may be sent during the data phase.
See options block information above.

If present, this must be the last block in the frame.



.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |254 |  size   |      padding           |
  +----+----+----+                        +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 254
  size :: 2 bytes, big endian, size of padding to follow
  padding :: random data

{% endhighlight %}

Notes
`````
- Size = 0 is allowed.
- Padding strategies TBD.
- Minimum padding TBD.
- Padding-only frames are allowed.
- Padding defaults TBD.
- See options block for padding parameter negotiation
- See options block for min/max padding parameters
- Noise limits messages to 64KB. If more padding is necessary, send multiple frames.
- Router response on violation of negotiated padding is implementation-dependent.


Other block types
`````````````````
Implementations should ignore unknown block types for
forward compatibility, except in message 3 part 2, where
unknown blocks are not allowed.


Future work
```````````
- The padding length is either to be decided on a per-message basis and
  estimates of the length distribution, or random delays should be added.
  These countermeasures are to be included to resist DPI, as message sizes
  would otherwise reveal that I2P traffic is being carried by the transport
  protocol. The exact padding scheme is an area of future work.


5) Termination
--------------

Connections may be terminated via normal or abnormal TCP socket close,
or, as Noise recommends, an explicit termination message.
The explicit termination message is defined in the data phase above.

Upon any normal or abnormal termination, routers should
zero-out any in-memory ephemeral data, including handshake ephemeral keys,
symmetric crypto keys, and related information.



Published Router Info
=====================

Capabilities
------------

As of release 0.9.50, the "caps" option is supported in NTCP2 addresses,
similar to SSU.
One or more capabilities may be published in the "caps" option.
Capabilities may be in any order, but "46" is the recommended order, for consistency across implementations.
There are two capabilities defined:

4: Indicates outbound IPv4 capability.
If an IP is published in the host field, this capability is not necessary.
If the router is hidden, or NTCP2 is outbound only, '4' and '6' may be combined in a single address.

6: Indicates outbound IPv6 capability.
If an IP is published in the host field, this capability is not necessary.
If the router is hidden, or NTCP2 is outbound only, '4' and '6' may be combined in a single address.



Published Addresses
-------------------


The published RouterAddress (part of the RouterInfo) will have a
protocol identifier of either "NTCP" or "NTCP2".

The RouterAddress must contain "host" and "port" options, as in
the current NTCP protocol.

The RouterAddress must contain three options
to indicate NTCP2 support:

- s=(Base64 key)
  The current Noise static public key (s) for this RouterAddress.
  Base 64 encoded using the standard I2P Base 64 alphabet.
  32 bytes in binary, 44 bytes as Base 64 encoded,
  little-endian X25519 public key.

- i=(Base64 IV)
  The current IV for encrypting the X value in message 1 for this RouterAddress.
  Base 64 encoded using the standard I2P Base 64 alphabet.
  16 bytes in binary, 24 bytes as Base 64 encoded,
  big-endian.

- v=2
  The current version (2).
  When published as "NTCP", additional support for version 1 is implied.
  Support for future versions will be with comma-separated values,
  e.g. v=2,3
  Implementation should verify compatibility, including multiple
  versions if a comma is present. Comma-separated versions must
  be in numerical order.

Alice must verify that all three options are present and valid
before connecting using the NTCP2 protocol.

When published as "NTCP" with "s", "i", and "v" options,
the router must accept incoming connections on that host and port
for both NTCP and NTCP2 protocols, and automatically detect the protocol
version.

When published as "NTCP2" with "s", "i", and "v" options,
the router accepts incoming connections on that host and port
for the NTCP2 protocol only.

If a router supports both NTCP1 and NTCP2 connections but
does not implement automatic version detection for incoming connections,
it must advertise both "NTCP" and "NTCP2" addresses, and include
the NTCP2 options in the "NTCP2" address only.
The router should set a lower cost value (higher priority)
in the "NTCP2" address than the "NTCP" address, so NTCP2 is preferred.

If multiple NTCP2 RouterAddresses (either as "NTCP" or "NTCP2") are published
in the same RouterInfo (for additional IP addresses or ports),
all addresses specifying the same port must contain the identical NTCP2 options and values.
In particular, all must contain the same static key and iv.



Unpublished NTCP2 Address
-------------------------

If Alice does not publish her NTCP2 address (as "NTCP" or "NTCP2") for incoming connections,
she must publish a "NTCP2" router address containing only her static key and NTCP2 version,
so that Bob may validate the key after receiving Alice's RouterInfo in message 3 part 2.

- s=(Base64 key)
  As defined above for published addresses.

- v=2
  As defined above for published addresses.

This router address will not contain "i", "host" or "port" options,
as these are not required for outbound NTCP2 connections.
The published cost for this address does not strictly matter, as it is inbound only;
however, it may be helpful to other routers if the cost is set higher (lower priority)
than other addresses. The suggested value is 14.

Alice may also simply add the "s" and "v" options to an existing published "NTCP" address.



Public Key and IV Rotation
--------------------------

Due to caching of RouterInfos, routers must not rotate the static public key or IV
while the router is up, whether in a published address or not. Routers must
persistently store this key and IV for reuse after an immediate restart, so incoming
connections will continue to work, and restart times are not exposed.  Routers
must persistently store, or otherwise determine, last-shutdown time, so that
the previous downtime may be calculated at startup.

Subject to concerns about exposing restart times, routers may rotate this key or IV
at startup if the router was previously down for some time (a couple hours at
least).

If the router has any published NTCP2 RouterAddresses (as NTCP or NTCP2), the
minimum downtime before rotation should be much longer, for example one month,
unless the local IP address has changed or the router "rekeys".

If the router has any published SSU RouterAddresses, but not NTCP2 (as NTCP or
NTCP2) the minimum downtime before rotation should be longer, for example one
day, unless the local IP address has changed or the router "rekeys".  This
applies even if the published SSU address has introducers.

If the router does not have any published RouterAddresses (NTCP, NTCP2, or
SSU), the minimum downtime before rotation may be as short as two hours, even
if the IP address changes, unless the router "rekeys".

If the router "rekeys" to a different Router Hash, it should generate a new
noise key and IV as well.

Implementations must be aware that changing the static public key or IV will prohibit
incoming NTCP2 connections from routers that have cached an older RouterInfo.
RouterInfo publishing, tunnel peer selection (including both OBGW and IB
closest hop), zero-hop tunnel selection, transport selection, and other
implementation strategies must take this into account.

IV rotation is subject to identical rules as key rotation, except that IVs are not present
except in published RouterAddresses, so there is no IV for hidden or firewalled
routers. If anything changes (version, key, options?) it is recommended that
the IV change as well.

Note: The minimum downtime before rekeying may be modified to ensure network
health, and to prevent reseeding by a router down for a moderate amount of
time.



Version Detection
=================

When published as "NTCP", the router must automatically detect the protocol
version for incoming connections.

This detection is implementation-dependent, but here is some general guidance.

To detect the version of an incoming NTCP connection, Bob proceeds as follows:

- Wait for at least 64 bytes (minimum NTCP2 message 1 size)
- If the initial received data is 288 or more bytes, the incoming connection
  is version 1.
- If less than 288 bytes, either

   - Wait for a short time for more data (good strategy before widespread NTCP2
     adoption) if at least 288 total received, it's NTCP 1.

   - Try the first stages of decoding as version 2, if it fails, wait a short
     time for more data (good strategy after widespread NTCP2 adoption)

      - Decrypt the first 32 bytes (the X key)
        of the SessionRequest packet using AES-256 with key RH_B.

      - Verify a valid point on the curve.
        If it fails, wait a short time for more data for NTCP 1

      - Verify the AEAD frame.
        If it fails, wait a short time for more data for NTCP 1

Note that changes or additional strategies may be recommended if we detect
active TCP segmentation attacks on NTCP 1.

To facilitate rapid version detection and handshaking, implementations must
ensure that Alice buffers and then flushes the entire contents of the first
message at once, including the padding.
This increases the likelihood that the data will be contained in a single TCP
packet (unless segmented by the OS or middleboxes), and received all at once by
Bob.  This is also for efficiency and to ensure the effectiveness of the random
padding.
This applies to both NTCP and NTCP2 handshakes.


Variants, Fallbacks, and General Issues
=======================================

- If Alice and Bob both support NTCP2, Alice should connect with NTCP2.

- If Alice fails to connect to Bob using NTCP2 for any reason, the connection fails.
  Alice may not retry using NTCP 1.


Clock Skew Guidelines
======================

Peer timestamps are included in the first two handshake messages, Session Request and Session Created.
A clock skew between two peers of greater than +/- 60 seconds is generally fatal.
If Bob thinks that his local clock is bad, he may adjust his clock using the
calculated skew, or some external source.
Otherwise, Bob should reply with a Session Created even if the maximum skew is exceeded,
rather than simply closing the connection. This allows Alice to get Bob's timestamp and
calculate the skew, and take action if necessary.
Bob does not have Alice's router identity at this point, but
to conserve resources,
it may be desirable for Bob to ban incoming connections from Alice's IP for some period of time,
or after repeated connection attempts with an excessive skew.

Alice should adjust the calculated clock skew by subtracting half the RTT.
If Alice thinks that her local clock is bad, she may adjust her clock using the
calculated skew, or some external source.
If Alice thinks that Bob's clock is bad, she may ban Bob for some period of time.
In either case, Alice should close the connection.

If Alice does reply with Session Confirmed
(probably because the skew is very close to the 60s limit,
and the Alice and Bob calculations are not exactly the same due to RTT),
Bob should adjust the calculated clock skew by subtracting half the RTT.
If the adjusted clock skew exceeds the maximum, Bob should then reply with
a Disconnect message containing a clock skew reason code, and close
the connection. At this point, Bob has Alice's router identity,
and may ban Alice for some period of time.


References
==========

.. [IACR-1150]
    https://eprint.iacr.org/2015/1150 

.. [NetDB]
    {{ site_url('docs/how/network-database', True) }}

.. [NOISE]
    https://noiseprotocol.org/noise.html

.. [NTCP]
    {{ site_url('docs/transport/ntcp', True) }}

.. [Prop104]
    {{ proposal_url('104') }}

.. [Prop109]
    {{ proposal_url('109') }}

.. [Prop111]
    {{ proposal_url('111') }}

.. [RFC-2104]
    https://tools.ietf.org/html/rfc2104

.. [RFC-3526]
    https://tools.ietf.org/html/rfc3526

.. [RFC-6151]
    https://tools.ietf.org/html/rfc6151

.. [RFC-7539]
    https://tools.ietf.org/html/rfc7539

.. [RFC-7748]
    https://tools.ietf.org/html/rfc7748

.. [RFC-7905]
    https://tools.ietf.org/html/rfc7905

.. [RouterAddress]
    {{ ctags_url('RouterAddress') }}

.. [RouterIdentity]
    {{ ctags_url('RouterIdentity') }}

.. [SIDH]
    De Feo, Luca; Jao, Plut., Towards quantum-resistant cryptosystems from
    supersingular elliptic curve isogenies

.. [SigningPublicKey]
    {{ ctags_url('SigningPublicKey') }}

.. [SipHash]
    https://www.131002.net/siphash/

.. [SSU]
    {{ site_url('docs/transport/ssu', True) }}

.. [STS]
    Diffie, W.; van Oorschot P. C.; Wiener M. J., Authentication and
    Authenticated Key Exchanges

.. [Ticket1112]
    https://{{ i2pconv('trac.i2p2.i2p') }}/ticket/1112

.. [Ticket1849]
    https://{{ i2pconv('trac.i2p2.i2p') }}/ticket/1849

.. [1] http://www.chesworkshop.org/ches2009/presentations/01_Session_1/CHES2009_ekasper.pdf

.. [2] https://www.blackhat.com/docs/us-16/materials/us-16-Devlin-Nonce-Disrespecting-Adversaries-Practical-Forgery-Attacks-On-GCM-In-TLS.pdf

.. [3] https://eprint.iacr.org/2014/613.pdf

.. [4] https://www.imperialviolet.org/2013/10/07/chacha20.html

.. [5] https://tools.ietf.org/html/rfc7539
