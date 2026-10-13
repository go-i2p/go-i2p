=========================
ECIES-X25519-AEAD-Ratchet
=========================
.. meta::
    :category: Protocols
    :lastupdated: 2025-06
    :accuratefor: 0.9.67

.. contents::


Note
====
Network deployment complete.
Subject to minor revisions.
See [Prop144]_ for the original proposal, including background discussion and additional information.

The following features are not implemented as of 0.9.66:

- MessageNumbers, Options, and Termination blocks
- Protocol-layer responses
- Zero static key
- Multicast

For the MLKEM PQ Hybrid version of this protocol, see [ECIES-HYBRID]_.


Overview
========

This is the new end-to-end encryption protocol
to replace ElGamal/AES+SessionTags [ElG-AES]_.

It relies on previous work as follows:

- Common structures spec [Common]_
- [I2NP]_ spec including LS2
- ElGamal/AES+Session Tags [Elg-AES]_
- http://zzz.i2p/topics/1768 new asymmetric crypto overview
- Low-level crypto overview [CRYPTO-ELG]_
- ECIES http://zzz.i2p/topics/2418
- [NTCP2]_ [Prop111]_
- 123 New netDB Entries
- 142 New Crypto Template
- [Noise]_ protocol
- [Signal]_ double ratchet algorithm

It supports new encryption for end-to-end,
destination-to-destination communication.

The design uses a Noise handshake and data phase incorporating Signal's double ratchet.

All references to Signal and Noise in this specification are for background information only.
Knowledge of Signal and Noise protocols is not required to understand
or implement this specification.

This specification is supported as of version 0.9.46.


Specification
=================

The design uses a Noise handshake and data phase incorporating Signal's double ratchet.


Summary of Cryptographic Design
-------------------------------

There are five portions of the protocol to be redesigned:


- 1) The new and Existing Session container formats
  are replaced with new formats.
- 2) ElGamal (256 byte public keys, 128 byte private keys) is be replaced
  with ECIES-X25519 (32 byte public and private keys)
- 3) AES is be replaced with
  AEAD_ChaCha20_Poly1305 (abbreviated as ChaChaPoly below)
- 4) SessionTags will be replaced with ratchets,
  which is essentially a cryptographic, synchronized PRNG.
- 5) The AES payload, as defined in the ElGamal/AES+SessionTags specification,
  is replaced with a block format similar to that in NTCP2.

Each of the five changes has its own section below.


Crypto Type
-----------

The crypto type (used in the LS2) is 4.
This indicates a little-endian 32-byte X25519 public key,
and the end-to-end protocol specified here.

Crypto type 0 is ElGamal.
Crypto types 1-3 are reserved for ECIES-ECDH-AES-SessionTag, see proposal 145 [Prop145]_.


Noise Protocol Framework
------------------------

This protocol provides the requirements based on the Noise Protocol Framework
[NOISE]_ (Revision 34, 2018-07-11).
Noise has similar properties to the Station-To-Station protocol
[STS]_, which is the basis for the [SSU]_ protocol.  In Noise parlance, Alice
is the initiator, and Bob is the responder.

This specification is based on the Noise protocol Noise_IK_25519_ChaChaPoly_SHA256.
(The actual identifier for the initial key derivation function
is "Noise_IKelg2_25519_ChaChaPoly_SHA256"
to indicate I2P extensions - see KDF 1 section below)
This Noise protocol uses the following primitives:

- Interactive Handshake Pattern: IK
  Alice immediately transmits her static key to Bob (I)
  Alice knows Bob's static key already (K)

- One-Way Handshake Pattern: N
  Alice does not transmit her static key to Bob (N)

- DH Function: X25519
  X25519 DH with a key length of 32 bytes as specified in [RFC-7748]_.

- Cipher Function: ChaChaPoly
  AEAD_CHACHA20_POLY1305 as specified in [RFC-7539]_ section 2.8.
  12 byte nonce, with the first 4 bytes set to zero.
  Identical to that in [NTCP2]_.

- Hash Function: SHA256
  Standard 32-byte hash, already used extensively in I2P.


Additions to the Framework
``````````````````````````

This specification defines the following enhancements to
Noise_IK_25519_ChaChaPoly_SHA256.  These generally follow the guidelines in
[NOISE]_ section 13.

1) Cleartext ephemeral keys are encoded with [Elligator2]_.

2) The reply is prefixed with a cleartext tag.

3) The payload format is defined for messages 1, 2, and the data phase.
   Of course, this is not defined in Noise.

All messages include an [I2NP]_ Garlic Message header.
The data phase uses encryption similar to, but not compatible with, the Noise data phase.


Handshake Patterns
------------------

Handshakes use [Noise]_ handshake patterns.

The following letter mapping is used:

- e = one-time ephemeral key
- s = static key
- p = message payload

One-time and Unbound sessions are similar to the Noise N pattern.

.. raw:: html

  {% highlight lang='dataspec' %}
<- s
  ...
  e es p ->

{% endhighlight %}

Bound sessions are similar to the Noise IK pattern.

.. raw:: html

  {% highlight lang='dataspec' %}
<- s
  ...
  e es s ss p ->
  <- tag e ee se
  <- p
  p ->

{% endhighlight %}


Security Properties
```````````````````

Using Noise terminology, the establishment and data sequence is as follows:
(Payload Security Properties from [Noise]_ )

.. raw:: html

  {% highlight lang='text' %}
IK(s, rs):           Authentication   Confidentiality
    <- s
    ...
    -> e, es, s, ss           1                2
    <- e, ee, se              2                4
    ->                        2                5
    <-                        2                5
{% endhighlight %}


Differences From XK
```````````````````
IK handshakes have several differences from XK handshakes used
in [NTCP2]_ and [SSU2]_.

- Four total DH operations compared to three for XK
- Sender authentication in first message: The payload is authenticated
  as belonging to the owner of the sender's public key, although
  the key could have been compromised (Authentication 1)
  XK requires another round trip before Alice is authenticated.
- Full forward secrecy (Confidentiality 5) after the second message.
  Bob may send a payload immediately after the second message with
  full forward secrecy.
  XK requires another round trip for full forward secrecy.

In summary, IK allows 1-RTT delivery of the response payload from Bob to Alice
with full forward secrecy, however the request payload is not forward-secret.


Sessions
--------

The ElGamal/AES+SessionTag protocol is unidirectional.
At this layer, the receiver doesn't know where a message is from.
Outbound and inbound sessions are not associated.
Acknowledgements are out-of-band using a DeliveryStatusMessage
(wrapped in a GarlicMessage) in the clove.

For this specification, we define two mechanisms to create a bidirectional protocol -
"pairing" and "binding".
These mechanisms provide increased efficiency and security.


Session Context
```````````````

As with ElGamal/AES+SessionTags, all inbound and outbound sessions
must be in a given context, either the router's context or
the context for a particular local destination.
In Java I2P, this context is called the Session Key Manager.

Sessions must not be shared among contexts, as that would
allow correlation among the various local destinations,
or between a local destination and a router.

When a given destination supports both ElGamal/AES+SessionTags
and this specification, both types of sessions may share a context.
See section 1c) below.



Pairing Inbound and Outbound Sessions
`````````````````````````````````````

When an outbound session is created at the originator (Alice),
a new inbound session is created and paired with the outbound session,
unless no reply is expected (e.g. raw datagrams).

A new inbound session is always paired with a new outbound session,
unless no reply is requested (e.g. raw datagrams).

If a reply is requested and bound to a far-end destination or router,
that new outbound session is bound to that destination or router,
and replaces any previous outbound session to that destination or router.

Pairing inbound and outbound sessions provides a bidirectional protocol
with the capability of ratcheting the DH keys.



Binding Sessions and Destinations
`````````````````````````````````

There is only one outbound session to a given destination or router.
There may be several current inbound sessions from a given destination or router.
Generally, when a new inbound session is created, and traffic is received
on that session (which serves as an ACK), any others will be marked
to expire relatively quickly, within a minute or so.
The previous messages sent (PN) value is checked, and if there are no
unreceived messages (within the window size) in the previous inbound session,
the previous session may be deleted immediately.


When an outbound session is created at the originator (Alice),
it is bound to the far-end Destination (Bob),
and any paired inbound session will also be bound to the far-end Destination.
As the sessions ratchet, they continue to be bound to the far-end Destination.

When an inbound session is created at the receiver (Bob),
it may be bound to the far-end Destination (Alice), at Alice's option.
If Alice includes binding information (her static key) in the New Session message,
the session will be bound to that destination,
and a outbound session will be created and bound to same Destination.
As the sessions ratchet, they continue to be bound to the far-end Destination.


Benefits of Binding and Pairing
```````````````````````````````

For the common, streaming case, we expect Alice and Bob to use the protocol as follows:

- Alice pairs her new outbound session to a new inbound session, both bound to the far-end destination (Bob).
- Alice includes the binding information and signature, and a reply request, in the
  New Session message sent to Bob.
- Bob pairs his new inbound session to a new outbound session, both bound to the far-end destination (Alice).
- Bob sends a reply (ack) to Alice in the paired session, with a ratchet to a new DH key.
- Alice ratchets to a new outbound session with Bob's new key, paired to the existing inbound session.

By binding an inbound session to a far-end Destination, and pairing the inbound session
to an outbound session bound to the same Destination, we achieve two major benefits:

1) The initial reply from Bob to Alice uses ephemeral-ephemeral DH

2) After Alice receives Bob's reply and ratchets, all subsequent messages from Alice to Bob
use ephemeral-ephemeral DH.


Message ACKs
````````````

In ElGamal/AES+SessionTags, when a LeaseSet is bundled as a garlic clove,
or tags are delivered, the sending router requests an ACK.
This is a separate garlic clove containing a DeliveryStatus Message.
For additional security, the DeliveryStatus Message is wrapped in a Garlic Message.
This mechanism is out-of-band from the perspective of the protocol.

In the new protocol, since the inbound and outbound sessions are paired,
we can have ACKs in-band. No separate clove is required.

An explicit ACK is simply an Existing Session message with no I2NP block.
However, in most cases, an explict ACK can be avoided, as there is reverse traffic.
It may be desirable for implementations to wait a short time (perhaps a hundred ms)
before sending an explicit ACK, to give the streaming or application layer time to respond.

Implementations will also need to defer any ACK sending until after the
I2NP block is processed, as the Garlic Message may contain a Database Store Message
with a lease set. A recent lease set will be necessary to route the ACK,
and the far-end destination (contained in the lease set) will be necessary to
verify the binding static key.


Session Timeouts
````````````````

Outbound sessions should always expire before inbound sessions.
One an outbound session expires, and a new one is created, a new paired inbound
session will be created as well. If there was an old inbound session,
it will be allowed to expire.


Multicast
---------

TBD


Definitions
-----------
We define the following functions corresponding to the cryptographic building blocks used.

ZEROLEN
    zero-length byte array

CSRNG(n)
    n-byte output from a cryptographically-secure random number generator.

H(p, d)
    SHA-256 hash function that takes a personalization string p and data d, and
    produces an output of length 32 bytes.
    As defined in [NOISE]_.
    || below means append.

    Use SHA-256 as follows::

        H(p, d) := SHA-256(p || d)

MixHash(d)
    SHA-256 hash function that takes a previous hash h and new data d,
    and produces an output of length 32 bytes.
    || below means append.

    Use SHA-256 as follows::

        MixHash(d) := h = SHA-256(h || d)

STREAM
    The ChaCha20/Poly1305 AEAD as specified in [RFC-7539]_.
    S_KEY_LEN = 32 and S_IV_LEN = 12.

    ENCRYPT(k, n, plaintext, ad)
        Encrypts plaintext using the cipher key k, and nonce n which MUST be unique for
        the key k.
        Associated data ad is optional.
        Returns a ciphertext that is the size of the plaintext + 16 bytes for the HMAC.

        The entire ciphertext must be indistinguishable from random if the key is secret.

    DECRYPT(k, n, ciphertext, ad)
        Decrypts ciphertext using the cipher key k, and nonce n.
        Associated data ad is optional.
        Returns the plaintext.

DH
    X25519 public key agreement system. Private keys of 32 bytes, public keys of 32
    bytes, produces outputs of 32 bytes. It has the following
    functions:

    GENERATE_PRIVATE()
        Generates a new private key.

    DERIVE_PUBLIC(privkey)
        Returns the public key corresponding to the given private key.

    GENERATE_PRIVATE_ELG2()
        Generates a new private key that maps to a public key suitable for Elligator2 encoding.
        Note that half of the randomly-generated private keys will not be suitable and must be discarded.

    ENCODE_ELG2(pubkey)
        Returns the Elligator2-encoded public key corresponding to the given public key (inverse mapping).
        Encoded keys are little endian.
        Encoded key must be 256 bits indistinguishable from random data.
        See Elligator2 section below for specification.

    DECODE_ELG2(pubkey)
        Returns the public key corresponding to the given Elligator2-encoded public key.
        See Elligator2 section below for specification.

    DH(privkey, pubkey)
        Generates a shared secret from the given private and public keys.

HKDF(salt, ikm, info, n)
    A cryptographic key derivation function which takes some input key material ikm (which
    should have good entropy but is not required to be a uniformly random string), a salt
    of length 32 bytes, and a context-specific 'info' value, and produces an output
    of n bytes suitable for use as key material.

    Use HKDF as specified in [RFC-5869]_, using the HMAC hash function SHA-256
    as specified in [RFC-2104]_. This means that SALT_LEN is 32 bytes max.

MixKey(d)
    Use HKDF() with a previous chainKey and new data d, and
    sets the new chainKey and k.
    As defined in [NOISE]_.

    Use HKDF as follows::

        MixKey(d) := output = HKDF(chainKey, d, "", 64)
                     chainKey = output[0:31]
                     k = output[32:63]




1) Message format
-----------------


Review of Current Message Format
````````````````````````````````

The Garlic Message as specified in [I2NP]_ is as follows.
As a design goal is that intermediate hops cannot distinguish new from old crypto,
this format cannot change, even though the length field is redundant.
The format is shown with the full 16-byte header, although the
actual header may be in a different format, depending on the transport used.

When decrypted the data contains a series of Garlic Cloves and additional
data, also known as a Clove Set.

See [I2NP]_ for details and a full specification.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |type|      msg_id       |  expiration
  +----+----+----+----+----+----+----+----+
                           |  size   |chks|
  +----+----+----+----+----+----+----+----+
  |      length       |                   |
  +----+----+----+----+                   +
  |          encrypted data               |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

{% endhighlight %}


Review of Encrypted Data Format
````````````````````````````````

In ElGamal/AES+SessionTags, there are two message formats:

1) New session:
- 514 byte ElGamal block
- AES block (128 bytes minimum, multiple of 16)

2) Existing session:
- 32 byte Session Tag
- AES block (128 bytes minimum, multiple of 16)

These messages are encapsulated in a I2NP garlic message, which contains
a length field, so the length is known.

The receiver first attempts to look up the first 32 bytes as a Session Tag.
If found, he decrypts the AES block.
If not found, and the data is at least (514+16) long, he attempts to decrypt the ElGamal block,
and if successful, decrypts the AES block.


New Session Tags and Comparison to Signal
`````````````````````````````````````````

In Signal Double Ratchet, the header contains:

- DH: Current ratchet public key
- PN: Previous chain message length
- N: Message Number

Signal's "sending chains" are roughly equivalent to our tag sets.
By using a session tag, we can eliminate most of that.

In New Session, we put only the public key in the unencrytped header.

In Existing Session, we use a session tag for the header.
The session tag is associated with the current ratchet public key,
and the message number.

In both new and Existing Session, PN and N are in the encrypted body.

In Signal, things are constantly ratcheting. A new DH public key requires the
receiver to ratchet and send a new public key back, which also serves
as the ack for the received public key.
This would be far too many DH operations for us.
So we separate the ack of the received key and the transmission of a new public key.
Any message using a session tag generated from the new DH public key constitutes an ACK.
We only transmit a new public key when we wish to rekey.

The maximum number of messages before the DH must ratchet is 65535.

When delivering a session key, we derive the "Tag Set" from it,
rather than having to deliver session tags as well.
A Tag Set can be up to 65536 tags.
However, receivers should implement a "look-ahead" strategy, rather
than generating all possible tags at once.
Only generate at most N tags past the last good tag received.
N might be at most 128, but 32 or even less may be a better choice.



1a) New session format
----------------------

New Session One Time Public key (32 bytes)
Encrypted data and MAC (remaining bytes)

The New Session message may or may not contain the sender's static public key.
If it is included, the reverse session is bound to that key.
The static key should be included if replies are expected,
i.e. for streaming and repliable datagrams.
It should not be included for raw datagrams.

The New Session message is similar to the one-way Noise [NOISE]_ pattern
"N" (if the static key is not sent),
or the two-way pattern "IK" (if the static key is sent).



1b) New session format (with binding)
-------------------------------------

Length is 96 + payload length.
Encrypted format:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   New Session Ephemeral Public Key    |
  +             32 bytes                  +
  |     Encoded with Elligator2           |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +         Static Key                    +
  |       ChaCha20 encrypted data         |
  +            32 bytes                   +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +    (MAC) for Static Key Section       +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +            Payload Section            +
  |       ChaCha20 encrypted data         |
  ~                                       ~
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +         (MAC) for Payload Section     +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  Public Key :: 32 bytes, little endian, Elligator2, cleartext

  Static Key encrypted data :: 32 bytes

  Payload Section encrypted data :: remaining data minus 16 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}


New Session Ephemeral Key
`````````````````````````

The ephemeral key is 32 bytes, encoded with Elligator2.
This key is never reused; a new key is generated with
each message, including retransmissions.

Static Key
``````````

When decryptied, Alice's X25519 static key, 32 bytes.


Payload
```````

Encrypted length is the remainder of the data.
Decrypted length is 16 less than the encrypted length.
Payload must contain a DateTime block and will usually contain one or more Garlic Clove blocks.
See the payload section below for format and additional requirements.



1c) New session format (without binding)
----------------------------------------

If no reply is required, no static key is sent.


Length is 96 + payload length.
Encrypted format:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   New Session Ephemeral Public Key    |
  +             32 bytes                  +
  |     Encoded with Elligator2           |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +           Flags Section               +
  |       ChaCha20 encrypted data         |
  +            32 bytes                   +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +         (MAC) for above section       +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +            Payload Section            +
  |       ChaCha20 encrypted data         |
  ~                                       ~
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +         (MAC) for Payload Section     +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  Public Key :: 32 bytes, little endian, Elligator2, cleartext

  Flags Section encrypted data :: 32 bytes

  Payload Section encrypted data :: remaining data minus 16 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}

New Session Ephemeral Key
`````````````````````````

Alice's ephemeral key.
The ephemeral key is 32 bytes, encoded with Elligator2, little endian.
This key is never reused; a new key is generated with
each message, including retransmissions.


Flags Section Decrypted data
````````````````````````````

The Flags section contains nothing.
It is always 32 bytes, because it must be the same length
as the static key for New Session messages with binding.
Bob determines whether it's a static key or a flags section
by testing if the 32 bytes are all zeros.

TODO any flags needed here?

Payload
```````

Encrypted length is the remainder of the data.
Decrypted length is 16 less than the encrypted length.
Payload must contain a DateTime block and will usually contain one or more Garlic Clove blocks.
See the payload section below for format and additional requirements.




1d) One-time format (no binding or session)
-------------------------------------------

If only a single message is expected to be sent,
no session setup or static key is required.


Length is 96 + payload length.
Encrypted format:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |       Ephemeral Public Key            |
  +             32 bytes                  +
  |     Encoded with Elligator2           |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +           Flags Section               +
  |       ChaCha20 encrypted data         |
  +            32 bytes                   +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +         (MAC) for above section       +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +            Payload Section            +
  |       ChaCha20 encrypted data         |
  ~                                       ~
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +         (MAC) for Payload Section     +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  Public Key :: 32 bytes, little endian, Elligator2, cleartext

  Flags Section encrypted data :: 32 bytes

  Payload Section encrypted data :: remaining data minus 16 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}


New Session One Time Key
````````````````````````

The one time key is 32 bytes, encoded with Elligator2, little endian.
This key is never reused; a new key is generated with
each message, including retransmissions.


Flags Section Decrypted data
````````````````````````````````

The Flags section contains nothing.
It is always 32 bytes, because it must be the same length
as the static key for New Session messages with binding.
Bob determines whether it's a static key or a flags section
by testing if the 32 bytes are all zeros.

TODO any flags needed here?

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |                                       |
  +             All zeros                 +
  |              32 bytes                 |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+

  zeros:: All zeros, 32 bytes.

{% endhighlight %}


Payload
```````

Encrypted length is the remainder of the data.
Decrypted length is 16 less than the encrypted length.
Payload must contain a DateTime block and will usually contain one or more Garlic Clove blocks.
See the payload section below for format and additional requirements.



1f) KDFs for New Session Message
--------------------------------

KDF for Initial ChainKey
````````````````````````

This is standard [NOISE]_ for IK with a modified protocol name.
Note that we use the same initializer for both the IK pattern (bound sessions)
and for N pattern (unbound sessions).

The protocol name is modified for two reasons.
First, to indicate that the ephemeral keys are encoded with Elligator2,
and second, to indicate that MixHash() is called before the second message
to mix in the tag value.

.. raw:: html

  {% highlight lang='text' %}
This is the "e" message pattern:

  // Define protocol_name.
  Set protocol_name = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"
   (40 bytes, US-ASCII encoded, no NULL termination).

  // Define Hash h = 32 bytes
  h = SHA256(protocol_name);

  Define ck = 32 byte chaining key. Copy the h data to ck.
  Set chainKey = h

  // MixHash(null prologue)
  h = SHA256(h);

  // up until here, can all be precalculated by Alice for all outgoing connections

{% endhighlight %}


KDF for Flags/Static Key Section Encrypted Contents
```````````````````````````````````````````````````

.. raw:: html

  {% highlight lang='text' %}
This is the "e" message pattern:

  // Bob's X25519 static keys
  // bpk is published in leaseset
  bsk = GENERATE_PRIVATE()
  bpk = DERIVE_PUBLIC(bsk)

  // Bob static public key
  // MixHash(bpk)
  // || below means append
  h = SHA256(h || bpk);

  // up until here, can all be precalculated by Bob for all incoming connections

  // Alice's X25519 ephemeral keys
  aesk = GENERATE_PRIVATE_ELG2()
  aepk = DERIVE_PUBLIC(aesk)

  // Alice ephemeral public key
  // MixHash(aepk)
  // || below means append
  h = SHA256(h || aepk);

  // h is used as the associated data for the AEAD in the New Session Message
  // Retain the Hash h for the New Session Reply KDF
  // eapk is sent in cleartext in the
  // beginning of the New Session message
  elg2_aepk = ENCODE_ELG2(aepk)
  // As decoded by Bob
  aepk = DECODE_ELG2(elg2_aepk)

  End of "e" message pattern.

  This is the "es" message pattern:

  // Noise es
  sharedSecret = DH(aesk, bpk) = DH(bsk, aepk)

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  // ChaChaPoly parameters to encrypt/decrypt
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  ad = h
  ciphertext = ENCRYPT(k, n, flags/static key section, ad)

  End of "es" message pattern.

  This is the "s" message pattern:

  // MixHash(ciphertext)
  // Save for Payload section KDF
  h = SHA256(h || ciphertext)

  // Alice's X25519 static keys
  ask = GENERATE_PRIVATE()
  apk = DERIVE_PUBLIC(ask)

  End of "s" message pattern.


{% endhighlight %}



KDF for Payload Section (with Alice static key)
```````````````````````````````````````````````

.. raw:: html

  {% highlight lang='text' %}
This is the "ss" message pattern:

  // Noise ss
  sharedSecret = DH(ask, bpk) = DH(bsk, apk)

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  // ChaChaPoly parameters to encrypt/decrypt
  // chainKey from Static Key Section
  Set sharedSecret = X25519 DH result
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  ad = h
  ciphertext = ENCRYPT(k, n, payload, ad)

  End of "ss" message pattern.

  // MixHash(ciphertext)
  // Save for New Session Reply KDF
  h = SHA256(h || ciphertext)

{% endhighlight %}


KDF for Payload Section (without Alice static key)
``````````````````````````````````````````````````

Note that this is a Noise "N" pattern, but we use the same "IK" initializer
as for bound sessions.

New Session messages can not be identified as containing Alice's static key or not
until the static key is decrypted and inspected to determine if it contains all zeros.
Therefore, the receiver must use the "IK" state machine for all
New Session messages.
If the static key is all zeros, the "ss" message pattern must be skipped.



.. raw:: html

  {% highlight lang='text' %}
chainKey = from Flags/Static key section
  k = from Flags/Static key section
  n = 1
  ad = h from Flags/Static key section
  ciphertext = ENCRYPT(k, n, payload, ad)

{% endhighlight %}



1g) New Session Reply format
----------------------------

One or more New Session Replies may be sent in response to a single New Session message.
Each reply is prepended by a tag, which is generated from a TagSet for the session.

The New Session Reply is in two parts.
The first part is the completion of the Noise IK handshake with a prepended tag.
The length of the first part is 56 bytes.
The second part is the data phase payload.
The length of the second part is 16 + payload length.

Total length is 72 + payload length.
Encrypted format:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |       Session Tag   8 bytes           |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Ephemeral Public Key           +
  |                                       |
  +            32 bytes                   +
  |     Encoded with Elligator2           |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +  (MAC) for Key Section (no data)      +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +            Payload Section            +
  |       ChaCha20 encrypted data         |
  ~                                       ~
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +         (MAC) for Payload Section     +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  Tag :: 8 bytes, cleartext

  Public Key :: 32 bytes, little endian, Elligator2, cleartext

  MAC :: Poly1305 message authentication code, 16 bytes
         Note: The ChaCha20 plaintext data is empty (ZEROLEN)

  Payload Section encrypted data :: remaining data minus 16 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}

Session Tag
```````````
The tag is generated in the Session Tags KDF, as initialized
in the DH Initialization KDF below.
This correlates the reply to the session.
The Session Key from the DH Initialization is not used.


New Session Reply Ephemeral Key
````````````````````````````````

Bob's ephemeral key.
The ephemeral key is 32 bytes, encoded with Elligator2, little endian.
This key is never reused; a new key is generated with
each message, including retransmissions.


Payload
```````
Encrypted length is the remainder of the data.
Decrypted length is 16 less than the encrypted length.
Payload will usually contain one or more Garlic Clove blocks.
See the payload section below for format and additional requirements.


KDF for Reply TagSet
`````````````````````

One or more tags are created from the TagSet, which is initialized using
the KDF below, using the chainKey from the New Session message.

.. raw:: html

  {% highlight lang='text' %}
// Generate tagset
  tagsetKey = HKDF(chainKey, ZEROLEN, "SessionReplyTags", 32)
  tagset_nsr = DH_INITIALIZE(chainKey, tagsetKey)

{% endhighlight %}


KDF for Reply Key Section Encrypted Contents
````````````````````````````````````````````

.. raw:: html

  {% highlight lang='text' %}
// Keys from the New Session message
  // Alice's X25519 keys
  // apk and aepk are sent in original New Session message
  // ask = Alice private static key
  // apk = Alice public static key
  // aesk = Alice ephemeral private key
  // aepk = Alice ephemeral public key
  // Bob's X25519 static keys
  // bsk = Bob private static key
  // bpk = Bob public static key

  // Generate the tag
  tagsetEntry = tagset_nsr.GET_NEXT_ENTRY()
  tag = tagsetEntry.SESSION_TAG

  // MixHash(tag)
  h = SHA256(h || tag)

  This is the "e" message pattern:

  // Bob's X25519 ephemeral keys
  besk = GENERATE_PRIVATE_ELG2()
  bepk = DERIVE_PUBLIC(besk)

  // Bob's ephemeral public key
  // MixHash(bepk)
  // || below means append
  h = SHA256(h || bepk);

  // elg2_bepk is sent in cleartext in the
  // beginning of the New Session message
  elg2_bepk = ENCODE_ELG2(bepk)
  // As decoded by Bob
  bepk = DECODE_ELG2(elg2_bepk)

  End of "e" message pattern.

  This is the "ee" message pattern:

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  // ChaChaPoly parameters to encrypt/decrypt
  // chainKey from original New Session Payload Section
  sharedSecret = DH(aesk, bepk) = DH(besk, aepk)
  keydata = HKDF(chainKey, sharedSecret, "", 32)
  chainKey = keydata[0:31]

  End of "ee" message pattern.

  This is the "se" message pattern:

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  sharedSecret = DH(ask, bepk) = DH(besk, apk)
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  ad = h
  ciphertext = ENCRYPT(k, n, ZEROLEN, ad)

  End of "se" message pattern.

  // MixHash(ciphertext)
  h = SHA256(h || ciphertext)

  chainKey is used in the ratchet below.

{% endhighlight %}


KDF for Payload Section Encrypted Contents
``````````````````````````````````````````

This is like the first Existing Session message,
post-split, but without a separate tag.
Additionally, we use the hash from above to bind the
payload to the NSR message.


.. raw:: html

  {% highlight lang='text' %}
// split()
  keydata = HKDF(chainKey, ZEROLEN, "", 64)
  k_ab = keydata[0:31]
  k_ba = keydata[32:63]
  tagset_ab = DH_INITIALIZE(chainKey, k_ab)
  tagset_ba = DH_INITIALIZE(chainKey, k_ba)

  // AEAD parameters for New Session Reply payload
  k = HKDF(k_ba, ZEROLEN, "AttachPayloadKDF", 32)
  n = 0
  ad = h
  ciphertext = ENCRYPT(k, n, payload, ad)
{% endhighlight %}


Notes
-----

Multiple NSR messages may be sent in reply, each with unique ephemeral keys, depending on the size of the response.

Alice and Bob are required to use new ephemeral keys for every NS and NSR message.

Alice must receive one of Bob's NSR messages before sending Existing Session (ES) messages,
and Bob must receive an ES message from Alice before sending ES messages.

The ``chainKey`` and ``k`` from Bob's NSR Payload Section are used
as inputs for the initial ES DH Ratchets (both directions, see DH Ratchet KDF).

Bob must only retain Existing Sessions for the ES messages received from Alice.
Any other created inbound and outbound sessions (for multiple NSRs) should be
destroyed immediately after receiving Alice's first ES message for a given session.



1h) Existing session format
---------------------------

Session tag (8 bytes)
Encrypted data and MAC (see section 3 below)


Format
``````
Encrypted:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |       Session Tag                     |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +            Payload Section            +
  |       ChaCha20 encrypted data         |
  ~                                       ~
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +              (MAC)                    +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  Session Tag :: 8 bytes, cleartext

  Payload Section encrypted data :: remaining data minus 16 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}


Payload
```````
Encrypted length is the remainder of the data.
Decrypted length is 16 less than the encrypted length.
See the payload section below for format and requirements.


KDF
```

.. raw:: html

  {% highlight lang='text' %}
See AEAD section below.

  // AEAD parameters for Existing Session payload
  k = The 32-byte session key associated with this session tag
  n = The message number N in the current chain, as retrieved from the associated Session Tag.
  ad = The session tag, 8 bytes
  ciphertext = ENCRYPT(k, n, payload, ad)
{% endhighlight %}



2) ECIES-X25519
---------------


Format: 32-byte public and private keys, little-endian.



2a) Elligator2
--------------

In standard Noise handshakes, the initial handshake messages in each direction start with
ephemeral keys that are transmitted in cleartext.
As valid X25519 keys are distinguishable from random, a man-in-the-middle may distinguish
these messages from Existing Session messages that start with random session tags.
In [NTCP2]_ ([Prop111]_), we used a low-overhead XOR function using the out-of-band static key to obfuscate
the key. However, the threat model here is different; we do not want to allow any MitM to
use any means to confirm the destination of the traffic, or to distinguish
the initial handshake messages from Existing Session messages.

Therefore, [Elligator2]_ is used to transform the ephemeral keys in the New Session and New Session Reply messages
so that they are indistinguishable from uniform random strings.



Format
``````

32-byte public and private keys.
Encoded keys are little endian.

As defined in [Elligator2]_, the encoded keys are indistinguishable from 254 random bits.
We require 256 random bits (32 bytes). Therefore, the encoding and decoding are
defined as follows:

Encoding:

.. raw:: html

  {% highlight lang='text' %}
ENCODE_ELG2() Definition

  // Encode as defined in Elligator2 specification
  encodedKey = encode(pubkey)
  // OR in 2 random bits to MSB
  randomByte = CSRNG(1)
  encodedKey[31] |= (randomByte & 0xc0)
{% endhighlight %}


Decoding:

.. raw:: html

  {% highlight lang='text' %}
DECODE_ELG2() Definition

  // Mask out 2 random bits from MSB
  encodedKey[31] &= 0x3f
  // Decode as defined in Elligator2 specification
  pubkey = decode(encodedKey)
{% endhighlight %}



Notes
`````

Elligator2 doubles average the key generation time, as half the private keys
result in public keys that are unsuitable for encoding with Elligator2.
Also, the key generation time is unbounded with an exponential distribution,
as the generator must keep retrying utnil a suitable key pair is found.

This overhead may be managed by doing key generation in advance,
in a separate thread, to keep a pool of suitable keys.

The generator does the ENCODE_ELG2() function to determine suitability.
Therefore, the generator should store the result of ENCODE_ELG2()
so it does not have to be calculated again.

Additionally, the unsuitable keys may be added to the pool of keys
used for [NTCP2]_, where Elligator2 is not used.
The security issues of doing so is TBD.




3) AEAD (ChaChaPoly)
--------------------

AEAD using ChaCha20 and Poly1305, same as in [NTCP2]_.
This corresponds to [RFC-7539]_, which is also
used similarly in TLS [RFC-7905]_.



New Session and New Session Reply Inputs
````````````````````````````````````````

Inputs to the encryption/decryption functions
for an AEAD block in a New Session message:

.. raw:: html

  {% highlight lang='dataspec' %}
k :: 32 byte cipher key
       See New Session and New Session Reply KDFs above.

  n :: Counter-based nonce, 12 bytes.
       n = 0

  ad :: Associated data, 32 bytes.
        The SHA256 hash of the preceding data, as output from mixHash()

  data :: Plaintext data, 0 or more bytes

{% endhighlight %}


Existing Session Inputs
```````````````````````

Inputs to the encryption/decryption functions
for an AEAD block in an Existing Session message:

.. raw:: html

  {% highlight lang='dataspec' %}
k :: 32 byte session key
       As looked up from the accompanying session tag.

  n :: Counter-based nonce, 12 bytes.
       Starts at 0 and incremented for each message when transmitting.
       For the receiver, the value
       as looked up from the accompanying session tag.
       First four bytes are always zero.
       Last eight bytes are the message number (n), little-endian encoded.
       Maximum value is 65535.
       Session must be ratcheted when N reaches that value.
       Higher values must never be used.

  ad :: Associated data
        The session tag

  data :: Plaintext data, 0 or more bytes

{% endhighlight %}


Encrypted Format
````````````````

Output of the encryption function, input to the decryption function:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |       ChaCha20 encrypted data         |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Poly1305 Message Authentication Code |
  +              (MAC)                    +
  |             16 bytes                  |
  +----+----+----+----+----+----+----+----+

  encrypted data :: Same size as plaintext data, 0 - 65519 bytes

  MAC :: Poly1305 message authentication code, 16 bytes

{% endhighlight %}

Notes
`````
- Since ChaCha20 is a stream cipher, plaintexts need not be padded.
  Additional keystream bytes are discarded.

- The key for the cipher (256 bits) is agreed upon by means of the SHA256 KDF.
  The details of the KDF for each message are in separate sections below.

- ChaChaPoly frames are of known size as they are encapsulated in the I2NP data message.

- For all messages,
  padding is inside the authenticated
  data frame.


AEAD Error Handling
```````````````````

All received data that fails the AEAD verification must be discarded.
No response is returned.




4) Ratchets
-----------

We still use session tags, as before, but we use ratchets to generate them.
Session tags also had a rekey option that we never implemented.
So it's like a double ratchet but we never did the second one.

Here we define something similar to Signal's Double Ratchet.
The session tags are generated deterministically and identically on
the receiver and sender sides.

By using a symmetric key/tag ratchet, we eliminate memory usage to store session tags on the sender side.
We also eliminate the bandwidth consumption of sending tag sets.
Receiver side usage is still significant, but we can reduce it further
as we will shrink the session tag from 32 bytes to 8 bytes.

We do not use header encryption as specified (and optional) in Signal,
we use session tags instead.

By using a DH ratchet, we acheive forward secrecy, which was never implemented
in ElGamal/AES+SessionTags.

Note: The New Session one-time public key is not part of the ratchet, its sole function
is to encrypt Alice's initial DH ratchet key.


Message Numbers
```````````````

The Double Ratchet handles lost or out-of-order messages by including in each message header
a tag. The receiver looks up the index of the tag, this is the message number N.
If the message contains a Message Number block with a PN value,
the recipient can delete any tags higher than that value in the previous tag set,
while retaining skipped tags
from the previous tag set in case the skipped messages arrive later.


Sample Implementation
``````````````````````

We define the following data structures and functions to implement these ratchets.

TAGSET_ENTRY
    A single entry in a TAGSET.

    INDEX
        An integer index, starting with 0

    SESSION_TAG
        An identifier to go out on the wire, 8 bytes

    SESSION_KEY
        A symmetric key, never goes on the wire, 32 bytes

TAGSET
    A collection of TAGSET_ENTRIES.

    CREATE(key, n)
        Generate a new TAGSET using initial cryptographic key material of 32 bytes.
        The associated session identifier is provided.
        The initial number of of tags to create is specified; this is generally 0 or 1
        for an outgoing session.
        LAST_INDEX = -1
        EXTEND(n) is called.

    EXTEND(n)
        Generate n more TAGSET_ENTRIES by calling EXTEND() n times.

    EXTEND()
        Generate one more TAGSET_ENTRY, unless the maximum number SESSION_TAGS have
        already been generated.
        If LAST_INDEX is greater than or equal to 65535, return.
        ++ LAST_INDEX
        Create a new TAGSET_ENTRY with the LAST_INDEX value and the calculated SESSION_TAG.
        Calls RATCHET_TAG() and (optionally) RATCHET_KEY().
        For inbound sessions, the calculation of the SESSION_KEY may
        be deferred and calculated in GET_SESSION_KEY().
        Calls EXPIRE()

    EXPIRE()
        Remove tags and keys that are too old, or if the TAGSET size exceeds some limit.

    RATCHET_TAG()
        Calculates the next SESSION_TAG based on the last SESSION_TAG.

    RATCHET_KEY()
        Calculates the next SESSION_KEY based on the last SESSION_KEY.

    SESSION
        The associated session.

    CREATION_TIME
        When the TAGSET was created.

    LAST_INDEX
        The last TAGSET_ENTRY INDEX generated by EXTEND().

    GET_NEXT_ENTRY()
        Used for outgoing sessions only.
        EXTEND(1) is called if there are no remaining TAGSET_ENTRIES.
        If EXTEND(1) did nothing, the max of 65535 TAGSETS have been used,
        and return an error.
        Returns the next unused TAGSET_ENTRY.

    GET_SESSION_KEY(sessionTag)
        Used for incoming sessions only.
        Returns the TAGSET_ENTRY containing the sessionTag.
        If found, the TAGSET_ENTRY is removed.
        If the SESSION_KEY calculation was deferred, it is calculated now.
        If there are few TAGSET_ENTRIES remaining, EXTEND(n) is called.




4a) DH Ratchet
``````````````

Ratchets but not nearly as fast as Signal does.
We separate the ack of the received key from generating the new key.
In typical usage, Alice and Bob will each ratchet (twice) immediately in a New Session,
but will not ratchet again.

Note that a ratchet is for a single direction, and generates a New Session tag / message key ratchet chain for that direction.
To generate keys for both directions, you have to ratchet twice.

You ratchet every time you generate and send a new key.
You ratchet every time you receive a new key.

Alice ratchets once when creating an unbound outbound session, she does not create an inbound session
(unbound is non-repliable).

Bob ratchets once when creating an unbound inbound session, and does not create a corresponding outbound session
(unbound is non-repliable).

Alice continues sending New Session (NS) messages to Bob until receiving one of Bob's New Session Reply (NSR) messages.
She then uses the NSR's Payload Section KDF results as inputs for the session ratchets (see DH Ratchet KDF),
and begins sending Existing Session (ES) messages.

For each NS message received, Bob creates a new inbound session, using the KDF results
of the reply Payload Section for inputs to the new inbound and outbound ES DH Ratchet.

For each reply required, Bob sends Alice a NSR message with the reply in the payload.
It is required Bob use new ephemeral keys for every NSR.

Bob must receive an ES message from Alice on one of the inbound sessions, before creating and sending
ES messages on the corresponding outbound session.

Alice should use a timer for receiving a NSR message from Bob. If the timer expires,
the session should be removed.

To avoid a KCI and/or resource exhaustion attack, where an attacker drops Bob's NSR replies to keep Alice sending NS messages,
Alice should avoid starting New Sessions to Bob after a certain number of retries due to timer expiration.

Alice and Bob each
do a DH ratchet for every NextKey block received.

Alice and Bob each generate new tag setstchets and two symmetric keys ratchets after each
DH ratchet. For each new ES message in a given direction, Alice and Bob advance the session
tag and symmtric key ratchets.

The frequency of DH ratchets after the initial handshake is implementation-dependent.
While the protocol places a limit of 65535 messages before a ratchet is required,
more frequent ratcheting (based on message count, elapsed time, or both)
may provide additional security.

After the final handshake KDF on bound sessions, Bob and Alice must run the Noise Split() function on the
resulting CipherState to create independent symmetric and tag chain keys for inbound and outbound sessions.


KEY AND TAG SET IDS
~~~~~~~~~~~~~~~~~~~~~~~~~

Key and tag set ID numbers are used to identify keys and tag sets.
Key IDs are used in NextKey blocks to identify the key sent or used.
Tag set IDs are used (with the message number) in ACK blocks to identify the message being acked.
Both key and tag set IDs apply to the tag sets for a single direction.
Key and tag set ID numbers must be sequential.

In the first tag sets used for a session in each direction, the tag set ID is 0.
No NextKey blocks have been sent, so there are no key IDs.

To begin a DH ratchet, the sender transmits a new NextKey block with a key ID of 0.
The receiver replies with a new NextKey block with a key ID of 0.
The sender then starts using a new tag set with a tag set ID of 1.

Subsequent tag sets are generated similarly.
For all tag sets used after NextKey exchanges, the tag set number is (1 + Alice's key ID + Bob's key ID).

Key and tag set IDs start at 0 and increment sequentially.
The maximum tag set ID is 65535.
The maximum key ID is 32767.
When a tag set is almost exhausted, the tag set sender must initiate a NextKey exchange.
When tag set 65535 is almost exhausted, the tag set sender must initiate a new session
by sending a New Session message.

With a streaming maximum message size of 1730, and assuming no retransmissions,
the theoretical maximum data transfer using a single tag set is 1730 * 65536 ~= 108 MB.
The actual maximum will be lower due to retransmissions.

The theoretical maximum data transfer with all 65536 available tag sets, before
the session would have to be discarded and replaced,
is 64K * 108 MB ~= 6.9 TB.



DH RATCHET MESSAGE FLOW
~~~~~~~~~~~~~~~~~~~~~~~~~

The next key exchange for a tag set must be initiated by the
sender of those tags (the owner of the outbound tag set).
The receiver (owner of the inbound tag set) will respond.
For a typical HTTP GET traffic at the application layer, Bob will send more messages and will ratchet first
by initiating the key exchange; the diagram below shows that.
When Alice ratchets, the same thing happens in reverse.

The first tag set used after the NS/NSR handshake is tag set 0.
When tag set 0 is almost exhausted, new keys must be exchanged in both directions to create tag set 1.
After that, a new key is only sent in one direction.

To create tag set 2, the tag sender sends a new key and the tag receiver sends the ID of his old key as an acknowledgement.
Both sides do a DH.

To create tag set 3, the tag sender sends the ID of his old key and requests a new key from the tag receiver.
Both sides do a DH.

Subsequent tag sets are generated as for tag sets 2 and 3.
The tag set number is (1 + sender key id + receiver key id).


.. raw:: html

  {% highlight %}
Tag Sender                    Tag Receiver

                   ... use tag set #0 ...


  (Tagset #0 almost empty)
  (generate new key #0)

  Next Key, forward, request reverse, with key #0  -------->
  (repeat until next key received)

                              (generate new key #0, do DH, create IB Tagset #1)

          <-------------      Next Key, reverse, with key #0
                              (repeat until tag received on new tagset)

  (do DH, create OB Tagset #1)


                   ... use tag set #1 ...


  (Tagset #1 almost empty)
  (generate new key #1)

  Next Key, forward, with key #1        -------->
  (repeat until next key received)

                              (reuse key #0, do DH, create IB Tagset #2)

          <--------------     Next Key, reverse, id 0
                              (repeat until tag received on new tagset)

  (do DH, create OB Tagset #2)


                   ... use tag set #2 ...


  (Tagset #2 almost empty)
  (reuse key #1)

  Next Key, forward, request reverse, id 1  -------->
  (repeat until next key received)

                              (generate new key #1, do DH, create IB Tagset #3)

          <--------------     Next Key, reverse, with key #1

  (do DH, create OB Tagset #3)
  (reuse key #1, do DH, create IB Tagset #3)



                   ... use tag set #3 ...



       After tag set 3, repeat the above
       patterns as shown for tag sets 2 and 3.

       To create a new even-numbered tag set, the sender sends a new key
       to the receiver. The receiver sends his old key ID
       back as an acknowledgement.

       To create a new odd-numbered tag set, the sender sends a reverse request
       to the receiver. The receiver sends a new reverse key to the sender.

{% endhighlight %}

After the DH ratchet is complete for an outbound tagset, and a new outbound tagset is created,
it should be used immediately, and the old outbound tagset may be deleted.

After the DH ratchet is complete for an inbound tagset, and a new inbound tagset is created,
the receiver should listen for tags in both tagsets, and delete the old tagset
after a short time, about 3 minutes.


Summary of tag set and key ID progression is in the table below.
* indicates that a new key is generated.


==============  =============  ===========
New Tag Set ID  Sender key ID  Rcvr key ID
==============  =============  ===========
0               n/a            n/a
1               0 *            0 *
2               1 *            0
3               1              1 *
4               2 *            1
5               2              2 *
...             ...            ...
65534           32767 *        32766
65535           32767          32767 *
==============  =============  ===========

Key and tag set ID numbers must be sequential.


DH INITIALIZATION KDF
~~~~~~~~~~~~~~~~~~~~~~~

This is the definition of DH_INITIALIZE(rootKey, k)
for a single direction. It creates a tagset, and a
"next root key" to be used for a subsequent DH ratchet if necessary.

We use DH initialization in three places. First, we use it
to generate a tag set for the New Session Replies.
Second, we use it to generate two tag sets, one for each direction,
for use in Existing Session messages.
Lastly, we use it after a DH Ratchet to generate a new tag set
in a single direction for additional Existing Session messages.


.. raw:: html

  {% highlight lang='text' %}
Inputs:
  1) rootKey = chainKey from Payload Section
  2) k from the New Session KDF or split()

  // KDF_RK(rk, dh_out)
  keydata = HKDF(rootKey, k, "KDFDHRatchetStep", 64)

  // Output 1: The next Root Key (KDF input for the next DH ratchet)
  nextRootKey = keydata[0:31]
  // Output 2: The chain key to initialize the new
  // session tag and symmetric key ratchets
  // for the tag set
  ck = keydata[32:63]

  // session tag and symmetric key chain keys
  keydata = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
  sessTag_ck = keydata[0:31]
  symmKey_ck = keydata[32:63]

{% endhighlight %}


DH RATCHET KDF
~~~~~~~~~~~~~~~

This is used after new DH keys are exchanged in NextKey blocks,
before a tagset is exhausted.

.. raw:: html

  {% highlight lang='text' %}

// Tag sender generates new X25519 ephemeral keys
  // and sends rapk to tag receiver in a NextKey block
  rask = GENERATE_PRIVATE()
  rapk = DERIVE_PUBLIC(rask)
  
  // Tag receiver generates new X25519 ephemeral keys
  // and sends rbpk to Tag sender in a NextKey block
  rbsk = GENERATE_PRIVATE()
  rbpk = DERIVE_PUBLIC(rbsk)

  sharedSecret = DH(rask, rbpk) = DH(rbsk, rapk)
  tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
  rootKey = nextRootKey // from previous tagset in this direction
  newTagSet = DH_INITIALIZE(rootKey, tagsetKey)

{% endhighlight %}



4b) Session Tag Ratchet
```````````````````````

Ratchets for every message, as in Signal.
The session tag ratchet is synchronized with the symmetric key ratchet,
but the receiver key ratchet may "lag behind" to save memory.

Transmitter ratchets once for each message transmitted.
No additional tags must be stored.
The transmitter must also keep a counter for 'N', the message number
of the message in the current chain. The 'N' value is included
in the sent message.
See the Message Number block definition.

Receiver must ratchet ahead by the max window size and store the tags in a "tag set",
which is associated with the session.
Once received, the stored tag may be discarded, and if there are no previous
unreceived tags, the window may be advanced.
The receiver should keep the 'N' value associated with each session tag,
and check that the number in the sent message matches this value.
See the Message Number block definition.


KDF
~~~

This is the definition of RATCHET_TAG().

.. raw:: html

  {% highlight lang='text' %}
Inputs:
  1) Session Tag Chain key sessTag_ck
     First time: output from DH ratchet
     Subsequent times: output from previous session tag ratchet

  Generated:
  2) input_key_material = SESSTAG_CONSTANT
     Must be unique for this tag set (generated from chain key),
     so that the sequence isn't predictable, since session tags
     go out on the wire in plaintext.

  Outputs:
  1) N (the current session tag number)
  2) the session tag (and symmetric key, probably)
  3) the next Session Tag Chain Key (KDF input for the next session tag ratchet)

  Initialization:
  keydata = HKDF(sessTag_ck, ZEROLEN, "STInitialization", 64)
  // Output 1: Next chain key
  sessTag_chainKey = keydata[0:31]
  // Output 2: The constant
  SESSTAG_CONSTANT = keydata[32:63]

  // KDF_ST(ck, constant)
  keydata_0 = HKDF(sessTag_chainkey, SESSTAG_CONSTANT, "SessionTagKeyGen", 64)
  // Output 1: Next chain key
  sessTag_chainKey_0 = keydata_0[0:31]
  // Output 2: The session tag
  // or more if tag is longer than 8 bytes
  tag_0 = keydata_0[32:39]

  // repeat as necessary to get to tag_n
  keydata_n = HKDF(sessTag_chainKey_(n-1), SESSTAG_CONSTANT, "SessionTagKeyGen", 64)
  // Output 1: Next chain key
  sessTag_chainKey_n = keydata_n[0:31]
  // Output 2: The session tag
  // or more if tag is longer than 8 bytes
  tag_n = keydata_n[32:39]

{% endhighlight %}


4c) Symmetric Key Ratchet
`````````````````````````

Ratchets for every message, as in Signal.
Each symmetric key has an associated message number and session tag.
The session key ratchet is synchronized with the symmetric tag ratchet,
but the receiver key ratchet may "lag behind" to save memory.

Transmitter ratchets once for each message transmitted.
No additional keys must be stored.

When receiver gets a session tag, if it has not already ratcheted the
symmetric key ratchet ahead to the associated key, it must "catch up" to the associated key.
The receiver will probably cache the keys for any previous tags
that have not yet been received.
Once received, the stored key may be discarded, and if there are no previous
unreceived tags, the window may be advanced.

For efficiency, the session tag and symmetric key ratchets are separate so
the session tag ratchet can run ahead of the symmetric key ratchet.
This also provides some additional security, since the session tags go out on the wire.


KDF
~~~

This is the definition of RATCHET_KEY().

.. raw:: html

  {% highlight lang='text' %}
Inputs:
  1) Symmetric Key Chain key symmKey_ck
     First time: output from DH ratchet
     Subsequent times: output from previous symmetric key ratchet

  Generated:
  2) input_key_material = SYMMKEY_CONSTANT = ZEROLEN
     No need for uniqueness. Symmetric keys never go out on the wire.
     TODO: Set a constant anyway?

  Outputs:
  1) N (the current session key number)
  2) the session key
  3) the next Symmetric Key Chain Key (KDF input for the next symmetric key ratchet)

  // KDF_CK(ck, constant)
  SYMMKEY_CONSTANT = ZEROLEN
  // Output 1: Next chain key
  keydata_0 = HKDF(symmKey_ck, SYMMKEY_CONSTANT, "SymmetricRatchet", 64)
  symmKey_chainKey_0 = keydata_0[0:31]
  // Output 2: The symmetric key
  k_0 = keydata_0[32:63]

  // repeat as necessary to get to k[n]
  keydata_n = HKDF(symmKey_chainKey_(n-1), SYMMKEY_CONSTANT, "SymmetricRatchet", 64)
  // Output 1: Next chain key
  symmKey_chainKey_n = keydata_n[0:31]
  // Output 2: The symmetric key
  k_n = keydata_n[32:63]


{% endhighlight %}



5) Payload
----------

This replaces the AES section format defined in the ElGamal/AES+SessionTags specification.

This uses the same block format as defined in the [NTCP2]_ specification.
Individual block types are defined differently.

There are concerns that encouraging implementers to share code
may lead to parsing issues. Implementers should carefully consider
the benefits and risks of sharing code, and ensure that the
ordering and valid block rules are different for the two contexts.




Payload Section Decrypted data
``````````````````````````````

Encrypted length is the remainder of the data.
Decrypted length is 16 less than the encrypted length.
All block types are supported.
Typical contents include the following blocks:

==================================  ============= ============
       Payload Block Type            Type Number  Block Length
==================================  ============= ============
DateTime                                  0            7      
Termination (TBD)                         4         9 typ.    
Options (TBD)                             5           21+     
Message Number (TBD)                      6          TBD      
Next Key                                  7         3 or 35  
ACK                                       8         4 typ. 
ACK Request                               9            3   
Garlic Clove                             11         varies    
Padding                                 254         varies    
==================================  ============= ============




Unencrypted data
````````````````
There are zero or more blocks in the encrypted frame.
Each block contains a one-byte identifier, a two-byte length,
and zero or more bytes of data.

For extensibility, receivers MUST ignore blocks with unknown type nunmbers,
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
         0 datetime
         1-3 reserved
         4 termination
         5 options
         6 previous message number
         7 next session key
         8 ack
         9 ack request
         10 reserved
         11 Garlic Clove
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
In the New Session message,
the DateTime block is required, and must be the first block.

Other allowed blocks:

- Garlic Clove (type 11)
- Options (type 5)
- Padding (type 254)

In the New Session Reply message,
no blocks are required.

Other allowed blocks:

- Garlic Clove (type 11)
- Options (type 5)
- Padding (type 254)

No other blocks are allowed.
Padding, if present, must be the last block.

In the Existing Session message, no blocks are required, and order is unspecified, except for the
following requirements:

Termination, if present, must be the last block except for Padding.
Padding, if present, must be the last block.

There may be multiple Garlic Clove blocks in a single frame.
There may be up to two Next Key blocks in a single frame.
Multiple Padding blocks are not allowed in a single frame.
Other block types probably won't have multiple blocks in
a single frame, but it is not prohibited.


DateTime
````````
An expiration.
Assists in replay prevention.
Bob must validate that the message is recent, using this timestamp.
Bob must implement a Bloom filter or other mechanism to prevent replay attacks,
if the time is valid.
Bob may also use an earlier replay detection check for a duplicate ephemeral key
(either pre- or post-Elligator2 decode) to detect and drop recent duplicate NS messages
before decryption.
Generally included in New Session messages only.

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


Garlic Clove
````````````

A single decrypted Garlic Clove as specified in [I2NP]_,
with modifications to remove fields that are unused
or redundant.
Warning: This format is significantly different than
the one for ElGamal/AES. Each clove is a separate payload block.
Garlic Cloves may not be fragmented across blocks or
across ChaChaPoly frames.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 11 |  size   |                        |
  +----+----+----+                        +
  |      Delivery Instructions            |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |type|  Message_ID       | Expiration   
  +----+----+----+----+----+----+----+----+
       |      I2NP Message body           |
  +----+                                  +
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  size :: size of all data to follow

  Delivery Instructions :: As specified in
         the Garlic Clove section of [I2NP]_.
         Length varies but is typically 1, 33, or 37 bytes

  type :: I2NP message type

  Message_ID :: 4 byte `Integer` I2NP message ID

  Expiration :: 4 bytes, seconds since the epoch

{% endhighlight %}

Notes:

- Implementers must ensure that when reading a block,
  malformed or malicious data will not cause reads to
  overrun into the next block.

- The Clove Set format specified in [I2NP]_ is not used.
  Each clove is contained in its own block.

- The I2NP message header is 9 bytes, with an identical format
  to that used in [NTCP2]_.

- The Certificate, Message ID, and Expiration from the
  Garlic Message definition in [I2NP]_ are not included.

- The Certificate, Clove ID, and Expiration from the
  Garlic Clove definition in [I2NP]_ are not included.



Termination
```````````
Implementation is optional.
Drop the session.
This must be the last non-padding block in the frame.
No more messages will be sent in this session.

Not allowed in NS or NSR. Only included in Existing Session messages.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 4  |  size   | rsn|     addl data     |
  +----+----+----+----+                   +
  ~               .   .   .               ~
  +----+----+----+----+----+----+----+----+

  blk :: 4
  size :: 2 bytes, big endian, value = 1 or more
  rsn :: reason, 1 byte:
         0: normal close or unspecified
         1: termination received
         others: optional, impementation-specific
  addl data :: optional, 0 or more bytes, for future expansion, debugging,
               or reason text.
               Format unspecified and may vary based on reason code.

{% endhighlight %}



Options
```````
UNIMPLEMENTED, for further study.
Pass updated options.
Options include various parameters for the session.
See the Session Tag Length Analysis section below for more information.

The options block may be variable length,
as more_options may be present.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 5  |  size   |ver |flg |STL |STimeout |
  +----+----+----+----+----+----+----+----+
  |  SOTW   |  RITW   |tmin|tmax|rmin|rmax|
  +----+----+----+----+----+----+----+----+
  |  tdmy   |  rdmy   |  tdelay |  rdelay |
  +----+----+----+----+----+----+----+----+
  |              more_options             |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 5
  size :: 2 bytes, big endian, size of options to follow, 21 bytes minimum
  ver :: Protocol version, must be 0
  flg :: 1 byte flags
         bits 7-0: Unused, set to 0 for future compatibility
  STL :: Session tag length (must be 8), other values unimplemented
  STimeout :: Session idle timeout (seconds), big endian
  SOTW :: Sender Outbound Tag Window, 2 bytes big endian
  RITW :: Receiver Inbound Tag Window 2 bytes big endian

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

  more_options :: Format undefined, for future use

{% endhighlight %}

SOTW is the sender's recommendation to the receiver for the
receiver's inbound tag window (the maximum lookahead).
RITW is the sender's declaration of the inbound tag window
(maximum lookahead) that he plans to use.
Each side then sets or adjusts the lookahead based
on some minimum or maximum or other calculation.


Notes:

- Support for non-default session tag length will hopefully
  never be required.
- The tag window is MAX_SKIP in the Signal documentation.

Issues:

- Options negotiation is TBD.
- Defaults TBD.
- Padding and delay options are copied from NTCP2,
  but those options have not been fully implemented or studied there.


Message Numbers
```````````````
Implementation is optional.
The length (number of messages sent) in the previous tag set (PN).
Receiver may immediately delete tags higher than PN from the previous tag set.
Receiver may expire tags less than or equal to PN from the previous tag set
after a short time (e.g. 2 minutes).


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+
  | 6  |  size   |  PN    |
 +----+----+----+----+----+

  blk :: 6
  size :: 2
  PN :: 2 bytes big endian. The index of the last tag sent in the previous tag set.

{% endhighlight %}


Notes:

- Maximum PN is 65535.
- The definitions of PN is equal to the definition Signal, minus one.
  This is similar to what Signal does, but in Signal, PN and N are in the header.
  Here, they're in the encrypted message body.
- Do not send this block in tag set 0, because there was no previous tag set.


Next DH Ratchet Public Key
``````````````````````````
The next DH ratchet key is in the payload,
and it is optional. We don't ratchet every time.
(This is different than in signal, where it is in the header, and sent every time)

For the first ratchet,
Key ID = 0.

Not allowed in NS or NSR. Only included in Existing Session messages.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 7  |  size   |flag|  key ID |         |
  +----+----+----+----+----+----+         +
  |                                       |
  +                                       +
  |     Next DH Ratchet Public Key        |
  +                                       +
  |                                       |
  +                             +----+----+
  |                             |
  +----+----+----+----+----+----+

  blk :: 7
  size :: 3 or 35
  flag :: 1 byte flags
          bit order: 76543210
          bit 0: 1 for key present, 0 for no key present
          bit 1: 1 for reverse key, 0 for forward key
          bit 2: 1 to request reverse key, 0 for no request
                 only set if bit 1 is 0
          bits 7-2: Unused, set to 0 for future compatibility
  key ID :: The key ID of this key. 2 bytes, big endian
            0 - 32767
  Public Key :: The next X25519 public key, 32 bytes, little endian
                Only if bit 0 is 1


{% endhighlight %}

Notes:

- Key ID is an incrementing counter for the local key used for that tag set, starting at 0.
- The ID must not change unless the key changes.
- It may not be strictly necessary, but it's useful for debugging.
  Signal does not use a key ID.
- The maximum Key ID is 32767.
- In the rare case that the tag sets in both directions are ratcheting at
  the same time, a frame will contain two Next Key blocks, one for
  the forward key and one for the reverse key.
- Key and tag set ID numbers must be sequential.
- See the DH Ratchet section above for details.


Ack
```
This is only sent if an ack request block was received.
Multiple acks may be present to ack multiple messages.

Not allowed in NS or NSR. Only included in Existing Session messages.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 8  |  size   |tagsetid |   N     |    |
  +----+----+----+----+----+----+----+    +
  |             more acks                 |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 8
  size :: 4 * number of acks to follow, minimum 1 ack
  for each ack:
  tagsetid :: 2 bytes, big endian, from the message being acked
  N :: 2 bytes, big endian, from the message being acked


{% endhighlight %}


Notes:

- The tag set ID and N uniquely identify the message being acked.
- In the first tag sets used for a session in each direction, the tag set ID is 0.
- No NextKey blocks have been sent, so there are no key IDs.
- For all tag sets used after NextKey exchanges, The tag set number is (1 + Alice's key ID + Bob's key ID).



Ack Request
```````````
Request an in-band ack.
To replace the out-of-band DeliveryStatus Message in the Garlic Clove.

If an explicit ack is requested, the current tagset ID and message number (N)
are returned in an ack block.

Not allowed in NS or NSR. Only included in Existing Session messages.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+
  |  9 |  size   |flg |
  +----+----+----+----+

  blk :: 9
  size :: 1
  flg :: 1 byte flags
         bits 7-0: Unused, set to 0 for future compatibility

{% endhighlight %}



Padding
```````
All padding is inside AEAD frames.
TODO Padding inside AEAD should roughly adhere to the negotiated parameters.
TODO Alice sent her requested tx/rx min/max parameters in the NS message.
TODO Bob sent his requested tx/rx min/max parameters in the NSR message.
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
  size :: 2 bytes, big endian, 0-65516
  padding :: zeros or random data

{% endhighlight %}

Notes:

- All-zero padding is fine, as it will be encrypted.
- Padding strategies TBD.
- Padding-only frames are allowed.
- Padding default is 0-15 bytes.
- See options block for padding parameter negotiation
- See options block for min/max padding parameters
- Router response on violation of negotiated padding is implementation-dependent.


Other block types
`````````````````
Implementations should ignore unknown block types for
forward compatibility.


Future work
```````````
- The padding length is either to be decided on a per-message basis and
  estimates of the length distribution, or random delays should be added.
  These countermeasures are to be included to resist DPI, as message sizes
  would otherwise reveal that I2P traffic is being carried by the transport
  protocol. The exact padding scheme is an area of future work, Appendix A
  provides more information on the topic.



Typical Usage Patterns
======================


HTTP GET
--------

This is the most typical use case, and most non-HTTP streaming use cases
will be identical to this use case as well.
A small initial message is sent, a reply follows,
and additional messages are sent in both directions.

An HTTP GET generally fits in a single I2NP message.
Alice sends a small request with a single new Session message, bundling a reply leaseset.
Alice includes immediate ratchet to new key.
Includes sig to bind to destination. No ack requested.

Bob ratchets immediately.

Alice ratchets immediately.

Continues on with those sessions.

.. raw:: html

  {% highlight %}
Alice                           Bob

  New Session (1b)     ------------------->
  with ephemeral key 1
  with static key for binding
  with next key
  with bundled HTTP GET
  with bundled LS
  without bundled Delivery Status Message

  any retransmissions, same as above

  following messages may arrive in any order:

  <--------------     New Session Reply (1g)
                      with Bob ephemeral key 1
                      with bundled HTTP reply part 1

  <--------------     New Session Reply (1g)
                      with Bob ephemeral key 2
                      with bundled HTTP reply part 2

  <--------------     New Session Reply (1g)
                      with Bob ephemeral key 3
                      with bundled HTTP reply part 3

  After reception of any of these messages,
  Alice switches to use Existing Session messages,
  creates a new inbound + outbound session pair,
  and ratchets.


  Existing Session     ------------------->
  with bundled streaming ack


  Existing Session     ------------------->
  with bundled streaming ack


  After reception of any of these messages,
  Bob switches to use Existing Session messages.


  <--------------     Existing Session
                      with bundled HTTP reply part 4


  Existing Session     ------------------->
  with bundled streaming ack

  <--------------     Existing Session
                      with bundled HTTP reply part 5

{% endhighlight %}



HTTP POST
---------

Alice has three options:

1) Send the first message only (window size = 1), as in HTTP GET.
   Not recommended.

2) Send up to streaming window, but using same Elligator2-encoded cleartext public key.
   All messages contain same next public key (ratchet).
   This will be visible to OBGW/IBEP because they all start with the same cleartext.
   Things proceed as in 1).
   Not recommended.

3) Recommended implementation.
   Send up to streaming window, but using a different Elligator2-encoded cleartext public key (session) for each.
   All messages contain same next public key (ratchet).
   This will not be visible to OBGW/IBEP because they all start with different cleartext.
   Bob must recognize that they all contain the same next public key,
   and respond to all with the same ratchet.
   Alice uses that next public key and continues.

Option 3 message flow:

.. raw:: html

  {% highlight %}
Alice                           Bob

  New Session (1b)     ------------------->
  with ephemeral key 1
  with static key for binding
  with bundled HTTP POST part 1
  with bundled LS
  without bundled Delivery Status Message


  New Session (1b)     ------------------->
  with ephemeral key 2
  with static key for binding
  with bundled HTTP POST part 2
  with bundled LS
  without bundled Delivery Status Message


  New Session (1b)     ------------------->
  with ephemeral key 3
  with static key for binding
  with bundled HTTP POST part 3
  with bundled LS
  without bundled Delivery Status Message


  following messages can arrive in any order:

  <--------------     New Session Reply (1g)
                      with Bob ephemeral key 1
                      with bundled streaming ack

  <--------------     New Session Reply (1g)
                      with Bob ephemeral key 2
                      with bundled streaming ack

  After reception of any of these messages,
  Alice switches to use Existing Session messages,
  creates a new inbound + outbound session pair,
  and ratchets.


  following messages can arrive in any order:


  Existing Session     ------------------->
  with bundled HTTP POST part 4

  Existing Session     ------------------->
  with next key
  with bundled HTTP POST part 5


  After reception of any of these messages,
  Bob switches to use Existing Session messages.


  <--------------     Existing Session
                      with bundled streaming ack

  After reception of any of this message,
  Alice switches to use Existing Session messages,
  and Alice ratchets.


  Existing Session     ------------------->
  with next key
  with bundled HTTP POST part 4

  after reception of this message, Bob ratchets

  Existing Session     ------------------->
  with next key
  with bundled HTTP POST part 5

  <--------------     Existing Session
                      with bundled streaming ack

{% endhighlight %}



Repliable Datagram
------------------

A single message, with a single reply expected.
Additional messages or replies may be sent.

Similar to HTTP GET, but with smaller options for session tag window size and lifetime.
Maybe don't request a ratchet.

.. raw:: html

  {% highlight %}
Alice                           Bob

  New Session (1b)     ------------------->
  with static key for binding
  with next key
  with bundled repliable datagram
  with bundled LS
  without bundled Delivery Status Message


  <--------------     New Session Reply (1g)
                      with Bob ephemeral key
                      with bundled reply part 1

  <--------------     New Session Reply (1g)
                      with Bob ephemeral key
                      with bundled reply part 2

  After reception of either message,
  Alice switches to use Existing Session messages,
  and ratchets.

  If the Existing Session message arrives first,
  Alice ratchets on the existing inbound and outbound
  sessions.

  When the New Session Reply arrives, Alice
  sets the existing inbound session to expire,
  creates a new inbound and outbound session,
  and sends Existing Session messages on
  the new outbound session.

  Alice keeps the expiring inbound session
  around for a while to process the Existing Session
  message sent to Alice.
  If all expected original Existing Session message replies
  have been processed, Alice can expire the original
  inbound session immediately.

  if there are any other messages:

  Existing Session     ------------------->
  with bundled message

  Existing Session     ------------------->
  with bundled streaming ack

  <--------------     Existing Session
                      with bundled message

{% endhighlight %}



Multiple Raw Datagrams
----------------------

Multiple anonymous messages, with no replies expected.

In this scenario, Alice requests a session, but without binding.
New session message is sent.
No reply LS is bundled.
A reply DSM is bundled (this is the only use case that requires bundled DSMs).
No next key is included. No reply or ratchet is requested.
No ratchet is sent.
Options set session tags window to zero.

.. raw:: html

  {% highlight %}
Alice                           Bob

  New Session (1c)     ------------------->
  with bundled message
  without bundled LS
  with bundled Delivery Status Message 1

  New Session (1c)     ------------------->
  with bundled message
  without bundled LS
  with bundled Delivery Status Message 2

  New Session (1c)     ------------------->
  with bundled message
  without bundled LS
  with bundled Delivery Status Message 3
 
  following messages can arrive in any order:

  <--------------     Delivery Status Message 1

  <--------------     Delivery Status Message 2

  <--------------     Delivery Status Message 3

  After reception of any of these messages,
  Alice switches to use Existing Session messages.

  Existing Session     ------------------->

  Existing Session     ------------------->

  Existing Session     ------------------->

{% endhighlight %}



Single Raw Datagram
-------------------

A single anonymous messages, with no reply expected.

One-time message is sent.
No reply LS or DSM are bundled. No next key is included. No reply or ratchet is requested.
No ratchet is sent.
Options set session tags window to zero.

.. raw:: html

  {% highlight %}
Alice                           Bob

  One-Time Message (1d)   ------------------->
  with bundled message
  without bundled LS
  without bundled Delivery Status Message

{% endhighlight %}



Long-Lived Sessions
-------------------

Long-lived sessions may ratchet, or request a ratchet, at any time,
to maintain forward secrecy from that point in time.
Sessions must ratchet as they approach the limit of sent messages per-session (65535).



Implementation Considerations
=============================

Defense
------------

As with the existing ElGamal/AES+SessionTag protocol, implementations must
limit session tag storage and protect against memory exhaustion attacks.

Some recommended strategies include:

- Hard limit on number of session tags stored
- Aggressive expiration of idle inbound sessions when under memory pressure
- Limit on number of inbound sessions bound to a single far-end destination
- Adaptive reduction of session tag window and deletion of old unused tags
  when under memory pressure
- Refusal to ratchet when requested, if under memory pressure


Parameters
------------

Recommended parameters and timeouts:

- NSR tagset size: 12 tsmin and tsmax
- ES tagset 0 size: tsmin 24, tsmax 160
- ES tagset (1+) size: 160 tsmin and tsmax
- NSR tagset timeout: 3 minutes for receiver
- ES tagset timeout: 8 minutes for sender, 10 minutes for receiver
- Remove previous ES tagset after: 3 minutes
- Tagset look ahead of tag N: min(tsmax, tsmin + N/4)
- Tagset trim behind tag N: min(tsmax, tsmin + N/4) / 2
- Send next key at tag: 4096
- Send next key after tagset lifetime: TBD
- Replace session if NS received after: 3 minutes
- Max clock skew: -5 minutes to +2 minutes
- NS replay filter duration: 5 minutes
- Padding size: 0-15 bytes (other strategies TBD)


Classification
------------------

Following are recommendations for classifying incoming messages.


X25519 Only
`````````````

On a tunnel that is solely used with this protocol, do identification
as is done currently with ElGamal/AES+SessionTags:

First, treat the initial data as a session tag, and look up the session tag.
If found, decrypt using the stored data associated with that session tag.

If not found, treat the initial data as a DH public key and nonce.
Perform a DH operation and the specified KDF, and attempt to decrypt the remaining data.


X25519 Shared with ElGamal/AES+SessionTags
````````````````````````````````````````````

On a tunnel that supports both this protocol and
ElGamal/AES+SessionTags, classify incoming messages as follows:

Due to a flaw in the ElGamal/AES+SessionTags specification,
the AES block is not padded to a random non-mod-16 length.
Therefore, the length of Existing Session messages mod 16 is always 0,
and the length of New Session messages mod 16 is always 2 (since the
ElGamal block is 514 bytes long).

If the length mod 16 is not 0 or 2,
treat the initial data as a session tag, and look up the session tag.
If found, decrypt using the stored data associated with that session tag.

If not found, and the length mod 16 is not 0 or 2,
treat the initial data as a DH public key and nonce.
Perform a DH operation and the specified KDF, and attempt to decrypt the remaining data.
(based on the relative traffic mix, and the relative costs of X25519 and ElGamal DH operations,
ths step may be done last instead)

Otherwise, if the length mod 16 is 0,
treat the initial data as a ElGamal/AES session tag, and look up the session tag.
If found, decrypt using the stored data associated with that session tag.

If not found, and the data is at least 642 (514 + 128) bytes long,
and the length mod 16 is 2,
treat the initial data as a ElGamal block.
Attempt to decrypt the remaining data.

Note that if the ElGamal/AES+SessionTag spec is updated to allow
non-mod-16 padding, things will need to be done differently.



Retransmissions and State Transistions
--------------------------------------

The ratchet layer does not do retransmissions, and with two exceptions,
does not use timers for tranmssions. Timers are also required
for tagset timeout.

Transmission timers are used only for sending NSR and for
replying with an ES when a received ES contains an ACK request.
Recommended timeout is one second. In almost all cases, the
higher layer (datagram or streaming) will reply, forcing
a NSR or ES, and the timer may be cancelled.
If the timer does fire, send an empty payload with the NSR or ES.



Ratchet-layer Responses
````````````````````````

Initial implementations rely on bidirectional traffic at the higher layers.
That is, the implementations assume that traffic in the opposite direction
will soon be transmitted, which will force any required response at the ECIES layer.

However, certain traffic may be unidirectional or very low bandwidth,
such that there is no higher-layer traffic to generate a timely response.

Receipt of NS and NSR messages require a response;
receipt of ACK Request and Next Key blocks also require a response.

Implementations should start a timer when one of these
messages is received which requires a response,
and generate an "empty" (no Garlic Clove block) response
at the ECIES layer
if no reverse traffic is sent in a short period of time (e.g. 1 second).

It may also be appropriate for an even shorter timeout for
responses to NS and NSR messages, to shift the traffic to
the efficient ES messages as soon as possible.


NS Binding For NSR
``````````````````

At the ratchet layer, as Bob, Alice is only known by static key.
The NS message is authenticated ([Noise]_ IK sender authentication 1).
However, this is not sufficient for the ratchet layer to be able to send anything
to Alice, as network routing requires a full Destination.

Before the NSR may be sent, Alice's full Destination must be discovered either
by the ratchet layer or a higher-layer repliable protocol,
either repliable [Datagrams]_ or [Streaming]_.
After finding the Leaseset for that Destination, that Leaseset
will contain the same static key as contained in the NS.

Typically, the higher layer will respond, forcing a network database
lookup of Alice's Leaseset by Alice's Destination Hash.
That Leaseset will almost always be found locally, because the
NS contained a Garlic Clove block, containing a Database Store message,
containing Alice's Leaseset.

For Bob to be prepared to send a ratchet-layer NSR, and to bind
the pending session to Alice's Destination, Bob should
"capture" the Destination while processing the NS payload.
If a Database Store message is found containing a Leaseset
with a key matching the static key in the NS,
the pending session is now bound to that Destination,
and Bob knows where to send any NSR if the response timer expires.
This is the recommended implementation.

An alternative design is to maintain a cache or database
where the static key is mapped to a Destination.
The security and practicality of this approach
is a topic for further study.

Neither this specification nor others strictly require that
every NS contains Alice's Leaseset.
However, in practice, it should.
The recommended ES tagset sender timeout (8 minutes)
is shorter than the maximum Leaseset timeout (10 minutes),
so there could be a small window where the previous session
has expired, Alice thinks that Bob
still has her valid Leaseset, and does not send a new Leaseset
with the new NS. This is a topic for further study.


Multiple NS Messages
````````````````````

If no NSR response is received before the higher layer (datagram or streaming)
sends more data, possibly as a retransmission, Alice must compose a new NS, using a new ephemeral key.
Do not reuse the ephemeral key from any previous NS.
Alice must maintain the additional handshake state and derived receive tagset,
to receive NSR messages in reply to any NSR that was sent.

Implementations may limit the total number of NS messages sent,
or the rate of NS message sending,
either by queueing or dropping higher layer messages before they are sent.

In certain situations, when under high load, or under certain attack scenarios,
it may be appropriate for Bob to queue, drop, or limit apparent NS messages without attempting to decrypt,
to avoid a resource exhaustion attack.

For each NS received, Bob generates an NSR outbund tagset, sends an NSR, does a split(),
and generates the inbound and outbound ES tagsets.
However, Bob does not send any ES messages until the first ES message
on the corresponding inbound tagset is received. After that, Bob may discard
all handshake states and tagsets for any other NS received or NSR sent, or allow
them to expire shortly. Do not use NSR tagsets for ES messages.

It is a topic for further study if Bob may choose to speculatively send ES messages immediately after
the NSR, even before receiving the first ES from Alice.
In certain scenarios and traffic patterns, this could save substantial
bandwidth and CPU.
This strategy may be based on heuristics such as traffic patterns,
percentage of ESs received on the first session's tagset, or other data.



Multiple NSR Messages
`````````````````````

For each NS message received, until an ES message is received, Bob must reply
with a new NSR, either due to higher layer traffic being sent, or NSR send timer expiration.

Each NSR uses the handshake state and tagset corresponding to the incoming NS.
Bob must maintain the handshake state and tagest for all NS messages received, until
an ES message is received.

Implementations may limit the total number of NSR messages sent,
or the rate of NSR message sending,
either by queueing or dropping higher layer messages before they are sent.
These may be limited either when caused by incoming NS messages, or
additional higher layer outbound traffic.

In certain situations, when under high load, or under certain attack scenarios,
it may be appropriate for Alice to queue, drop, or limit NSR messages
without attempting to decrypt, to avoid a resource exhaustion attack.
These limits may be either total across all sessions, per session, or both.

Once Alice receives an NSR, Alice does a split() to derive the ES session keys.
Alice should set a timer, and send an empty ES message if the higher layer does
not send any traffic, typically within one second.

The other inbound NSR tagsets may be removed soon or allowed
to expire, but Alice should keep them for a short while, to
decrypt any other NSR messages that are received.


Replay Prevention
-----------------

Bob must implement a Bloom filter or other mechanism to prevent NS replay attacks,
if the included DateTime is recent, and reject NS messages where the
DateTime is too old.
Bob may also have use an earlier replay detection check for a duplicate ephemeral key
(either pre- or post-Elligator2 decode) to detect and drop recent duplicate NS messages
before decryption.

NSR and ES messages have inherent replay prevention because the
session tag is one-time-use.

Garlic messages also have replay prevention if the router implements
a router-wide Bloom filter based on I2NP message ID.




Related Changes
=====================

Database Lookups from ECIES Destinations: See [Prop154]_,
now incorporated in [I2NP]_ for release 0.9.46.

This specification requires LS2 support to publish the X25519 public key with the leaseset.
No changes are required to the LS2 specifications in [I2NP]_.
All support was designed, specified, and implemented in [Prop123]_ implemented in 0.9.38.

This specification requires a property to be set in the I2CP options to be enabled.
All support was designed, specified, and implemented in [Prop123]_ implemented in 0.9.38.

The option required to enable ECIES is a single I2CP property
for I2CP, BOB, SAM, or i2ptunnel.

Typical values are i2cp.leaseSetEncType=4 for ECIES only,
or i2cp.leaseSetEncType=4,0 for ECIES and ElGamal dual keys.



Compatibility
===============

Any router supporting LS2 with dual keys (0.9.38 or higher) should support
connection to destinations with dual keys.

ECIES-only destinations require a majority of the floodfills to be updated
to 0.9.46 to get encrypted lookup replies. See [Prop154]_.

ECIES-only destinations can only connect with other destinations that are
either ECIES-only, or dual-key.



References
==========

.. [Common]
    {{ spec_url('common-structures') }}

.. [CRYPTO-ELG]
    {{ site_url('docs/how/cryptography', True) }}#elgamal

.. [ECIES-HYBRID]
   {{ spec_url('ecies-hybrid') }}

.. [Datagrams]
    {{ spec_url('datagrams') }}

.. [Elligator2]
    https://elligator.cr.yp.to/elligator-20130828.pdf
    https://www.imperialviolet.org/2013/12/25/elligator.html
    See also OBFS4 code

.. [ElG-AES]
    {{ site_url('docs/how/elgamal-aes', True) }}

.. [GARLICSPEC]
    {{ site_url('docs/how/garlic-routing', True) }}

.. [I2CP]
    {{ spec_url('i2cp') }}

.. [I2NP]
    {{ spec_url('i2np') }}

.. [NTCP2]
    {{ spec_url('ntcp2') }}

.. [NOISE]
    https://noiseprotocol.org/noise.html

.. [Prop111]
    {{ proposal_url('111') }}

.. [Prop123]
    {{ proposal_url('123') }}

.. [Prop142]
    {{ proposal_url('142') }}

.. [Prop144]
    {{ proposal_url('144') }}

.. [Prop145]
    {{ proposal_url('145') }}

.. [Prop152]
    {{ proposal_url('152') }}

.. [Prop153]
    {{ proposal_url('153') }}

.. [Prop154]
    {{ proposal_url('154') }}

.. [RFC-2104]
    https://tools.ietf.org/html/rfc2104

.. [RFC-5869]
    https://tools.ietf.org/html/rfc5869

.. [RFC-7539]
    https://tools.ietf.org/html/rfc7539

.. [RFC-7748]
    https://tools.ietf.org/html/rfc7748

.. [RFC-7905]
    https://tools.ietf.org/html/rfc7905

.. [RFC-4880-S5.1]
    https://tools.ietf.org/html/rfc4880#section-5.1

.. [Signal]
    https://signal.org/docs/specifications/doubleratchet/

.. [SSU]
    {{ site_url('docs/transport/ssu', True) }}

.. [SSU2]
    {{ spec_url('ssu2') }}

.. [Streaming]
    {{ spec_url('streaming') }}

.. [STS]
    Diffie, W.; van Oorschot P. C.; Wiener M. J., Authentication and
    Authenticated Key Exchanges
