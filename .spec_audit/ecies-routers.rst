=============================
ECIES-X25519 Router Messages
=============================
.. meta::
    :category: Protocols
    :lastupdated: 2025-03
    :accuratefor: 0.9.65

.. contents::


Note
====
Supported as of release 0.9.49.
Network deployment and testing in progress.
Subject to minor revision.
See proposal 156 [Prop156]_.


Overview
========

This document specifies Garlic message encryption to ECIES routers,
using crypto primitives introduced by [ECIES-X25519]_.
It is a portion of the overall proposal
[Prop156]_ for converting routers from ElGamal to ECIES-X25519 keys.
This specification is implemented as of release 0.9.49.

For an overview of all changes required for ECIES routers, see proposal 156 [Prop156]_.
For Garlic Messages to ECIES-X25519 destinations, see [ECIES-X25519]_.


Cryptographic Primitives
------------------------

The primitives required to implement this specification are:

- AES-256-CBC as in [Cryptography]_
- STREAM ChaCha20/Poly1305 functions:
  ENCRYPT(k, n, plaintext, ad) and DECRYPT(k, n, ciphertext, ad) - as in [NTCP2]_ [ECIES-X25519]_ and [RFC-7539]_
- X25519 DH functions - as in [NTCP2]_ and [ECIES-X25519]_
- HKDF(salt, ikm, info, n) - as in [NTCP2]_ and [ECIES-X25519]_

Other Noise functions defined elsewhere:

- MixHash(d) - as in [NTCP2]_ and [ECIES-X25519]_
- MixKey(d) - as in [NTCP2]_ and [ECIES-X25519]_



Design
======

The ECIES Router SKM does not need a full Ratchet SKM as specified in [ECIES]_ for Destinations.
There is no requirement for non-anonymous messages using the IK pattern.
The threat model does not require Elligator2-encoded ephemeral keys.

Therefore, the router SKM will use the Noise "N" pattern, same as specified
in [Prop152]_ for tunnel building.
It will use the same payload format as specified in [ECIES]_ for Destinations.
The zero static key (no binding or session) mode of IK specified in [ECIES]_ will not be used.

Replies to lookups will be encrypted with a ratchet tag if requested in the lookup.
This is as documented in [Prop154]_,  now specified in [I2NP]_.

The design enables the router to have a single ECIES Session Key Manager.
There is no need to run "dual key" Session Key Managers as
described in [ECIES]_ for Destinations.
Routers only have one public key.

An ECIES router does not have an ElGamal static key.
The router still needs an implementation of ElGamal to build tunnels
through ElGamal routers and send encrypted messages to ElGamal routers.

An ECIES router MAY require a partial ElGamal Session Key Manager to
receive ElGamal-tagged messages received as replies to NetDB lookups
from pre-0.9.46 floodfill routers, as those routers do not
have an implementation of ECIES-tagged replies as specified in [Prop152]_.
If not, an ECIES router may not request an encrypted reply from a
pre-0.9.46 floodfill router.

This is optional. Decision may vary in various I2P implementations
and may depend on the amount of the network that has upgraded to
0.9.46 or higher.
As of this date, approximately 85% of the network is 0.9.46 or higher.


Noise Protocol Framework
------------------------

This specification provides the requirements based on the Noise Protocol Framework
[NOISE]_ (Revision 34, 2018-07-11).
In Noise parlance, Alice is the initiator, and Bob is the responder.

It is based on the Noise protocol Noise_N_25519_ChaChaPoly_SHA256.
This Noise protocol uses the following primitives:

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


Handshake Patterns
------------------

Handshakes use [Noise]_ handshake patterns.

The following letter mapping is used:

- e = one-time ephemeral key
- s = static key
- p = message payload

The build request is identical to the Noise N pattern.
This is also identical to the first (Session Request) message in the XK pattern used in [NTCP2]_.


.. raw:: html

  {% highlight lang='dataspec' %}
<- s
  ...
  e es p ->

{% endhighlight %}


Message encryption
-----------------------

Messages are created and asymmetrically encrypted to the target router.
This asymmetric encryption of messages is currently ElGamal as defined in [Cryptography]_
and contains a SHA-256 checksum. This design is not forward-secret.

The ECIES design uses the one-way Noise pattern "N" with ECIES-X25519 ephemeral-static DH, with an HKDF, and
ChaCha20/Poly1305 AEAD for forward secrecy, integrity, and authentication.
Alice is the anonymous message sender, a router or destination.
The target ECIES router is Bob.



Reply encryption
-----------------------

Replies are not part of this protocol, as Alice is anonymous. The reply keys, if any,
are bundled in the request message. See the I2NP specification [I2NP]_ for Database Lookup Messages.

Replies to Database Lookup messages are Database Store or Database Search Reply messages.
They are encrypted as Existing Session messages with
the 32-byte reply key and 8-byte reply tag
as specified in [I2NP]_ and [Prop154]_.

There are no explicit replies to Database Store messages. The sender may bundle its
own reply as a Garlic Message to itself, containing a Delivery Status message.



Specification
=========================

X25519: See [ECIES]_.

Router Identity and Key Certificate: See [Common]_.


Request Encryption
---------------------

The request encryption is the same as that specified in [Tunnel-Creation-ECIES]_ and [Prop152]_,
using the Noise "N" pattern.

Replies to lookups will be encrypted with a ratchet tag if requested in the lookup.
Database Lookup request messages contain the 32-byte reply key and 8-byte reply tag
as specified in [I2NP]_ and [Prop154]_. The key and tag are used to encrypt the reply.

Tag sets are not created.
The zero static key scheme specified in
ECIES-X25519-AEAD-Ratchet [Prop144]_ and [ECIES]_ will not be used.
Ephemeral keys will not be Elligator2-encoded.

Generally, these will be New Session messages and will be sent with a zero static key
(no binding or session), as the sender of the message is anonymous.


KDF for Initial ck and h
````````````````````````

This is standard [NOISE]_ for pattern "N" with a standard protocol name.
This is the same as specified in [Tunnel-Creation-ECIES]_ and [Prop152]_ for tunnel build messages.


.. raw:: html

  {% highlight lang='text' %}
This is the "e" message pattern:

  // Define protocol_name.
  Set protocol_name = "Noise_N_25519_ChaChaPoly_SHA256"
  (31 bytes, US-ASCII encoded, no NULL termination).

  // Define Hash h = 32 bytes
  // Pad to 32 bytes. Do NOT hash it, because it is not more than 32 bytes.
  h = protocol_name || 0

  Define ck = 32 byte chaining key. Copy the h data to ck.
  Set chainKey = h

  // MixHash(null prologue)
  h = SHA256(h);

  // up until here, can all be precalculated by all routers.

{% endhighlight %}


KDF for Message
````````````````````````

Message creators generate an ephemeral X25519 keypair for each message.
Ephemeral keys must be unique per message.
This is the same as specified in [Tunnel-Creation-ECIES]_ and [Prop152]_ for tunnel build messages.


.. raw:: html

  {% highlight lang='dataspec' %}

// Target router's X25519 static keypair (hesk, hepk) from the Router Identity
  hesk = GENERATE_PRIVATE()
  hepk = DERIVE_PUBLIC(hesk)

  // MixHash(hepk)
  // || below means append
  h = SHA256(h || hepk);

  // up until here, can all be precalculated by each router
  // for all incoming messages

  // Sender generates an X25519 ephemeral keypair
  sesk = GENERATE_PRIVATE()
  sepk = DERIVE_PUBLIC(sesk)

  // MixHash(sepk)
  h = SHA256(h || sepk);

  End of "e" message pattern.

  This is the "es" message pattern:

  // Noise es
  // Sender performs an X25519 DH with receiver's static public key.
  // The target router
  // extracts the sender's ephemeral key preceding the encrypted record.
  sharedSecret = DH(sesk, hepk) = DH(hesk, sepk)

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  // ChaChaPoly parameters to encrypt/decrypt
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  // Chain key is not used
  //chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  plaintext = 464 byte build request record
  ad = h
  ciphertext = ENCRYPT(k, n, plaintext, ad)

  End of "es" message pattern.

  // MixHash(ciphertext) is not required
  //h = SHA256(h || ciphertext)

{% endhighlight %}



Payload
````````````````````````

The payload is the same block format as defined in [ECIES]_ and [Prop144]_.
All messages must contain a DateTime block for replay prevention.




Implementation Notes
=====================

* Older routers do not check the encryption type of the router and will send ElGamal-encrypted
  messages. Some recent routers are buggy and will send various types of malformed messages.
  Implementers should detect and reject these records prior to the DH operation
  if possible, to reduce CPU usage.



References
==========

.. [Common]
    {{ spec_url('common-structures') }}

.. [Cryptography]
   {{ spec_url('cryptography') }}

.. [ECIES]
   {{ spec_url('ecies') }}

.. [ECIES-X25519]
   {{ spec_url('ecies') }}

.. [I2NP]
   {{ spec_url('i2np') }}

.. [NOISE]
    https://noiseprotocol.org/noise.html

.. [NTCP2]
   {{ spec_url('ntcp2') }}

.. [Prop119]
   {{ proposal_url('119') }}

.. [Prop143]
   {{ proposal_url('143') }}

.. [Prop144]
    {{ proposal_url('144') }}

.. [Prop152]
    {{ proposal_url('152') }}

.. [Prop153]
    {{ proposal_url('153') }}

.. [Prop154]
    {{ proposal_url('154') }}

.. [Prop156]
    {{ proposal_url('156') }}

.. [Prop157]
    {{ proposal_url('157') }}

.. [RFC-7539]
   https://tools.ietf.org/html/rfc7539

.. [RFC-7748]
   https://tools.ietf.org/html/rfc7748

.. [Tunnel-Creation]
   {{ spec_url('tunnel-creation') }}

.. [Tunnel-Creation-ECIES]
   {{ spec_url('tunnel-creation-ecies') }}



