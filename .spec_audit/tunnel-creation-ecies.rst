=============================
ECIES-X25519 Tunnel Creation
=============================
.. meta::
    :category: Protocols
    :lastupdated: 2025-06
    :accuratefor: 0.9.66

.. contents::

Overview
========

This document specifies Tunnel Build message encryption
using crypto primitives introduced by [ECIES-X25519]_.
It is a portion of the overall proposal
[Prop156]_ for converting routers from ElGamal to ECIES-X25519 keys.

There are two versions specified.
The first uses the existing build messages and build record size, for compatibility with ElGamal routers.
This specification was implemented as of release 0.9.48 and is now deprecated.
The second uses two new build messages and a smaller build record size, and may only be used with ECIES routers.
This specification is implemented as of release 0.9.51.

For the purposes of transitioning the network from ElGamal + AES256 to ECIES + ChaCha20,
tunnels with mixed ElGamal and ECIES routers are necessary.
Specifications for handling mixed tunnel hops are provided.
No changes will be made to the format, processing, or encryption of ElGamal hops.
This format maintains the same size for tunnel build records,
as required for compatibility.

ElGamal tunnel creators will generate ephemeral X25519 keypairs per-hop, and
follow this spec for creating tunnels containing ECIES hops.

This document specifies ECIES-X25519 Tunnel Building.
For an overview of all changes required for ECIES routers, see proposal 156 [Prop156]_.
For additional background on the development of the long record specification, see proposal 152 [Prop152]_.
For additional background on the development of the short record specification, see proposal 157 [Prop157]_.


Cryptographic Primitives
------------------------

The primitives required to implement this specification are:

- AES-256-CBC as in [Cryptography]_
- STREAM ChaCha20 functions:
  ENCRYPT(k, iv, plaintext) and DECRYPT(k, iv, ciphertext) - as in [EncryptedLeaseSet]_ and [RFC-7539]_
- STREAM ChaCha20/Poly1305 functions:
  ENCRYPT(k, n, plaintext, ad) and DECRYPT(k, n, ciphertext, ad) - as in [NTCP2]_ [ECIES-X25519]_ and [RFC-7539]_
- X25519 DH functions - as in [NTCP2]_ and [ECIES-X25519]_
- HKDF(salt, ikm, info, n) - as in [NTCP2]_ and [ECIES-X25519]_

Other Noise functions defined elsewhere:

- MixHash(d) - as in [NTCP2]_ and [ECIES-X25519]_
- MixKey(d) - as in [NTCP2]_ and [ECIES-X25519]_



Design
======

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


Request encryption
-----------------------

Build request records are created by the tunnel creator and asymmetrically encrypted to the individual hop.
This asymmetric encryption of request records is currently ElGamal as defined in [Cryptography]_
and contains a SHA-256 checksum. This design is not forward-secret.

The ECIES design uses the one-way Noise pattern "N" with ECIES-X25519 ephemeral-static DH, with an HKDF, and
ChaCha20/Poly1305 AEAD for forward secrecy, integrity, and authentication.
Alice is the tunnel build requestor. Each hop in the tunnel is a Bob.



Reply encryption
-----------------------

Build reply records are created by the hops creator and symmetrically encrypted to the creator.
This symmetric encryption of ElGamal reply records is AES with a prepended SHA-256 checksum.
and contains a SHA-256 checksum. This design is not forward-secret.

ECIES replies use ChaCha20/Poly1305 AEAD for integrity, and authentication.



Long Record Specification
=========================

NOTE: Deprecated, obsolete. Use the Short Record format specified  below.


Build Request Records
-------------------------------------

Encrypted BuildRequestRecords are 528 bytes for both ElGamal and ECIES, for compatibility.




Request Record Unencrypted
```````````````````````````````````````

This is the specification of the tunnel BuildRequestRecord for ECIES-X25519 routers.
Summary of changes:

- Remove unused 32-byte router hash
- Change request time from hours to minutes
- Add expiration field for future variable tunnel time
- Add more space for flags
- Add Mapping for additional build options
- AES-256 reply key and IV are not used for the hop's own reply record
- Unencrypted record is longer because there is less encryption overhead


The request record does not contain any ChaCha reply keys.
Those keys are derived from a KDF. See below.

All fields are big-endian.

Unencrypted size: 464 bytes

.. raw:: html

  {% highlight lang='dataspec' %}

bytes     0-3: tunnel ID to receive messages as, nonzero
  bytes     4-7: next tunnel ID, nonzero
  bytes    8-39: next router identity hash
  bytes   40-71: AES-256 tunnel layer key
  bytes  72-103: AES-256 tunnel IV key
  bytes 104-135: AES-256 reply key
  bytes 136-151: AES-256 reply IV
  byte      152: flags
  bytes 153-155: more flags, unused, set to 0 for compatibility
  bytes 156-159: request time (in minutes since the epoch, rounded down)
  bytes 160-163: request expiration (in seconds since creation)
  bytes 164-167: next message ID
  bytes   168-x: tunnel build options (Mapping)
  bytes     x-x: other data as implied by flags or options
  bytes   x-463: random padding

{% endhighlight %}

The flags field is the same as defined in [Tunnel-Creation]_ and contains the following::

 Bit order: 76543210 (bit 7 is MSB)
 bit 7: if set, allow messages from anyone
 bit 6: if set, allow messages to anyone, and send the reply to the
        specified next hop in a Tunnel Build Reply Message
 bits 5-0: Undefined, must set to 0 for compatibility with future options

Bit 7 indicates that the hop will be an inbound gateway (IBGW).  Bit 6
indicates that the hop will be an outbound endpoint (OBEP).  If neither bit is
set, the hop will be an intermediate participant.  Both cannot be set at once.

The request exipration is for future variable tunnel duration.
For now, the only supported value is 600 (10 minutes).

The tunnel build options is a Mapping structure as defined in [Common]_.
The only options currently defined are for bandwidth parameters, as of API 0.9.65, see below for details.
If the Mapping structure is empty, this is two bytes 0x00 0x00.
The maximum size of the Mapping (including the length field) is 296 bytes,
and the maximum value of the Mapping length field is 294.



Request Record Encrypted
`````````````````````````````````````

All fields are big-endian except for the ephemeral public key which is little-endian.

Encrypted size: 528 bytes

.. raw:: html

  {% highlight lang='dataspec' %}

bytes    0-15: Hop's truncated identity hash
  bytes   16-47: Sender's ephemeral X25519 public key
  bytes  48-511: ChaCha20 encrypted BuildRequestRecord
  bytes 512-527: Poly1305 MAC

{% endhighlight %}



Build Reply Records
-------------------------------------

Encrypted BuildReplyRecords are 528 bytes for both ElGamal and ECIES, for compatibility.


Reply Record Unencrypted
`````````````````````````````````````
This is the specification of the tunnel BuildReplyRecord for ECIES-X25519 routers.
Summary of changes:

- Add Mapping for build reply options
- Unencrypted record is longer because there is less encryption overhead

ECIES replies are encrypted with ChaCha20/Poly1305.

All fields are big-endian.

Unencrypted size: 512 bytes

.. raw:: html

  {% highlight lang='dataspec' %}

bytes    0-x: Tunnel Build Reply Options (Mapping)
  bytes    x-x: other data as implied by options
  bytes  x-510: Random padding
  byte     511: Reply byte

{% endhighlight %}

The tunnel build reply options is a Mapping structure as defined in [Common]_.
The only options currently defined are for bandwidth parameters, as of API 0.9.65, see below for details.
If the Mapping structure is empty, this is two bytes 0x00 0x00.
The maximum size of the Mapping (including the length field) is 511 bytes,
and the maximum value of the Mapping length field is 509.

The reply byte is one of the following values
as defined in [Tunnel-Creation]_ to avoid fingerprinting:

- 0x00 (accept)
- 30 (TUNNEL_REJECT_BANDWIDTH)


Reply Record Encrypted
```````````````````````````````````

Encrypted size: 528 bytes

.. raw:: html

  {% highlight lang='dataspec' %}

bytes   0-511: ChaCha20 encrypted BuildReplyRecord
  bytes 512-527: Poly1305 MAC

{% endhighlight %}

After full transition to ECIES records, ranged padding rules are the same as for request records.


Symmetric Encryption of Records
--------------------------------------------------------

Mixed tunnels are allowed, and necessary, for the transition from ElGamal to ECIES.
During the transitionary period, an increasing number of routers will be keyed under ECIES keys.

Symmetric cryptography preprocessing will run in the same way:

- "encryption":

  - cipher run in decryption mode
  - request records preemptively decrypted in preprocessing (concealing encrypted request records)

- "decryption":

  - cipher run in encryption mode
  - request records encrypted (revealing next plaintext request record) by participant hops

- ChaCha20 does not have "modes", so it is simply run three times:

  - once in preprocessing
  - once by the hop
  - once on final reply processing

When mixed tunnels are used, tunnel creators will need to base the symmetric encryption
of BuildRequestRecord on the current and previous hop's encryption type.

Each hop will use its own encryption type for encrypting BuildReplyRecords, and the other
records in the VariableTunnelBuildMessage (VTBM).

On the reply path, the endpoint (sender) will need to undo the [Multiple-Encryption]_, using each hop's reply key.

As a clarifying example, let's look at an outbound tunnel w/ ECIES surrounded by ElGamal:

- Sender (OBGW) -> ElGamal (H1) -> ECIES (H2) -> ElGamal (H3)

All BuildRequestRecords are in their encrypted state (using ElGamal or ECIES).

AES256/CBC cipher, when used, is still used for each record, without chaining across multiple records.

Likewise, ChaCha20 will be used to encrypt each record, not streaming across the entire VTBM.

The request records are preprocessed by the Sender (OBGW):

- H3's record is "encrypted" using:

  - H2's reply key (ChaCha20)
  - H1's reply key (AES256/CBC)

- H2's record is "encrypted" using:

  - H1's reply key (AES256/CBC)

- H1's record goes out without symmetric encryption

Only H2 checks the reply encryption flag, and sees its followed by AES256/CBC.

After being processed by each hop, the records are in a "decrypted" state:

- H3's record is "decrypted" using:

  - H3's reply key (AES256/CBC)

- H2's record is "decrypted" using:

  - H3's reply key (AES256/CBC)
  - H2's reply key (ChaCha20-Poly1305)

- H1's record is "decrypted" using:

  - H3's reply key (AES256/CBC)
  - H2's reply key (ChaCha20)
  - H1's reply key (AES256/CBC)

The tunnel creator, a.k.a. Inbound Endpoint (IBEP), postprocesses the reply:

- H3's record is "encrypted" using:

  - H3's reply key (AES256/CBC)

- H2's record is "encrypted" using:

  - H3's reply key (AES256/CBC)
  - H2's reply key (ChaCha20-Poly1305)

- H1's record is "encrypted" using:

  - H3's reply key (AES256/CBC)
  - H2's reply key (ChaCha20)
  - H1's reply key (AES256/CBC)


Request Record Keys
-----------------------------------------------------------------------

These keys are explicitly included in ElGamal BuildRequestRecords.
For ECIES BuildRequestRecords, the tunnel keys and AES reply keys are included,
but the ChaCha reply keys are derived from the DH exchange.
See [Prop156]_ for details of the router static ECIES keys.

Below is a description of how to derive the keys previously transmitted in request records.


KDF for Initial ck and h
````````````````````````

This is standard [NOISE]_ for pattern "N" with a standard protocol name.

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


KDF for Request Record
````````````````````````

ElGamal tunnel creators generate an ephemeral X25519 keypair for each
ECIES hop in the tunnel, and use scheme above for encrypting their BuildRequestRecord.
ElGamal tunnel creators will use the scheme prior to this spec for encrypting to ElGamal hops.

ECIES tunnel creators will need to encrypt to each of the ElGamal hop's public key using the
scheme defined in [Tunnel-Creation]_. ECIES tunnel creators will use the above scheme for encrypting
to ECIES hops.

This means that tunnel hops will only see encrypted records from their same encryption type.

For ElGamal and ECIES tunnel creators, they will generate unique ephemeral X25519 keypairs
per-hop for encrypting to ECIES hops.

**IMPORTANT**:
Ephemeral keys must be unique per ECIES hop, and per build record.
Failing to use unique keys opens an attack vector for colluding hops to confirm they are in the same tunnel.


.. raw:: html

  {% highlight lang='dataspec' %}

// Each hop's X25519 static keypair (hesk, hepk) from the Router Identity
  hesk = GENERATE_PRIVATE()
  hepk = DERIVE_PUBLIC(hesk)

  // MixHash(hepk)
  // || below means append
  h = SHA256(h || hepk);

  // up until here, can all be precalculated by each router
  // for all incoming build requests

  // Sender generates an X25519 ephemeral keypair per ECIES hop in the VTBM (sesk, sepk)
  sesk = GENERATE_PRIVATE()
  sepk = DERIVE_PUBLIC(sesk)

  // MixHash(sepk)
  h = SHA256(h || sepk);

  End of "e" message pattern.

  This is the "es" message pattern:

  // Noise es
  // Sender performs an X25519 DH with Hop's static public key.
  // Each Hop, finds the record w/ their truncated identity hash,
  // and extracts the Sender's ephemeral key preceding the encrypted record.
  sharedSecret = DH(sesk, hepk) = DH(hesk, sepk)

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  // ChaChaPoly parameters to encrypt/decrypt
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  // Save for Reply Record KDF
  chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  plaintext = 464 byte build request record
  ad = h
  ciphertext = ENCRYPT(k, n, plaintext, ad)

  End of "es" message pattern.

  // MixHash(ciphertext)
  // Save for Reply Record KDF
  h = SHA256(h || ciphertext)

{% endhighlight %}

``replyKey``, ``layerKey`` and ``layerIV`` must still be included inside ElGamal records,
and can be generated randomly.



Reply Record Encryption
--------------------------------------

The reply record is ChaCha20/Poly1305 encrypted.

.. raw:: html

  {% highlight lang='dataspec' %}

// AEAD parameters
  k = chainkey from build request
  n = 0
  plaintext = 512 byte build reply record
  ad = h from build request

  ciphertext = ENCRYPT(k, n, plaintext, ad)

{% endhighlight %}



Short Record Specification
===========================

This specification uses two new I2NP tunnel build messages,
Short Tunnel Build Message (type 25) and Outbound Tunnel Build Reply Message (type 26).

The tunnel creator and all hops in the created tunnel must ECIES-X25519, and at least version 0.9.51.
The hops in the reply tunnel (for an outbound build) or the outbound tunnel (for an inbound build)
do not have any requirements.

Encrypted request and reply records will be 218 bytes, compared to 528 bytes for all other build messages.

The plaintext request records will be 154 bytes,
compared to 222 bytes for ElGamal records,
and 464 bytes for ECIES records as defined above.

The plaintext response records will be 202 bytes,
compared to 496 bytes for ElGamal records,
and 512 bytes for ECIES records as defined above.

The reply encryption will be ChaCha20/Poly1305 for the hop's own record,
and ChaCha20 (NOT ChaCha20/Poly1305) for the other records in the build message.

Request records will be made smaller by using HKDF to create the
layer and reply keys, so they are not explicitly included in the request.



Message Flow
------------------

.. raw:: html

  {% highlight %}
STBM: Short tunnel build message (type 25)
  OTBRM: Outbound tunnel build reply message (type 26)

  Outbound Build A-B-C
  Reply through existing inbound D-E-F


                  New Tunnel
           STBM      STBM      STBM
  Creator ------> A ------> B ------> C ---\
                                     OBEP   \
                                            | Garlic wrapped (optional)
                                            | OTBRM
                                            | (TUNNEL delivery)
                                            | from OBEP to
                                            | creator
                Existing Tunnel             /
  Creator <-------F---------E-------- D <--/
                                     IBGW



  Inbound Build D-E-F
  Sent through existing outbound A-B-C


                Existing Tunnel
  Creator ------> A ------> B ------> C ---\
                                    OBEP    \
                                            | Garlic wrapped (optional)
                                            | STBM
                                            | (ROUTER delivery)
                                            | from creator
                  New Tunnel                | to IBGW
            STBM      STBM      STBM        /
  Creator <------ F <------ E <------ D <--/
                                     IBGW



{% endhighlight %}


Notes
`````
Garlic wrapping of the messages hides them from the OBEP (for an inbound build)
or the IBGW (for an outbound build). This is recommended but not required.
If the OBEP and IBGW are the same router, it is not necessary.



Short Build Request Records
-------------------------------------

Short encrypted BuildRequestRecords are 218 bytes.


Short Request Record Unencrypted
```````````````````````````````````````

Summary of changes from long records:

- Change unencrypted length from 464 to 154 bytes
- Change encrypted length from 528 to 218 bytes
- Remove layer and reply keys and IVs, they will be generated from a KDF


The request record does not contain any ChaCha reply keys.
Those keys are derived from a KDF. See below.

All fields are big-endian.

Unencrypted size: 154 bytes.

.. raw:: html

  {% highlight lang='dataspec' %}

bytes     0-3: tunnel ID to receive messages as, nonzero
  bytes     4-7: next tunnel ID, nonzero
  bytes    8-39: next router identity hash
  byte       40: flags
  bytes   41-42: more flags, unused, set to 0 for compatibility
  byte       43: layer encryption type
  bytes   44-47: request time (in minutes since the epoch, rounded down)
  bytes   48-51: request expiration (in seconds since creation)
  bytes   52-55: next message ID
  bytes    56-x: tunnel build options (Mapping)
  bytes     x-x: other data as implied by flags or options
  bytes   x-153: random padding (see below)

{% endhighlight %}


The flags field is the same as defined in [Tunnel-Creation]_ and contains the following::

 Bit order: 76543210 (bit 7 is MSB)
 bit 7: if set, allow messages from anyone
 bit 6: if set, allow messages to anyone, and send the reply to the
        specified next hop in a Tunnel Build Reply Message
 bits 5-0: Undefined, must set to 0 for compatibility with future options

Bit 7 indicates that the hop will be an inbound gateway (IBGW).  Bit 6
indicates that the hop will be an outbound endpoint (OBEP).  If neither bit is
set, the hop will be an intermediate participant.  Both cannot be set at once.

Layer encryption type: 0 for AES (as in current tunnels);
1 for future (ChaCha?)

The request exipration is for future variable tunnel duration.
For now, the only supported value is 600 (10 minutes).

The creator ephemeral public key is an ECIES key, big-endian.
It is used for the KDF for the IBGW layer and reply keys and IVs.
This is only included in the plaintext record in an Inbound Tunnel Build message.
It is required because there is no DH at this layer for the build record.

The tunnel build options is a Mapping structure as defined in [Common]_.
The only options currently defined are for bandwidth parameters, as of API 0.9.65, see below for details.
If the Mapping structure is empty, this is two bytes 0x00 0x00.
The maximum size of the Mapping (including the length field) is 98 bytes,
and the maximum value of the Mapping length field is 96.


Short Request Record Encrypted
`````````````````````````````````````

All fields are big-endian except for the ephemeral public key which is little-endian.

Encrypted size: 218 bytes

.. raw:: html

  {% highlight lang='dataspec' %}

bytes    0-15: Hop's truncated identity hash
  bytes   16-47: Sender's ephemeral X25519 public key
  bytes  48-201: ChaCha20 encrypted ShortBuildRequestRecord
  bytes 202-217: Poly1305 MAC

{% endhighlight %}


Short Build Reply Records
-------------------------------------

Short encrypted BuildReplyRecords are 218 bytes.


Short Reply Record Unencrypted
`````````````````````````````````````

Summary of changes from long records:

- Change unencrypted length from 512 to 202 bytes
- Change encrypted length from 528 to 218 bytes


ECIES replies are encrypted with ChaCha20/Poly1305.

All fields are big-endian.

Unencrypted size: 202 bytes.

.. raw:: html

  {% highlight lang='dataspec' %}

bytes    0-x: Tunnel Build Reply Options (Mapping)
  bytes    x-x: other data as implied by options
  bytes  x-200: Random padding (see below)
  byte     201: Reply byte

{% endhighlight %}

The tunnel build reply options is a Mapping structure as defined in [Common]_.
The only options currently defined are for bandwidth parameters, as of API 0.9.65, see below for details.
If the Mapping structure is empty, this is two bytes 0x00 0x00.
The maximum size of the Mapping (including the length field) is 201 bytes,
and the maximum value of the Mapping length field is 199.

The reply byte is one of the following values
as defined in [Tunnel-Creation]_ to avoid fingerprinting:

- 0x00 (accept)
- 30 (TUNNEL_REJECT_BANDWIDTH)

An additional reply value may be defined in the future to
represent rejection for unsupported options.


Short Reply Record Encrypted
```````````````````````````````````

Encrypted size: 218 bytes

.. raw:: html

  {% highlight lang='dataspec' %}

bytes   0-201: ChaCha20 encrypted ShortBuildReplyRecord
  bytes 202-217: Poly1305 MAC

{% endhighlight %}



KDF
---

We use the chaining key (ck) from Noise state after tunnel build record encryption/decrytion
to derive following keys: reply key, AES layer key, AES IV key and garlic reply key/tag for the OBEP.

Reply keys:
Note that the KDF is slightly different for the OBEP and non-OBEP hops.
Unlike long records we can't use left part of ck for reply key, because it's not last and will be used later.
The reply key is used to encypt reply that record using AEAD/Chaha20/Poly1305 and Chacha20 to reply other records.
Both use the same key. The nonce is the record's position in the message starting from 0.
See below for details.


.. raw:: html

  {% highlight lang='dataspec' %}
keydata = HKDF(ck, ZEROLEN, "SMTunnelReplyKey", 64)
  replyKey = keydata[32:63]
  ck = keydata[0:31]

  AES Layer key:
  keydata = HKDF(ck, ZEROLEN, "SMTunnelLayerKey", 64)
  layerKey = keydata[32:63]

  IV key for non-OBEP record:
  ivKey = keydata[0:31]
  because it's last

  IV key for OBEP record:
  ck = keydata[0:31]
  keydata = HKDF(ck, ZEROLEN, "TunnelLayerIVKey", 64)
  ivKey = keydata[32:63]
  ck = keydata[0:31]

  OBEP garlic reply key/tag:
  keydata = HKDF(ck, ZEROLEN, "RGarlicKeyAndTag", 64)
  garlicReplyKey = keydata[32:63]
  garlicReplyTag = keydata[0:7]

{% endhighlight %}

Note: The KDF for the IV key at the OBEP is different from that for the other hops,
even if the reply is not garlic encrypted.


Record Encryption
```````````````````````

The hop's own reply record is encrypted with ChaCha20/Poly1305.
This is the same as for the long record specification above,
EXCEPT that 'n' is the record number 0-7, instead of always being 0.
See [RFC-7539]_.

.. raw:: html

  {% highlight lang='dataspec' %}

// AEAD parameters
  k = replyKey from KDF above
  n = record number 0-7
  plaintext = 202 byte build reply record
  ad = h from build request

  ciphertext = ENCRYPT(k, n, plaintext, ad)

{% endhighlight %}


The other records are iteratively and symmetrically encrypted at each hop with ChaCha20 (NOT ChaCha20/Poly1305).
This is different from the long record specification above, which
uses AES and does not use the record number.

The record number is put in the IV at byte 4, because ChaCha20
uses a 12-byte IV with a little-endian nonce at bytes 4-11.
See [RFC-7539]_.


.. raw:: html

  {% highlight lang='dataspec' %}

// Parameters
  k = replyKey from KDF above
  n = record number 0-7
  iv = 12 bytes, all zeros except iv[4] = n
  plaintext = 218 byte encrypted record

  ciphertext = ENCRYPT(k, iv, plaintext)

{% endhighlight %}


Garlic Encryption
```````````````````````

Garlic wrapping of the messages hides them from the OBEP (for an inbound build)
or the IBGW (for an outbound build). This is recommended but not required.
If the OBEP and IBGW are the same router, it is not necessary.

Garlic encryption of an inbound Short Tunnel Build Message,
by the creator, encrypted to the ECIES IBGW, uses Noise 'N' encryption,
as defined in [ECIES-ROUTERS]_.

Garlic encryption of an Outbound Tunnel Build Reply Message,
by the OBEP, encrypted to the creator, uses
They are encrypted as Existing Session messages with
the 32-byte garlic reply key and 8-byte garlic reply tag from the KDF above.
The format is as specified for replies to Database Lookups in [I2NP]_,
[ECIES-ROUTERS]_, and [ECIES-X25519]_.


Layer Encryption
``````````````````

This specification includes a layer encryption type field in the build request record.
The only layer encryption currently supported is type 0, which is AES.
This is unchanged from previous specifications, except that the layer key and IV key
are derived from the KDF above rather than being included in the build request record.

Adding new layer encryption types, for example ChaCha20, is a topic for additional research,
and is not currently a part of this specification.



Implementation Notes
=====================

* Older routers do not check the encryption type of the hop and will send ElGamal-encrypted
  records. Some recent routers are buggy and will send various types of malformed records.
  Implementers should detect and reject these records prior to the DH operation
  if possible, to reduce CPU usage.

Build Records
-------------

Build record order must be randomized, so middle hops do not
know their location within the tunnel.

The recommended minimum number of build records is 4.
If there are more build records than hops, "fake" records must be added,
containing random or implementation-specific data.
For inbound tunnel builds, there must always be one "fake" record for the
originating router, with the correct 16-byte hash prefix
and a real X25519 ephemeral key, otherwise
the closest hop will know that the next hop is the originator.

The remainder of the "fake" record may be random data, or may encrypted in any format
for the originator to send data to itself about the build,
perhaps to reduce storage requirements for pending builds.

Originators of inbound tunnels must use some method to validate
that their "fake" record has not been modified by the previous hop,
as this may also be used for deanonimization.
The orignator may store and verify a checksum of the record,
or include the checksum in the record,
or use an AEAD encryption/decryption function, implementation-dependent.
If the 16-byte hash prefix or other build record contents were
modified, the router must discard the tunnel.

Fake records for outbound tunnels, and additional fake records for
inbound tunnels, do not have these requirements, and may
be completely random data, as they will never be visible
to any hop. It may still be desirable for the originator
to validate that they have not been modified.


Tunnel Bandwidth Parameters
===========================

Overview
--------

As we have increased the performance of the network over the last several years
with new protocols, encryption types, and congestion control improvements,
faster applications such as video streaming are becoming possible.
These applications require high bandwidth at each hop in their client tunnels.

Participating routers, however, do not have any information about how much
bandwidth a tunnel will use when they get a tunnel build message.
They can only accept or reject a tunnel based on the current total bandwidth
used by all participating tunnels and the total bandwidth limit for participating tunnels.

Requesting routers also do not have any information on how much bandwidth
is available at each hop.

Also, routers currently have no way to limit inbound traffic on a tunnel.
This would be quite useful during times of overload or DDoS of a service.

Tunnel bandwidth parameters in the tunnel build request and reply messages
add support for these features. See [Prop168]_ for additional background.
These parameters are defined as of API 0.9.65, but support may vary by implementation.
They are supported for both long and short ECIES build records.

Build Request Options
---------------------------

The following three options may be set in the tunnel build options mapping field of the record:
A requesting router may include any, all, or none.

- m := minimum bandwidth required for this tunnel (KBps positive integer as a string)
- r := requested bandwidth for this tunnel (KBps positive integer as a string)
- l := limit bandwidth for this tunnel; only sent to IBGW (KBps positive integer as a string)

Constraint: m <= r <= l

The participating router should reject the tunnel if "m" is specified and it cannot
provide at least that much bandwidth.

Request options are sent to each participant in the corresponding encrypted build request record,
and are not visible to other participants.


Build Reply Option
---------------------------

The following option may be set in the tunnel build reply options mapping field of the record,
when the response is ACCEPTED:

- b := bandwidth available for this tunnel (KBps positive integer as a string)

Constraint: b >= m

The participating router should include this if either "m" or "r" was specified
in the build request. The value should be at least that of the "m" value if specified,
but may be less or more than the "r" value if specified.

The participating router should attempt to reserve and provide at least this
much bandwidth for the tunnel, however this is not guaranteed.
Routers cannot predict conditions 10 minutes into the future, and
participating traffic is lower-priority than a router's own traffic and tunnels.

Routers may also over-allocate available bandwidth if necessary, and this is
probably desirable, as other hops in the tunnel could reject it.

For these reasons, the participating router's reply should be treated
as a best-effort commitment, but not a guarantee.

Reply options are sent to the requesting router in the corresponding encrypted build reply record,
and are not visible to other participants.


Implementation Notes
---------------------

Bandwidth parameters are as seen at the participating routers at the tunnel layer,
i.e. the number of fixed-size 1 KB tunnel messages per second.
Transport (NTCP2 or SSU2) overhead is not included.

This bandwidth may be much more or less than the bandwidth seen at the client.
Tunnel messages contain substantial overhead, including overhead from higher layers
including ratchet and streaming. Intermittent small messages such as streaming acks
will be expanded to 1 KB each.
However, gzip compression at the I2CP layer may substantially reduce bandwidth.

The simplest implementation at the requesting router is to use
the average, minimum, and/or maximum bandwidths of current tunnels in the pool
to calculate the values to put in the request.
More complex algorithms are possible and are up to the implementer.

There are no current I2CP or SAM options defined for the client to tell the
router what bandwidth is required, and no new options are proposed here.
Options may be defined at a later date if necessary.

Implementations may use available bandwidth or any other data, algorithm, local policy,
or local configuration to calculate the bandwidth value returned in the
build response.



References
==========

.. [Common]
    {{ spec_url('common-structures') }}

.. [Cryptography]
   {{ spec_url('cryptography') }}

.. [ECIES-ROUTERS]
   {{ spec_url('ecies-routers') }}

.. [ECIES-X25519]
   {{ spec_url('ecies') }}

.. [EncryptedLeaseSet]
   {{ site_url('docs/spec/encryptedleaseset') }}

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

.. [Prop152]
    {{ proposal_url('152') }}

.. [Prop153]
    {{ proposal_url('153') }}

.. [Prop156]
    {{ proposal_url('156') }}

.. [Prop157]
    {{ proposal_url('157') }}

.. [Prop168]
    {{ proposal_url('168') }}

.. [Tunnel-Creation]
   {{ spec_url('tunnel-creation') }}

.. [Multiple-Encryption]
   https://en.wikipedia.org/wiki/Multiple_encryption

.. [RFC-7539]
   https://tools.ietf.org/html/rfc7539

.. [RFC-7748]
   https://tools.ietf.org/html/rfc7748



