======
SSU2
======
.. meta::
    :category: Transports
    :lastupdated: 2025-04
    :accuratefor: 0.9.65

.. contents::



Status
========

Substantially complete. See [Prop159]_ for additional background and goals,
including security analysis, threat models, a review of SSU 1 security and issues,
and excerpts of the QUIC specifications.

Rollout plan:


==========================      =====================  ====================
    Feature                     Testing (not default)  Enabled by default
==========================      =====================  ====================
Local test code                         2022-02
Joint test code                         2022-03
Joint test in-net               0.9.54  2022-05
Freeze basic protocol           0.9.54  2022-05
Basic Session                   0.9.55  2022-08        0.9.56  2022-11
Address Validation (Retry)      0.9.55  2022-08        0.9.56  2022-11
Fragmented RI in handshake      0.9.55  2022-08        0.9.56  2022-11
New Token                       0.9.55  2022-08        0.9.57  2022-11
Freeze extended protocol        0.9.55  2022-08
Relay                           0.9.55  2022-08        0.9.56  2022-11
Peer Test                       0.9.55  2022-08        0.9.56  2022-11
Enable for random 2%            0.9.55  2022-08
Path Validation                 0.9.55+ dev            0.9.56  2022-11
Connection Migration            0.9.55+ dev            0.9.56  2022-11
Immediate ACK flag              0.9.55+ dev            0.9.56  2022-11
Key Rotation                    0.9.57  2023-02        0.9.58  2023-05
Disable SSU 1 (i2pd)            0.9.56  2022-11
Disable SSU 1 (Java I2P)        0.9.58  2023-05        0.9.61  2023-12
==========================      =====================  ====================

Basic Session includes the handshake and data phase.
Extended protocol includes relay and peer test.



Overview
========

This specification defines an authenticated key agreement protocol to improve the
resistance of [SSU]_ to various forms of automated identification and attacks.

As with other I2P transports, SSU2 is defined
for point-to-point (router-to-router) transport of I2NP messages.
It is not a general-purpose data pipe.
Like [SSU]_, it also provides two additional services:
Relaying for NAT traversal, and Peer Testing for determination of inbound reachability.
It also provides a third service, not in SSU, for connection migration
when a peer changes IP or port.



Design Overview
====================

Summary
--------

We rely on several existing protocols, both within I2P and outside standards,
for inspiration, guidance, and code reuse:

* Threat models: From NTCP2 [NTCP2]_, with significant additional threats
  relevant to UDP transport as analyzed by QUIC [RFC-9000]_ [RFC-9001]_.

* Cryptographic choices: From [NTCP2]_.

* Handshake: Noise XK from [NTCP2]_ and [NOISE]_. Significant simplifications
  to NTCP2 are possible due to the encapsulation (inherent message boundaries)
  provided by UDP.

* Handshake ephemeral key obfuscation: Adapted from [NTCP2]_
  but using ChaCha20 from [ECIES]_ instead of AES.

* Packet headers: Adapted from WireGuard [WireGuard]_ and QUIC [RFC-9000]_ [RFC-9001]_.

* Packet header obfuscation: Adapted from [NTCP2]_
  but using ChaCha20 from [ECIES]_ instead of AES.

* Packet header protection: Adapted from QUIC [RFC-9001]_ and [Nonces]_

* Headers used as AEAD associated data as in [ECIES]_.

* Packet numbering: Adapted from WireGuard [WireGuard]_ and QUIC [RFC-9000]_ [RFC-9001]_.

* Messages: Adapted from [SSU]_

* I2NP Fragmentation: Adapted from [SSU]_

* Relay and Peer Testing: Adapted from [SSU]_

* Signatures of Relay and Peer Test data: From the common structures spec [Common]_

* Block format: From [NTCP2]_ and [ECIES]_.

* Padding and options: From [NTCP2]_ and [ECIES]_.

* Acks, nacks: Adapted from QUIC [RFC-9000]_.

* Flow control: TBD


There are no new cryptographic primitives that have not been used in I2P before.



Delivery Guarantees
----------------------

As with other I2P transports NTCP, NTCP2, and SSU 1, this transport is not a general-purpose
facility for delivery of an in-order stream of bytes. It is designed for
transport of I2NP messages. There is no "stream" abstraction provided.

In addition, as for SSU, it contains additional facilities for peer-facilitated NAT traversal
and testing of reachability (inbound connections).

As for SSU 1, it does NOT provide in-order delivery of I2NP messages.
Nor does it provide guaranteed delivery of I2NP messages.
For efficiency, or because of out-of order delivery of UDP datagrams
or loss of those datagrams, I2NP messages may be delivered to the
far-end out-of-order, or may not be delivered at all.
An I2NP message may be retransmitted multiple times if necessary,
but delivery may eventually fail without causing the full connection to be
disconnected. Also, new I2NP messages may continue to be sent even
while retransmission (loss recovery) is occurring for other I2NP messages.

This protocol does NOT completely prevent duplicate delivery of I2NP messages.
The router should enforce I2NP expiration and use a Bloom filter or other
mechanism based on the I2NP message ID.
See the I2NP Message Duplication section below.


Noise Protocol Framework
-------------------------

This specification provides the requirements based on the Noise Protocol Framework
[NOISE]_ (Revision 33, 2017-10-04).
Noise has similar properties to the Station-To-Station protocol
[STS]_, which is the basis for the [SSU]_ protocol.  In Noise parlance, Alice
is the initiator, and Bob is the responder.

SSU2 is based on the Noise protocol Noise_XK_25519_ChaChaPoly_SHA256.
(The actual identifier for the initial key derivation function
is "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"
to indicate I2P extensions - see KDF 1 section below)

NOTE: This identifier is different than that used for NTCP2, because 
all three handshake messages use the header as associated data.

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
-------------------------------

This specification defines the following enhancements to
Noise_XK_25519_ChaChaPoly_SHA256.  These generally follow the guidelines in
[NOISE]_ section 13.

1) Handshake messages (Session Request, Created, Confirmed) include
   a 16 or 32 byte header.

2) The headers for the handshake messages (Session Request, Created, Confirmed)
   are used as input to mixHash() before encryption/decryption
   to bind the headers to the message.

3) Headers are encrypted and protected.

4) Cleartext ephemeral keys are obfuscated with ChaCha20 encryption using a known
   key and IV.  This is quicker than elligator2.

5) The payload format is defined for messages 1, 2, and the data phase.
   Of course, this is not defined in Noise.

The data phase uses encryption similar to, but not compatible with, the Noise data phase.



Definitions
===============

We define the following functions corresponding to the cryptographic building blocks used.

ZEROLEN
    zero-length byte array

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




Messages
========

Each UDP datagram contains exactly one message.
The length of the datagram (after the IP and UDP headers) is the length of the message.
Padding, if any, is contained in a padding block inside the message.
In this document, we use the terms "datagram" and "packet" mostly interchangeably.
Each datagram (or packet) contains a single message (unlike QUIC, where
a datagram may contain multiple QUIC packets).
The "packet header" is the part after the IP/UDP header.

Exception:
The Session Confirmed message is unique in that it may be fragmented across multiple packets.
See the Session Confirmed Fragmentation section below for more information.

All SSU2 messages are at least 40 bytes in length.
Any message of length 1-39 bytes is invalid.
All SSU2 messages are less than or equal to 1472 (IPv4) or 1452 (IPv6) bytes in length. The message
format is based on Noise messages, with modifications for framing and indistinguishability.
Implementations using standard Noise libraries must pre-process received
messages to the standard Noise message format. All encrypted fields are AEAD
ciphertexts.


The following messages are defined:

====  ================  =============  =============
Type      Message       Header Length  Header Encr. Length
====  ================  =============  =============
  0   SessionRequest    32             64
  1   SessionCreated    32             64
  2   SessionConfirmed  16             16
  6   Data              16             16
  7   PeerTest          32             32
  9   Retry             32             32
 10   Token Request     32             32
 11   HolePunch         32             32
====  ================  =============  =============



Session Establishment
-----------------------

The standard establishment sequence, when Alice has a valid token previously received from Bob, is as follows:

.. raw:: html

  {% highlight %}
Alice                           Bob

  SessionRequest ------------------->
  <------------------- SessionCreated
  SessionConfirmed ----------------->
{% endhighlight %}


When Alice does not have a valid token, the establishment sequence is as follows:

.. raw:: html

  {% highlight %}
Alice                           Bob

  TokenRequest --------------------->
  <---------------------------  Retry
  SessionRequest ------------------->
  <------------------- SessionCreated
  SessionConfirmed ----------------->
{% endhighlight %}


When Alice thinks she has a valid token,
but Bob rejects it (perhaps because Bob restarted),
the establishment sequence is as follows:

.. raw:: html

  {% highlight %}
Alice                           Bob

  SessionRequest ------------------->
  <---------------------------  Retry
  SessionRequest ------------------->
  <------------------- SessionCreated
  SessionConfirmed ----------------->
{% endhighlight %}


Bob may reject a Session or Token Request by replying with a Retry message
containing a Termination block with a reason code.
Based on the reason code, Alice should not attempt another
request for some period of time:


.. raw:: html

  {% highlight %}
Alice                           Bob

  SessionRequest ------------------->
  <---------------------------  Retry containing a Termination block

  or

  TokenRequest --------------------->
  <---------------------------  Retry containing a Termination block
{% endhighlight %}


Using Noise terminology, the establishment and data sequence is as follows:
(Payload Security Properties)

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


Packet Header
---------------

All packets start with an obfuscated (encrypted) header.
There are two header types, long and short.
Note that the first 13 bytes (Destination Connection ID, packet number, and type)
are the same for all headers.

Long Header
`````````````
The long header is 32 bytes. It is used before a session is created, for Token Request, SessionRequest, SessionCreated, and Retry.
It is also used for out-of-session Peer Test and Hole Punch messages.

Before header encryption:

.. raw:: html

  {% highlight lang='dataspec' %}

+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+

  Destination Connection ID :: 8 bytes, unsigned big endian integer

  Packet Number :: 4 bytes, unsigned big endian integer

  type :: The message type = 0, 1, 7, 9, 10, or 11

  ver :: The protocol version, equal to 2

  id :: 1 byte, the network ID (currently 2, except for test networks)

  flag :: 1 byte, unused, set to 0 for future compatibility

  Source Connection ID :: 8 bytes, unsigned big endian integer

  Token :: 8 bytes, unsigned big endian integer

{% endhighlight %}


Short Header
`````````````
The short header is 16 bytes. It is used for Session Created and for Data messages.
Unauthenticated messages such as Session Request, Retry, and Peer Test will
always use the long header.

16 bytes is required, because
the receiver must decrypt the first 16 bytes to get the message type,
and then must decrypt an additional 16 bytes if it's actually a long header,
as indicated by the message type.

For Session Confirmed, before header encryption:

.. raw:: html

  {% highlight lang='dataspec' %}

+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type|frag|  flags  |
  +----+----+----+----+----+----+----+----+

  Destination Connection ID :: 8 bytes, unsigned big endian integer

  Packet Number :: 4 bytes, all zeros

  type :: The message type = 2

  frag :: 1 byte fragment info:
         bit order: 76543210 (bit 7 is MSB)
         bits 7-4: fragment number 0-14, big endian
         bits 3-0: total fragments 1-15, big endian

  flags :: 2 bytes, unused, set to 0 for future compatibility

{% endhighlight %}

See the Session Confirmed Fragmentation section below for more information
about the frag field.


For Data messages, before header encryption:

.. raw:: html

  {% highlight lang='dataspec' %}

+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type|flag|moreflags|
  +----+----+----+----+----+----+----+----+

  Destination Connection ID :: 8 bytes, unsigned big endian integer

  Packet Number :: 4 bytes, unsigned big endian integer

  type :: The message type = 6

  flag :: 1 byte flags:
         bit order: 76543210 (bit 7 is MSB)
         bits 7-1: unused, set to 0 for future compatibility
         bits 0: when set to 1, immediate ack requested

  moreflags :: 2 bytes, unused, set to 0 for future compatibility

{% endhighlight %}



Connection ID Numbering
```````````````````````````

Connection IDs must be randomly generated.
Source and Destination IDs must NOT be identical,
so that an on-path attacker cannot capture and send a packet
back to the originator that looks valid.
Do NOT use a counter to generate connection IDs, so that an on-path
attacker cannot generate a packet that looks valid.

Unlike in QUIC, we do not change the connection IDs during or after the handshake,
even after a Retry message. The IDs remain constant from the first message
(Token Request or Session Request) to the last message (Data with Termination).
Additionally, connection IDs do not change during or after
path challenge or connection migration.

Also different than QUIC is that connection IDs in the headers
are always header-encrypted. See below.



Packet Numbering
`````````````````
If no First Packet Number block is sent in the handshake,
packets are numbered within a single session, for each direction, starting from 0, to a max of (2**32 -1).
A session must be terminated, and a new session created, well before the max
number of packets is sent.

If a First Packet Number block is sent in the handshake,
packets are numbered within a single session, for that direction, starting from that packet number.
The packet number may wrap around during the session.
When a max of 2**32 packets have been sent, wrapping the packet number back
to the first packet number, that session is no longer valid.
A session must be terminated, and a new session created, well before the max
number of packets is sent.


TODO key rotation, reduce max packet number?


Handshake packets that are determined to be lost are retransmitted
whole, with the identical header including packet number.
The handshake messages Session Request, Session Created, and Session Confirmed
MUST be retransmitted with the same packet number and identical encrypted contents,
so that the same chained hash will be used to encrypt the response.
The Retry message is never transmitted.

Data phase packets that are determined to be lost are never retransmitted
whole (except termination, see below).  The same applies to the blocks that are contained within lost
packets.  Instead, the information that might be carried in blocks is
sent again in new packets as needed.
Data Packets are never retransmitted with the same packet number.
Any retransmission of packet contents (whether or not the contents remain the same)
must use the next unused packet number.

Retransmitting an unchanged whole packet as-is, with the same packet number,
is not allowed for several reasons. For background see QUIC [RFC-9000]_ section 12.3.

- It's inefficient to store packets for retransmission
- A new packet data looks different to an on-path observer, can't tell it's retransmitted
- A new packet gets an updated ack block sent with it, not the old ack block
- You only retransmit what's necessary. some fragments could have been already retransmitted once and been acked
- You can fit as much as you need into each retransmitted packet if more is pending
- Endpoints that track all individual packets for the purposes of
  detecting duplicates are at risk of accumulating excessive state.
  The data required for detecting duplicates can be limited by
  maintaining a minimum packet number below which all packets are
  immediately dropped.
- This scheme is much more flexible


New packets are used to carry information that is
determined to have been lost.  In general, information is sent again
when a packet containing that information is determined to be lost,
and sending ceases when a packet containing that information is remain the same)
acknowledged.

Exception: A data phase packet containing a Termination block may,
but is not required to be, retransmitted whole, as-is.
See the Session Termination section below.


The following packets contain a random packet number that is ignored:

- Session Request
- Session Created
- Token Request
- Retry
- Peer Test
- Hole Punch

For Alice, outbound packet numbering starts at 0 with Session Confirmed.
For Bob, outbound packet numbering starts at 0 with first Data packet,
which should be an ACK of the Session Confirmed.
The packet numbers
in an example standard handshake will be:

.. raw:: html

  {% highlight %}
Alice                           Bob

  SessionRequest (r)    ------------>
  <-------------   SessionCreated (r)
  SessionConfirmed (0)  ------------>
  <-------------             Data (0) (Ack-only)
  Data (1)              ------------> (May be sent before Ack is received)
  <-------------             Data (1)
  Data (2)              ------------>
  Data (3)              ------------>
  Data (4)              ------------>
  <-------------             Data (2)

  r = random packet number (ignored)
  Token Request, Retry, and Peer Test
  also have random packet numbers.
{% endhighlight %}


Any retransmission of handshake messages
(SessionRequest, SessionCreated, or SessionConfirmed)
must be resent unchanged, with the same packet number.
Do not use different ephemeral keys or change the payload
when retransmitting these messages.


Header Binding
````````````````
The header (before obfuscation and protection) is always included in the associated
data for the AEAD function, to cryptographically bind the header to the data.


Header Encryption
```````````````````

Header encryption has several goals.
See the "Additional DPI Discussion" section above for background and assumptions.

- Prevent online DPI from identifying the protocol
- Prevent patterns in a series of messages in the same connection,
  except for handshake retransmissions
- Prevent patterns in messages of the same type in different connections
- Prevent decryption of handshake headers
  without knowledge of the introduction key found in the netdb
- Prevent identification of X25519 ephemeral keys
  without knowledge of the introduction key found in the netdb
- Prevent decryption of data phase packet number and type
  by any online or offline attacker
- Prevent injection of valid handshake packets by an on-path or off-path observer
  without knowledge of the introduction key found in the netdb
- Prevent injection of valid data packets by an on-path or off-path observer
- Allow rapid and efficient classification of incoming packets
- Provide "probing" resistance so that there is no response to a bad
  Session Request, or if there is a Retry response,
  the response is not identifiable as I2P
  without knowledge of the introduction key found in the netdb
- The Destination Connection ID is not critical data,
  and it's ok if it can be decrypted by an observer
  with knowledge of the introduction key found in the netdb
- The packet number of a data phase packet is an AEAD nonce and is critical data.
  It must not be decryptable by an observer even
  with knowledge of the introduction key found in the netdb.
  See [Nonces]_.

Headers are encrypted with known keys published in the network database
or calculated later.
In the handshake phase, this is for DPI resistance only, as the key is public and the
key and nonces are reused, so it is effectively just obfuscation.
Note that the header encryption is also used to obfuscate
the ephemeral keys X (in Session Request) and Y (in Session Created).

See the Inbound Packet Handling section below for additional guidance.

Bytes 0-15 of all headers
are encrypted using a header protection scheme by XORing with data calculated from known keys,
using ChaCha20, similar to QUIC [RFC-9001]_ and [Nonces]_.
This ensures that the encrypted short header and the first part of the long header
will appear to be random.

For Session Request and Session Created, bytes 16-31 of the long header and the 32-byte Noise ephemeral key
are encrypted using ChaCha20.
The unencrypted data is random, so the encrypted data will appear to be random.

For Retry, bytes 16-31 of the long header
are encrypted using ChaCha20.
The unencrypted data is random, so the encrypted data will appear to be random.

Unlike the QUIC [RFC-9001]_ header protection scheme,
ALL parts of all headers, including destination and source connection IDs,
are encrypted.
QUIC [RFC-9001]_ and [Nonces]_ are primarily focused on encrypting
the "critical" part of the header, i.e. the packet number (ChaCha20 nonce).
While encrypting the session ID makes incoming packet classification a little more complex,
it makes some attacks more difficult. QUIC defines different connection IDs
for different phases, and for path challenge and connection migration.
Here we use the same connection IDs throughout, as they are encrypted.

There are seven header protection key phases:

- Session Request and Token Request
- Session Created
- Retry
- Session Confirmed
- Data Phase
- Peer Test
- Hole Punch


=================  ===================  ====================
    Message          Key k_header_1       Key k_header_2
=================  ===================  ====================
Token Request      Bob Intro Key        Bob Intro Key
Session Request    Bob Intro Key        Bob Intro Key
Session Created    Bob Intro Key        See Session Request KDF
Session Confirmed  Bob Intro Key        See Session Created KDF
Retry              Bob Intro Key        Bob Intro Key
Data               Alice/Bob Intro Key  See data phase KDF
Peer Test 5,7      Alice Intro Key      Alice Intro Key
Peer Test 6        Charlie Intro Key    Charlie Intro Key
Hole Punch         Alice Intro Key      Alice Intro Key
=================  ===================  ====================



Header encryption is designed to allow rapid classification of
inbound packets, without complex heuristics or fallbacks.
This is accomplished by using the same k_header_1 key
for almost all inbound messages.
Even when the source IP or port of a connection changes
due to an actual IP change or NAT behavior, the packet may be
rapidly mapped to a session with a single lookup of the connection ID.

Note that Session Created and Retry are the ONLY messages that require fallback processing
for k_header_1 to decrypt the Connection ID, because they use the sender's (Bob's) intro key.
ALL other messages use the receiver's intro key for k_header_1.
The fallback processing need only look up pending outbound connections by
source IP/port.

If the fallback processing by source IP/port fails to find a pending
outbound connection, there could be several causes:

- Not an SSU2 message
- A corrupted SSU2 message
- The reply is spoofed or modified by an attacker
- Bob has a symmetric NAT
- Bob changed IP or port during processing of the message
- Bob sent the reply out a different interface

While additional fallback processing is possible to attempt to find
the pending outbound connection and decrypt the connection ID
using the k_header_1 for that connection, it is probably not necessary.
If Bob has issues with his NAT or packet routing, it is probably
better to let the connection fail.
This design relies on endpoints retaining a stable address for the duration of the handshake.

See the Inbound Packet Handling sesion below for additional guidelines.

See the individual KDF sections below for the derivation of the header encryption keys for that phase.



Header Encryption KDF
````````````````````````

.. raw:: html

  {% highlight lang='dataspec' %}
// incoming encrypted packet
  packet = incoming encrypted packet
  len = packet.length

  // take the next-to-last 12 bytes of the packet
  iv = packet[len-24:len-13]
  k_header_1 = header encryption key 1
  data = {0, 0, 0, 0, 0, 0, 0, 0}
  mask = ChaCha20.encrypt(k_header_1, iv, data)

  // encrypt the first part of the header by XORing with the mask
  packet[0:7] ^= mask[0:7]

  // take the last 12 bytes of the packet
  iv = packet[len-12:len-1]
  k_header_2 = header encryption key 2
  data = {0, 0, 0, 0, 0, 0, 0, 0}
  mask = ChaCha20.encrypt(k_header_2, iv, data)

  // encrypt the second part of the header by XORing with the mask
  packet[8:15] ^= mask[0:7]


  // For Session Request and Session Created only:
  iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

  // encrypt the third part of the header and the ephemeral key
  packet[16:63] = ChaCha20.encrypt(k_header_2, iv, packet[16:63])


  // For Retry, Token Request, Peer Test, and Hole Punch only:
  iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

  // encrypt the third part of the header
  packet[16:31] = ChaCha20.encrypt(k_header_2, iv, packet[16:31])


{% endhighlight %}

This KDF uses the last 24 bytes of the packet as the IV for the two
ChaCha20 operations. As all packets end with a 16 byte MAC,
this requires that all packet payloads are a minimum of 8 bytes.
This requirement is additionally documented in the message sections below.



Header Validation
```````````````````
After decrypting the first 8 bytes of the header,
the receiver will know the Destination Connection ID. From there,
the receiver knows what header encryption key to use for
the remainder of the header, based on the key phase of the session.

Decrypting the next 8 bytes of the header will then reveal the message type and be able to determine
if it is a short or long header.
If it is a long header, the receiver must validate the version and netid fields.
If the version is != 2, or the netid is != the expected value (generally 2, except in test networks),
the receiver should drop the message.


Packet Integrity
------------------------

All message contain either three or four parts:

- The message header
- For Session Request and Session Created only, an ephemeral key
- A ChaCha20-encrypted payload
- A Poly1305 MAC

In all cases, the header (and if present, the ephemeral key) is bound
to the authentication MAC to ensure that the entire message is intact.

- For handshake messages Session Request, Session Created, and Session Confirmed,
  the message header is mixHash()ed before the Noise processing phase
- The ephemeral key, if present, is covered by a standard Noise misHash()
- For messages outside the Noise handshake, the header is used
  as Associated Data for the ChaCha20/Poly1305 encryption.

Inbound packet handlers must always decrypt the ChaCha20 payload and validate
the MAC before processing the message, with one exception:
To mitigate DoS attacks from address-spoofed packets containing
apparent Session Request messages with an invalid token, a handler need NOT
attempt to decrypt and validate the full message
(requiring an expensive DH operation in addition to the ChaCha2o/Poly1305 decryption).
The handler may respond with a Retry message using the values found in the header
of the Session Request message.


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
        The packet header, 16 bytes.

  data :: Plaintext data, 0 or more bytes

{% endhighlight %}

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

For ChaCha20, what is described here corresponds to [RFC-7539]_, which is also
used similarly in TLS [RFC-7905]_.

Notes
`````
- Since ChaCha20 is a stream cipher, plaintexts need not be padded.
  Additional keystream bytes are discarded.

- The key for the cipher (256 bits) is agreed upon by means of the SHA256 KDF.
  The details of the KDF for each message are in separate sections below.


AEAD Error Handling
```````````````````
- In all messages, the AEAD message size is known in advance.
  On an AEAD authentication failure, recipient must halt further message processing and
  discard the message.

- Bob should maintain a blacklist of IPs with
  repeated failures.


KDF for Session Request
-------------------------------------------------------

The Key Derivation Function (KDF) generates a handshake phase cipher key k from the DH result,
using HMAC-SHA256(key, data) as defined in [RFC-2104]_.
These are the InitializeSymmetric(), MixHash(), and MixKey() functions,
exactly as defined in the Noise spec.

KDF for Initial ChainKey
````````````````````````

.. raw:: html

  {% highlight lang='text' %}

// Define protocol_name.
  Set protocol_name = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"
   (52 bytes, US-ASCII encoded, no NULL termination).

  // Define Hash h = 32 bytes
  h = SHA256(protocol_name);

  Define ck = 32 byte chaining key. Copy the h data to ck.
  Set ck = h

  // MixHash(null prologue)
  h = SHA256(h);

  // up until here, can all be precalculated by Alice for all outgoing connections

  // Bob's X25519 static keys
  // bpk is published in routerinfo
  bsk = GENERATE_PRIVATE()
  bpk = DERIVE_PUBLIC(bsk)

  // Bob static key
  // MixHash(bpk)
  // || below means append
  h = SHA256(h || bpk);

  // Bob introduction key
  // bik is published in routerinfo
  bik = RANDOM(32)

  // up until here, can all be precalculated by Bob for all incoming connections

{% endhighlight %}


KDF for Session Request
`````````````````````````

.. raw:: html

  {% highlight lang='text' %}

// MixHash(header)
  h = SHA256(h || header)

  This is the "e" message pattern:

  // Alice's X25519 ephemeral keys
  aesk = GENERATE_PRIVATE()
  aepk = DERIVE_PUBLIC(aesk)

  // Alice ephemeral key X
  // MixHash(aepk)
  h = SHA256(h || aepk);

  // h is used as the associated data for the AEAD in Session Request
  // Retain the Hash h for the Session Created KDF


  End of "e" message pattern.

  This is the "es" message pattern:

  // DH(e, rs) == DH(s, re)
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
  ciphertext = ENCRYPT(k, n, payload, ad)

  // retain the chainKey for Session Created KDF


  End of "es" message pattern.

  // Header encryption keys for this message
  // bik = Bob's intro key
  k_header_1 = bik
  k_header_2 = bik

  // Header encryption keys for next message (Session Created)
  k_header_1 = bik
  k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)

  // Header encryption keys for next message (Retry)
  k_header_1 = bik
  k_header_2 = bik


{% endhighlight %}




SessionRequest (Type 0)
------------------------

Alice sends to Bob, either as the first message in the handshake,
or in response to a Retry message.
Bob responds with a Session Created message.
Size: 80 + payload size.
Minimum Size: 88

If Alice does not have a valid token, Alice should send a Token Request  message
instead of a Session Request, to avoid the asymmetric encryption
overhead in generating a Session Request.

Long header.
Noise content: Alice's ephemeral key X
Noise payload: DateTime and other blocks
Max payload size: MTU - 108 (IPv4) or MTU - 128 (IPv6).
For 1280 MTU: Max payload is 1172 (IPv4) or 1152 (IPv6).
For 1500 MTU: Max payload is 1392 (IPv4) or 1372 (IPv6).

Payload Security Properties:

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
We use ChaCha20 encryption to achieve this,
rather than more complex and slower alternatives such as elligator2.
Asymmetric encryption to Bob's router public key would be far too slow.
ChaCha20 encryption uses Bob's intro key as published
in the network database.

ChaCha20 encryption is for DPI resistance only.
Any party knowing Bob's introduction key, which is published in the network database,
may decrypt the header and X value in this message.


Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Long Header bytes 0-15, ChaCha20     |
  +  encrypted with Bob intro key         +
  |    See Header Encryption KDF          |
  +----+----+----+----+----+----+----+----+
  |  Long Header bytes 16-31, ChaCha20    |
  +  encrypted with Bob intro key n=0     +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +       X, ChaCha20 encrypted           +
  |       with Bob intro key n=0          |
  +              (32 bytes)               +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   ChaCha20 encrypted data             |
  +          (length varies)              +
  |  k defined in KDF for Session Request |
  +  n = 0                                +
  |  see KDF for associated data          |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+

  X :: 32 bytes, ChaCha20 encrypted X25519 ephemeral key, little endian
          key: Bob's intro key
          n: 1
          data: 48 bytes (bytes 16-31 of the header, followed by encrypted X)

{% endhighlight %}

Unencrypted data (Poly1305 authentication tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |                   X                   |
  +              (32 bytes)               +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |     Noise payload (block data)        |
  +          (length varies)              +
  |     see below for allowed blocks      |
  +----+----+----+----+----+----+----+----+


  Destination Connection ID :: Randomly generated by Alice

  id :: 1 byte, the network ID (currently 2, except for test networks)

  ver :: 2

  type :: 0

  flag :: 1 byte, unused, set to 0 for future compatibility

  Packet Number :: Random 4 byte number generated by Alice, ignored

  Source Connection ID :: Randomly generated by Alice,
                          must not be equal to Destination Connection ID

  Token :: 0 if not previously received from Bob

  X :: 32 bytes, X25519 ephemeral key, little endian

{% endhighlight %}


Payload
```````

- DateTime block
- Options block (optional)
- Relay Tag Request block (optional)
- Padding block (optional)

The minimum payload size is 8 bytes. Since the DateTime block is
only 7 bytes, at least one other block must be present.


Notes
`````
- The unique X value in the initial ChaCha20 block ensure that the ciphertext is
  different for every session.

- To provide probing resistance, Bob should not send a Retry message
  in response to a Session Request message unless the
  message type, protocol version, and network ID fields in the Session Request message
  are valid.

- Bob must reject connections where the timestamp value is too far off from the
  current time. Call the maximum delta time "D".  Bob must maintain a local
  cache of previously-used handshake values and reject duplicates, to prevent
  replay attacks. Values in the cache must have a lifetime of at least 2*D.
  The cache values are implementation-dependent, however the 32-byte X value
  (or its encrypted equivalent) may be used.
  Reject by sending a Retry message containing a zero token and a termination block.

- Diffie-Hellman ephemeral keys may never be reused, to prevent cryptographic attacks,
  and reuse will be rejected as a replay attack.

- The "KE" and "auth" options must be compatible, i.e. the shared secret K must
  be of the appropriate size. If more "auth" options are added, this could
  implicitly change the meaning of the "KE" flag to use a different KDF or a
  different truncation size.

- Bob must validate that Alice's ephemeral key is a valid point on the curve
  here.

- Padding should be limited to a reasonable amount.  Bob may reject connections
  with excessive padding.  Bob will specify his padding options in Session Created.
  Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
  (Distribution to be determined, see Appendix A.)

- On most errors, including AEAD, DH, apparent replay, or key
  validation failure, Bob should halt further message processing and
  drop the message without responding.

- Bob MAY send a Retry message containing a zero token and a Termination block with a
  clock skew reason code if the timestamp in the DateTime block is too
  far skewed.

- DoS Mitigation: DH is a relatively expensive operation. As with the previous NTCP protocol,
  routers should take all necessary measures to prevent CPU or connection exhaustion.
  Place limits on maximum active connections and maximum connection setups in progress.
  Enforce read timeouts (both per-read and total for "slowloris").
  Limit repeated or simultaneous connections from the same source.
  Maintain blacklists for sources that repeatedly fail.
  Do not respond to AEAD failure. Alternatively, respond with a Retry message
  before the DH operation and AEAD validation.

- "ver" field: The overall Noise protocol, extensions, and SSU2 protocol
  including payload specifications, indicating SSU2.
  This field may be used to indicate support for future changes.

- The network ID field is used to quickly identify cross-network connections.
  If this field is does not match Bob's network ID,
  Bob should disconnect and block future connections.

- Bob must drop the message if the Source Connection ID equals
  the Destination Connection ID.



KDF for Session Created and Session Confirmed part 1
----------------------------------------------------------------------------------

.. raw:: html

  {% highlight lang='text' %}

// take h saved from Session Request KDF
  // MixHash(ciphertext)
  h = SHA256(h || encrypted Noise payload from Session Request)

  // MixHash(header)
  h = SHA256(h || header)

  This is the "e" message pattern:

  // Bob's X25519 ephemeral keys
  besk = GENERATE_PRIVATE()
  bepk = DERIVE_PUBLIC(besk)

  // h is from KDF for Session Request
  // Bob ephemeral key Y
  // MixHash(bepk)
  h = SHA256(h || bepk);

  // h is used as the associated data for the AEAD in Session Created
  // Retain the Hash h for the Session Confirmed KDF

  End of "e" message pattern.

  This is the "ee" message pattern:

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  sharedSecret = DH(aesk, bepk) = DH(besk, aepk)
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  ad = h
  ciphertext = ENCRYPT(k, n, payload, ad)

  // retain the chaining key ck for Session Confirmed KDF

  End of "ee" message pattern.

  // Header encryption keys for this message
  // bik = Bob's intro key
  k_header_1 = bik
  k_header_2: See Session Request KDF above

  // Header protection keys for next message (Session Confirmed)
  k_header_1 = bik
  k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)

{% endhighlight %}


SessionCreated (Type 1)
------------------------

Bob sends to Alice, in response to a Session Request message.
Alice responds with a Session Confirmed message.
Size: 80 + payload size.
Minimum Size: 88

Noise content: Bob's ephemeral key Y
Noise payload: DateTime, Address, and other blocks
Max payload size: MTU - 108 (IPv4) or MTU - 128 (IPv6).
For 1280 MTU: Max payload is 1172 (IPv4) or 1152 (IPv6).
For 1500 MTU: Max payload is 1392 (IPv4) or 1372 (IPv6).

Payload Security Properties:

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
which are necessary DPI countermeasures.  We use ChaCha20 encryption to achieve
this, rather than more complex and slower alternatives such as elligator2.
Asymmetric encryption to Alice's router public key would be far too slow.  ChaCha20
encryption uses Bob's intro key,
as published in the network database.

ChaCha20 encryption is for DPI resistance only.  Any party knowing Bob's intro key,
which is published in the network database, and captured the first 32
bytes of Session Request, may decrypt the Y value in this message.


Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Long Header bytes 0-15, ChaCha20     |
  +  encrypted with Bob intro key and     +
  | derived key, see Header Encryption KDF|
  +----+----+----+----+----+----+----+----+
  |  Long Header bytes 16-31, ChaCha20    |
  +  encrypted with derived key n=0       +
  |  See Header Encryption KDF            |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +       Y, ChaCha20 encrypted           +
  |       with derived key n=0            |
  +              (32 bytes)               +
  |       See Header Encryption KDF       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |   ChaCha20 data                       |
  +   Encrypted and authenticated data    +
  |  length varies                        |
  +  k defined in KDF for Session Created +
  |  n = 0; see KDF for associated data   |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+

  Y :: 32 bytes, ChaCha20 encrypted X25519 ephemeral key, little endian
          key: Bob's intro key
          n: 1
          data: 48 bytes (bytes 16-31 of the header, followed by encrypted Y)

{% endhighlight %}

Unencrypted data (Poly1305 auth tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |                  Y                    |
  +              (32 bytes)               +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |     Noise payload (block data)        |
  +          (length varies)              +
  |      see below for allowed blocks     |
  +----+----+----+----+----+----+----+----+

  Destination Connection ID :: The Source Connection ID
                               received from Alice in Session Request

  id :: 1 byte, the network ID (currently 2, except for test networks)

  ver :: 2

  type :: 0

  flag :: 1 byte, unused, set to 0 for future compatibility

  Packet Number :: Random 4 byte number generated by Bob, ignored

  Source Connection ID :: The Destination Connection ID
                          received from Alice in Session Request

  Token :: 0 (unused)

  Y :: 32 bytes, X25519 ephemeral key, little endian

{% endhighlight %}


Payload
```````
- DateTime block
- Address block
- Relay Tag block (optional)
- New Token block (not recommended, see note)
- First Packet Number block (optional)
- Options block (optional)
- Termination block (not recommended, send in a retry message instead)
- Padding block (optional)

The minimum payload size is 8 bytes. Since the DateTime and Address blocks
total more than that, the requirement is met with only those two blocks.

Notes
`````

- Alice must validate that Bob's ephemeral key is a valid point on the curve
  here.

- Padding should be limited to a reasonable amount.
  Alice may reject connections with excessive padding.
  Alice will specify her padding options in Session Confirmed.
  Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
  (Distribution to be determined, see Appendix A.)

- On any error, including AEAD, DH, timestamp, apparent replay, or key
  validation failure, Alice must halt further message processing and close the
  connection without responding.

- Alice must reject connections where the timestamp value is too far off from
  the current time. Call the maximum delta time "D".  Alice must maintain a
  local cache of previously-used handshake values and reject duplicates, to
  prevent replay attacks. Values in the cache must have a lifetime of at least
  2*D.  The cache values are implementation-dependent, however the 32-byte Y
  value (or its encrypted equivalent) may be used.

- Alice must drop the message if the source IP and port do not match
  the destination IP and port of the Session Request.

- Alice must drop the message if the Destination and Source Connection IDs
  do not match the Source and Destination Connection IDs of the Session Request.

- Bob sends a relay tag block if requested by Alice in the Session Request.

- New Token block is not recommended in Session Created, because Bob
  should do validation of the Session Confirmed first. See
  the Tokens section below.


Issues
``````
- Include min/max padding options here?



KDF for Session Confirmed part 1, using Session Created KDF
---------------------------------------------------------------------------

.. raw:: html

  {% highlight lang='text' %}

// take h saved from Session Created KDF
  // MixHash(ciphertext)
  h = SHA256(h || encrypted Noise payload from Session Created)

  // MixHash(header)
  h = SHA256(h || header)
  // h is used as the associated data for the AEAD in Session Confirmed part 1, below

  This is the "s" message pattern:

  // Alice's X25519 static keys
  ask = GENERATE_PRIVATE()
  apk = DERIVE_PUBLIC(ask)

  // AEAD parameters
  // k is from Session Request
  n = 1
  ad = h
  ciphertext = ENCRYPT(k, n++, apk, ad)

  // MixHash(ciphertext)
  h = SHA256(h || ciphertext);

  // h is used as the associated data for the AEAD in Session Confirmed part 2

  End of "s" message pattern.

  // Header encryption keys for this message
  See Session Confirmed part 2 below

{% endhighlight %}


KDF for Session Confirmed part 2
--------------------------------------------------------------

.. raw:: html

  {% highlight lang='text' %}

This is the "se" message pattern:

  // DH(ask, bepk) == DH(besk, apk)
  sharedSecret = DH(ask, bepk) = DH(besk, apk)

  // MixKey(DH())
  //[chainKey, k] = MixKey(sharedSecret)
  keydata = HKDF(chainKey, sharedSecret, "", 64)
  chainKey = keydata[0:31]

  // AEAD parameters
  k = keydata[32:63]
  n = 0
  ad = h
  ciphertext = ENCRYPT(k, n, payload, ad)

  // h from Session Confirmed part 1 is used as the associated data for the AEAD in Session Confirmed part 2
  // MixHash(ciphertext)
  h = SHA256(h || ciphertext);

  // retain the chaining key ck for the data phase KDF
  // retain the hash h for the data phase KDF

  End of "se" message pattern.

  // Header encryption keys for this message
  // bik = Bob's intro key
  k_header_1 = bik
  k_header_2: See Session Created KDF above

  // Header protection keys for data phase
  See data phase KDF below

{% endhighlight %}


SessionConfirmed (Type 2)
-----------------------------

Alice sends to Bob, in response to a Session Created message.
Bob responds immediately with a Data message containing an ACK block.
Size: 80 + payload size.
Minimum Size: About 500 (minimum router info block size is about 420 bytes)

Noise content: Alice's static key
Noise payload part 1: None
Noise payload part 2: Alice's RouterInfo, and other blocks
Max payload size: MTU - 108 (IPv4) or MTU - 128 (IPv6).
For 1280 MTU: Max payload is 1172 (IPv4) or 1152 (IPv6).
For 1500 MTU: Max payload is 1392 (IPv4) or 1372 (IPv6).

Payload Security Properties:


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
  |  Short Header 16 bytes, ChaCha20      |
  +  encrypted with Bob intro key and     +
  | derived key, see Header Encryption KDF|
  +----+----+----+----+----+----+----+----+
  |   ChaCha20 frame (32 bytes)           |
  +   Encrypted and authenticated data    +
  +   Alice static key S                  +
  | k defined in KDF for Session Created  |
  +     n = 1                             +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  + Length varies (remainder of packet)   +
  |                                       |
  +   ChaChaPoly frame                    +
  |   Encrypted and authenticated         |
  +   see below for allowed blocks        +
  |                                       |
  +     k defined in KDF for              +
  |     Session Confirmed part 2          |
  +     n = 0                             +
  |     see KDF for associated data       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+

  S :: 32 bytes, ChaChaPoly encrypted Alice's X25519 static key, little endian
       inside 48 byte ChaChaPoly frame

{% endhighlight %}

Unencrypted data (Poly1305 auth tags not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type|frag|  flags  |
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
  |        Noise Payload                  |
  +        (length varies)                +
  |        see below for allowed blocks   |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  Destination Connection ID :: As sent in Session Request,
                               or one received in Session Confirmed?

  Packet Number :: 0 always, for all fragments, even if retransmitted

  type :: 2

  frag :: 1 byte fragment info:
         bit order: 76543210 (bit 7 is MSB)
         bits 7-4: fragment number 0-14, big endian
         bits 3-0: total fragments 1-15, big endian

  flags :: 2 bytes, unused, set to 0 for future compatibility

  S :: 32 bytes, Alice's X25519 static key, little endian

{% endhighlight %}


Payload
```````
- RouterInfo block (must be the first block)
- Options block (optional)
- New Token block (optional)
- Relay Request block (optional)
- Peer Test block (optional)
- First Packet Number block (optional)
- I2NP, First Fragment, or Follow-on Fragment blocks (optional, but probably no room)
- Padding block (optional)

The minimum payload size is 8 bytes. Since the RouterInfo block
will be well more than that, the requirement is met with only that block.


Notes
`````
- Bob must perform the usual Router Info validation.
  Ensure the signature type is supported, verify the signature,
  verify the timestamp is within bounds, and any other checks necessary.
  See below for notes on handling fragmented Router Infos.

- Bob must verify that Alice's static key received in the first frame matches
  the static key in the Router Info. Bob must first search the Router Info for
  a NTCP or SSU2 Router Address with a matching version (v) option.
  See Published Router Info and Unpublished Router Info sections below.
  See below for notes on handling fragmented Router Infos.

- If Bob has an older version of Alice's RouterInfo in his netdb, verify
  that the static key in the router info is the same in both, if present,
  and if the older version is less than XXX old (see key rotate time below)

- Bob must validate that Alice's static key is a valid point on the curve here.

- Options should be included, to specify padding parameters.

- On any error, including AEAD, RI, DH, timestamp, or key validation failure,
  Bob must halt further message processing and close the connection without
  responding.

- Message 3 part 2 frame content: This format of this frame is the same as the
  format of data phase frames, except that the length of the frame is sent
  by Alice in Session Request. See below for the data phase frame format.
  The frame must contain 1 to 4 blocks in the following order:
  1) Alice's Router Info block (required)
  2) Options block (optional)
  3) I2NP blocks (optional)
  4) Padding block (optional)
  This frame must never contain any other block type.
  TODO: what about relay and peer test?

- Message 3 part 2 padding block is recommended.

- There may be no space, or only a small amount of space, available for
  I2NP blocks, depending on the MTU and the Router Info size.
  Do NOT include I2NP blocks if the Router Info is fragmented.
  The simplest implementation may be to never include I2NP blocks in
  the Session Confirmed message, and send all I2NP blocks in
  subsequent Data messages.
  See Router Info block section below for maximum block size.


Session Confirmed Fragmentation
`````````````````````````````````````

The Session Confirmed message must contain the full signed Router Info from Alice so that
Bob may perform several required checks:

- The static key "s" in the RI matches the static key in the handshake
- The introduction key "i" in the RI must be extracted and valid, to be used
  in the data phase
- The RI signature is valid

Unfortunately, the Router Info, even when gzip compressed in the RI block, may exceed the MTU.
Therefore, the Session Confirmed may be fragmented across two or more packets.
This is the ONLY case in the SSU2 protocol where an AEAD-protected payload is fragmented
across two or more packets.

The headers for each packet are constructed as follows:

- ALL headers are short headers with the same packet number 0
- ALL headers contain a "frag" field, with the fragment number and
  total number of fragments
- The unencrypted header of fragment 0 is the associated data (AD) for the "jumbo" message
- Each header is encrypted using the last 24 bytes of data in THAT packet

Construct the series of packets as follows:

- Create a single RI block (fragment 0 of 1 in the RI block frag field).
  We do not use RI block fragmentation, that was for an alternate method
  of solving the same problem.
- Create a "jumbo" payload with the RI block and any other blocks to be included
- Calculate the total data size (not including the header),
  which is the payload size + 64 bytes for the static key and two MACs
- Calculate the space available in each packet, which is
  the MTU minus the IP header (20 or 40), minus the UDP header (8),
  minus the SSU2 short header (16). Total per-packet overhead is
  44 (IPv4) or 64 (IPv6).
- Calculate the number of packets.
- Calculate the size of the data in the last packet. It must be greater than
  or equal to 24 bytes, so that header encryption will work.
  If it is too small, either add a padding block, OR increase the size of the
  padding block if already present, OR reduce the size of one of the other packets
  so that the last packet will be big enough.
- Create the unencrypted header for the first packet, with the total number of
  fragments in the frag field, and encrypt the "jumbo"
  payload with Noise, using the header as AD, as usual.
- Split up the encrypted jumbo packet into fragments
- Add an unencrypted header for each fragment 1-n
- Encrypt the header for each fragment 0-n. Each header uses the SAME
  k_header_1 and k_header_2 as defined above in the Session Confirmed KDF.
- Transmit all fragments

Reassembly process:

When Bob receives any Session Confirmed message, he decrypts the header,
inspects the frag field, and determines that the Session Confirmed is fragmented.
He does not (and cannot) decrypt the message until all fragments are received
and reassembled.

- Preserve the header for fragment 0, as it is used as the Noise AD
- Discard the headers for other fragments before reassembly
- Reassemble the "jumbo" payload, with the header for fragment 0 as AD,
  and decrypt with Noise
- Validate the RI block as usual
- Proceed to the data phase and send ACK 0, as usual

There is no mechanism for Bob to ack individual fragments. When Bob receives all
fragments, reassembles, decrypts, and validates the contents, Bob does a split()
as usual, enters the data phase, and sends an ACK of packet number 0.

If Alice does not receive an ACK of packet number 0, she must retransmit all
session confirmed packets as-is.

Examples:

For 1500 MTU over IPv6, max payload is 1372, RI block overhead is 5,
max (gzip compressed) RI data size is 1367 (assuming no other blocks).
With two packets, the overhead of the 2nd packet is 64, so it can hold
another 1436 bytes of payload. So two packets is enough for a compressed
RI up to 2803 bytes.

The largest compressed RI seen in the current network is about 1400 bytes;
therefore, in practice, two fragments should be enough, even with
a minimum 1280 MTU. The protocol allows for 15 fragments max.

Security analysis:

The integrity and security of a fragmented Session Confirmed is the same as that
of an unfragmented one. Any alteration of any fragment will cause the
Noise AEAD to fail after reassembly. The headers of the fragments after fragment
0 are only used to identify the fragment. Even if an on-path attacker had the
k_header_2 key used to encrypt the header (unlikely, derived from the handshake),
this would not allow the attacker to substitute a valid fragment.



KDF for data phase
----------------------------------------------

The data phase uses the header for associated data.

The KDF generates two cipher keys k_ab and k_ba from the chaining key ck,
using HMAC-SHA256(key, data) as defined in [RFC-2104]_.
This is the split() function, exactly as defined in the Noise spec.

.. raw:: html

  {% highlight lang='text' %}
// split()
  // chainKey = from handshake phase
  keydata = HKDF(chainKey, ZEROLEN, "", 64)
  k_ab = keydata[0:31]
  k_ba = keydata[32:63]

  // key is k_ab for Alice to Bob
  // key is k_ba for Bob to Alice

  keydata = HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
  k_data = keydata[0:31]
  k_header_2 = keydata[32:63]


  // AEAD parameters
  k = k_data
  n = 4 byte packet number from header
  ad = 16 byte header, before header encryption
  ciphertext = ENCRYPT(k, n, payload, ad)

  // Header encryption keys for data phase
  // aik = Alice's intro key
  // bik = Bob's intro key
  k_header_1 = Receiver's intro key (aik or bik)
  k_header_2: from above

{% endhighlight %}





Data Message (Type 6)
---------------------------

Noise payload: All block types are allowed
Max payload size: MTU - 60 (IPv4) or MTU - 80 (IPv6).
For 1500 MTU: Max payload is 1440 (IPv4) or 1420 (IPv6).

Starting with the 2nd part of Session Confirmed, all messages are inside
an authenticated and encrypted ChaChaPoly payload.
All padding is inside the message.
Inside the payload is a standard format with zero or more "blocks".
Each block has a one-byte type and a two-byte length.
Types include date/time, I2NP message, options, termination, and padding.

Note: Bob may, but is not required, to send his RouterInfo to Alice as
his first message to Alice in the data phase.

Payload Security Properties:


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
- The router must drop a message with an AEAD error.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Short Header 16 bytes, ChaCha20      |
  +  encrypted with intro key and         +
  |  derived key, see Data Phase KDF      |
  +----+----+----+----+----+----+----+----+
  |   ChaCha20 data                       |
  +   Encrypted and authenticated data    +
  |  length varies                        |
  +  k defined in Data Phase KDF          +
  |  n = packet number from header        |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+

{% endhighlight %}

Unencrypted data (Poly1305 auth tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type|    flags     |
  +----+----+----+----+----+----+----+----+
  |     Noise payload (block data)        |
  +          (length varies)              +
  |                                       |
  +----+----+----+----+----+----+----+----+

  Destination Connection ID :: As specified in session setup

  Packet Number :: 4 byte big endian integer

  type :: 6

  flags :: 3 bytes, unused, set to 0 for future compatibility

{% endhighlight %}


Notes
`````
- The minimum payload size is 8 bytes. This requirement will be met
  by any ACK, I2NP, First Fragment, or Follow-on Fragment block.
  If the requirement is not met, a Padding block must be included.

- Each packet number may only be used once.
  When retransmitting I2NP messages or fragments,
  a new packet number must be used.


KDF for Peer Test
--------------------

.. raw:: html

  {% highlight lang='text' %}

// AEAD parameters
  // bik = Bob's intro key
  k = bik
  n = 4 byte packet number from header
  ad = 32 byte header, before header encryption
  ciphertext = ENCRYPT(k, n, payload, ad)

  // Header encryption keys for this message
  k_header_1 = bik
  k_header_2 = bik

{% endhighlight %}


Peer Test (Type 7)
------------------------

Charlie sends to Alice, and Alice Sends to Charlie,
for Peer Test phases 5-7 only.
Peer Test phases 1-4 must be sent in-session using a Peer Test block in a Data message.
See the Peer Test Block and Peer Test Process sections below for more information.

Size: 48 + payload size.

Noise payload: See below.

Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Long Header bytes 0-15, ChaCha20     |
  +  encrypted with Alice or Charlie      +
  |  intro key                            |
  +----+----+----+----+----+----+----+----+
  |  Long Header bytes 16-31, ChaCha20    |
  +  encrypted with Alice or Charlie      +
  |  intro key                            |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   ChaCha20 encrypted data             |
  +          (length varies)              +
  |                                       |
  +  see KDF for key and n                +
  |  see KDF for associated data          |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+


{% endhighlight %}

Unencrypted data (Poly1305 authentication tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+
  |    ChaCha20 payload (block data)      |
  +          (length varies)              +
  |    see below for allowed blocks       |
  +----+----+----+----+----+----+----+----+


  Destination Connection ID :: See below

  type :: 7

  ver :: 2

  id :: 1 byte, the network ID (currently 2, except for test networks)

  flag :: 1 byte, unused, set to 0 for future compatibility

  Packet Number :: Random number generated by Alice or Charlie

  Source Connection ID :: See below

  Token :: Randomly generated by Alice or Charlie, ignored

{% endhighlight %}

Payload
```````
- DateTime block
- Address block (required for messages 6 and 7, see note below)
- Peer Test block
- Padding block (optional)

The minimum payload size is 8 bytes. Since the Peer Test block
totals more than that, the requirement is met with only this block.

In messages 5 and 7, the Peer Test block may be identical to
the block from in-session messages 3 and 4,
containing the agreement signed by Charlie,
or it may be regenerated. Signature is optional.

In message 6, the Peer Test block may be identical to
the block from in-session messages 1 and 2,
containing the request signed by Alice,
or it may be regenerated. Signature is optional.

Connection IDs: The two connection IDs are derived from the test nonce.
For messages 5 and 7 sent from Charlie to Alice, the Destination Connection ID
is two copies of the 4-byte big-endian test nonce, i.e. ((nonce << 32) | nonce).
The Source Connection ID is the inverse of the Destination Connection ID,
i.e. ~((nonce << 32) | nonce).
For message 6 sent from Alice to Charlie, swap the two connection IDs.

Address block contents:

- In message 5: Not required.
- In message 6: Charlie's IP and port as selected from Charlie's RI.
- In message 7: Alice's actual IP and port message 6 was received from.



KDF for Retry
----------------

The requirement for the Retry message is that Bob is not required to
decrypt the Session Request message to generate a Retry message in response.
Also, this message must be fast to generate, using symmetric encryption only.

.. raw:: html

  {% highlight lang='text' %}

// AEAD parameters
  // bik = Bob's intro key
  k = bik
  n = 4 byte packet number from header
  ad = 32 byte header, before header encryption
  ciphertext = ENCRYPT(k, n, payload, ad)

  // Header encryption keys for this message
  k_header_1 = bik
  k_header_2 = bik

{% endhighlight %}


Retry (Type 9)
-------------------------------

Bob sends to Alice, in response to a Session Request or Token Request message.
Alice responds with a new Session Request.
Size: 48 + payload size.

Also serves as a Termination message (i.e., "Don't Retry")
if a Termination block is included.


Noise payload: See below.

Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Long Header bytes 0-15, ChaCha20     |
  +  encrypted with Bob intro key         +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Long Header bytes 16-31, ChaCha20    |
  +  encrypted with Bob intro key         +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   ChaCha20 encrypted data             |
  +          (length varies)              +
  |                                       |
  +  see KDF for key and n                +
  |  see KDF for associated data          |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+


{% endhighlight %}

Unencrypted data (Poly1305 authentication tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+
  |    ChaCha20 payload (block data)      |
  +          (length varies)              +
  |    see below for allowed blocks       |
  +----+----+----+----+----+----+----+----+


  Destination Connection ID :: The Source Connection ID
                               received from Alice in Token Request
                               or Session Request

  Packet Number :: Random number generated by Bob

  type :: 9

  ver :: 2

  id :: 1 byte, the network ID (currently 2, except for test networks)

  flag :: 1 byte, unused, set to 0 for future compatibility

  Source Connection ID :: The Destination Connection ID
                          received from Alice in Token Request
                          or Session Request

  Token :: 8 byte unsigned integer, randomly generated by Bob, nonzero,
           or zero if session is rejected and a termination block is included

{% endhighlight %}

Payload
```````
- DateTime block
- Address block
- Options block (optional)
- Termination block (optional, if session is rejected)
- Padding block (optional)

The minimum payload size is 8 bytes. Since the DateTime and Address blocks
total more than that, the requirement is met with only those two blocks.


Notes
`````
- To provide probing resistance, a router should not send a Retry message
  in response to a Session Request or Token Request message unless the
  message type, protocol version, and network ID fields in the Request message
  are valid.

- To limit the magnitude of any amplification attack that can be mounted using spoofed source addresses,
  the Retry message must not contain large amounts of padding.
  It is recommended that the Retry message be no larger than three times the size
  of the message it is responding to.
  Alternatively, use a simple method such as adding a random amount of padding
  in the range 1-64 bytes.


KDF for Token Request
--------------------------

This message must be fast to generate, using symmetric encryption only.

.. raw:: html

  {% highlight lang='text' %}

// AEAD parameters
  // bik = Bob's intro key
  k = bik
  n = 4 byte packet number from header
  ad = 32 byte header, before header encryption
  ciphertext = ENCRYPT(k, n, payload, ad)

  // Header encryption keys for this message
  k_header_1 = bik
  k_header_2 = bik

{% endhighlight %}


Token Request (Type 10)
-------------------------------

Alice sends to Bob. Bob response with a Retry message.
Size: 48 + payload size.

If Alice does not have a valid token, Alice should send this message
instead of a Session Request, to avoid the asymmetric encryption
overhead in generating a Session Request.


Noise payload: See below.

Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Long Header bytes 0-15, ChaCha20     |
  +  encrypted with Bob intro key         +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Long Header bytes 16-31, ChaCha20    |
  +  encrypted with Bob intro key         +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   ChaCha20 encrypted data             |
  +          (length varies)              +
  |                                       |
  +  see KDF for key and n                +
  |  see KDF for associated data          |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+


{% endhighlight %}

Unencrypted data (Poly1305 authentication tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+
  |    ChaCha20 payload (block data)      |
  +          (length varies)              +
  |    see below for allowed blocks       |
  +----+----+----+----+----+----+----+----+


  Destination Connection ID :: Randomly generated by Alice

  Packet Number :: Random number generated by Alice

  type :: 10

  ver :: 2

  id :: 1 byte, the network ID (currently 2, except for test networks)

  flag :: 1 byte, unused, set to 0 for future compatibility

  Source Connection ID :: Randomly generated by Alice,
                          must not be equal to Destination Connection ID

  Token :: zero

{% endhighlight %}


Payload
```````
- DateTime block
- Padding block

The minimum payload size is 8 bytes.


Notes
`````
- To provide probing resistance, a router should not send a Retry message
  in response to a Token Request message unless the
  message type, protocol version, and network ID fields in the Token Request message
  are valid.

- This is NOT a standard Noise message and is not part of the handshake.
  It is not bound to the Session Request message other than by connection IDs.

- On most errors, including AEAD, or apparent replay
  Bob should halt further message processing and
  drop the message without responding.

- Bob must reject connections where the timestamp value is too far off from the
  current time. Call the maximum delta time "D".  Bob must maintain a local
  cache of previously-used handshake values and reject duplicates, to prevent
  replay attacks. Values in the cache must have a lifetime of at least 2*D.
  The cache values are implementation-dependent, however the 32-byte X value
  (or its encrypted equivalent) may be used.

- Bob MAY send a Retry message containing a zero token and a Termination block with a
  clock skew reason code if the timestamp in the DateTime block is too
  far skewed.

- Minimum size: TBD, same rules as for Session Created?



KDF for Hole Punch
--------------------------

This message must be fast to generate, using symmetric encryption only.

.. raw:: html

  {% highlight lang='text' %}

// AEAD parameters
  // aik = Alice's intro key
  k = aik
  n = 4 byte packet number from header
  ad = 32 byte header, before header encryption
  ciphertext = ENCRYPT(k, n, payload, ad)

  // Header encryption keys for this message
  k_header_1 = aik
  k_header_2 = aik

{% endhighlight %}




Hole Punch (Type 11)
-------------------------------

Charlie sends to Alice, in response to a Relay Intro received from Bob.
Alice responds with a new Session Request.
Size: 48 + payload size.

Noise payload: See below.

Raw contents:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  Long Header bytes 0-15, ChaCha20     |
  +  encrypted with Alice intro key       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  Long Header bytes 16-31, ChaCha20    |
  +  encrypted with Alice intro key       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |   ChaCha20 encrypted data             |
  +          (length varies)              +
  |                                       |
  +  see KDF for key and n                +
  |  see KDF for associated data          |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +        Poly1305 MAC (16 bytes)        +
  |                                       |
  +----+----+----+----+----+----+----+----+


{% endhighlight %}

Unencrypted data (Poly1305 authentication tag not shown):

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |      Destination Connection ID        |
  +----+----+----+----+----+----+----+----+
  |   Packet Number   |type| ver| id |flag|
  +----+----+----+----+----+----+----+----+
  |        Source Connection ID           |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+
  |    ChaCha20 payload (block data)      |
  +          (length varies)              +
  |    see below for allowed blocks       |
  +----+----+----+----+----+----+----+----+


  Destination Connection ID :: See below

  Packet Number :: Random number generated by Charlie

  type :: 11

  ver :: 2

  id :: 1 byte, the network ID (currently 2, except for test networks)

  flag :: 1 byte, unused, set to 0 for future compatibility

  Source Connection ID :: See below

  Token :: 8 byte unsigned integer, randomly generated by Charlie, nonzero.

{% endhighlight %}

Payload
```````
- DateTime block
- Address block
- Relay Response block
- Padding block (optional)

The minimum payload size is 8 bytes. Since the DateTime and Address blocks
total more than that, the requirement is met with only those two blocks.

Connection IDs: The two connection IDs are derived from the relay nonce.
The Destination Connection ID
is two copies of the 4-byte big-endian relay nonce, i.e. ((nonce << 32) | nonce).
The Source Connection ID is the inverse of the Destination Connection ID,
i.e. ~((nonce << 32) | nonce).

Alice should ignore the token in the header. The token to be used in
the Session Request is in the Relay Response block.



Noise Payload
===============

Each Noise payload contains zero or more "blocks".

This uses the same block format as defined in the [NTCP2]_ and [ECIES]_ specifications.
Individual block types are defined differently.
The equivalent term in QUIC [RFC-9000]_ is "frames".

There are concerns that encouraging implementers to share code
may lead to parsing issues. Implementers should carefully consider
the benefits and risks of sharing code, and ensure that the
ordering and valid block rules are different for the two contexts.


Payload Format
----------------

There are one or more blocks in the encrypted payload.
A block is a simple Tag-Length-Value (TLV) format.
Each block contains a one-byte identifier, a two-byte length,
and zero or more bytes of data.
This format is identical to that in [NTCP2]_ and [ECIES]_,
however the block definitions are different.

For extensibility, receivers must ignore blocks with unknown identifiers,
and treat them as padding.


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

  blk :: 1 byte, see below
  size :: 2 bytes, big endian, size of data to follow, 0 - TBD
  data :: the data

{% endhighlight %}

Header encryption uses the last 24 bytes of the packet as the IV for the two
ChaCha20 operations. As all packets end with a 16 byte MAC,
this requires that all packet payloads are a minimum of 8 bytes.
If a payload would not otherwise meet this requirement,
a Padding block must be included.

Maximum ChaChaPoly payload varies based on message type, MTU,
and IPv4 or IPv6 address type.
Maximum payload is MTU - 60 for IPv4 and MTU - 80 for IPv6.
Maximum payload data is MTU - 63 for IPv4 and MTU - 83 for IPv6.
Upper limit is about 1440 bytes for IPv4, 1500 MTU, Data message.
Maximum total block size is the maximum payload size.
Maximum single block size is the maximum total block size.
Block type is 1 byte.
Block length is 2 bytes.
Maximum single block data size is the maximum single block size minus 3.

Notes:

- Implementers must ensure that when reading a block,
  malformed or malicious data will not cause reads to
  overrun into the next block or beyond the payload boundary.

- Implementations should ignore unknown block types for
  forward compatibility.



Block types:

====================================  ============= ============
       Payload Block Type              Type Number  Block Length
====================================  ============= ============
DateTime                                    0            7      
Options                                     1           15+
Router Info                                 2         varies 
I2NP Message                                3         varies 
First Fragment                              4         varies 
Follow-on Fragment                          5         varies 
Termination                                 6         9 typ.
Relay Request                               7         varies
Relay Response                              8         varies
Relay Intro                                 9         varies
Peer Test                                  10         varies
Next Nonce                                 11           TBD
ACK                                        12         varies 
Address                                    13         9 or 21
reserved                                   14           --
Relay Tag Request                          15            3      
Relay Tag                                  16            7      
New Token                                  17           15
Path Challenge                             18         varies
Path Response                              19         varies
First Packet Number                        20            7  
Congestion                                 21            4
reserved for experimental features      224-253
Padding                                   254         varies    
reserved for future extension             255
====================================  ============= ============


Block Ordering Rules
----------------------

In the Session Confirmed, Router Info must be the first block.

In all other messages, order is unspecified, except for the
following requirements:
Padding, if present, must be the last block.
Termination, if present, must be the last block except for Padding.
Multiple Padding blocks are not allowed in a single payload.


Block Specifications
----------------------

DateTime
````````
For time synchronization:

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

Notes:

- Unlike in SSU 1, there is no timestamp in the packet header
  for the data phase in SSU 2.
- Implementations should periodically send DateTime blocks
  in the data phase.
- Implementations must round to the nearest second to prevent clock bias in the network.


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


Options Issues:

- Options negotiation is TBD.


RouterInfo
``````````
Pass Alice's RouterInfo to Bob.
Used in Session Confirmed part 2 payload only.
Not to be used in the data phase; use an
I2NP DatabaseStore Message instead.

Minimum Size: About 420 bytes, unless the router identity and
signature in the router info are compressible, which is unlikely.

NOTE: The Router Info block is never fragmented.
The frag field is always 0/1.
See the Session Confirmed Fragmentation section above for more information.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 2  |  size   |flag|frag|              |
  +----+----+----+----+----+              +
  |                                       |
  +       Router Info fragment            +
  | (Alice RI in Session Confirmed)       |
  + (Alice, Bob, or third-party           +
  |  RI in data phase)                    |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 2
  size :: 2 bytes, big endian, 2 + fragment size
  flag :: 1 byte flags
         bit order: 76543210 (bit 7 is MSB)
         bit 0: 0 for local store, 1 for flood request
         bit 1: 0 for uncompressed, 1 for gzip compressed
         bits 7-2: Unused, set to 0 for future compatibility
  frag :: 1 byte fragment info:
         bit order: 76543210 (bit 7 is MSB)
         bits 7-4: fragment number, always 0
         bits 3-0: total fragments, always 1, big endian

  routerinfo :: Alice's or Bob's RouterInfo


{% endhighlight %}

Notes:

- The Router Info is optionally compressed with gzip,
  as indicated by flag bit 1.
  This is different from NTCP2, where it is never compressed,
  and from a DatabaseStore Message, where it always is compressed.
  Compression is optional because it usually is of little benefit
  for small Router Infos, where there is little compressible content,
  but is very beneficial for large Router Infos with several
  compressible Router Addresses.
  Compression is recommended if it allows a Router Info to fit
  in a single Session Confirmed packet without fragmentation.

- Maximum size of first or only fragment in the Session Confirmed message:
  MTU - 113 for IPv4 or MTU - 133 for IPv6.
  Assuming 1500 byte default MTU, and no other blocks in the message,
  1387 for IPv4 or 1367 for IPv6.
  97% of current router infos are smaller than 1367 witout gzipping.
  99.9% of current router infos are smaller than 1367 when gzipped.
  Assuming 1280 byte minimum MTU, and no other blocks in the message,
  1167 for IPv4 or 1147 for IPv6.
  94% of current router infos are smaller than 1147 witout gzipping.
  97% of current router infos are smaller than 1147 when gzipped.

- The frag byte is now unused, the Router Info block is never fragmented.
  The frag byte must be set to fragment 0, total fragments 1.
  See the Session Confirmed Fragmentation section above for more information.

- Flooding must not be requested unless there are published
  RouterAddresses in the RouterInfo. The receiving router
  must not flood the RouterInfo unless there are published
  RouterAddresses in it.

- This protocol does not provide an acknowledgment that the RouterInfo
  was stored or flooded.
  If acknowledgment is desired, and the receiver is floodfill,
  the sender should instead send a standard I2NP DatabaseStoreMessage
  with a reply token.



I2NP Message
````````````
A complete I2NP message with a modified header.

This uses the same 9 bytes for the I2NP header
as in [NTCP2]_ (type, message id, short expiration).


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

Notes:

- This is the same 9-byte I2NP header format used in NTCP2.

- This is exactly the same format as the First Fragment block,
  but the block type indicates that this is a complete message.

- Maximum size including 9-byte I2NP header is MTU - 63 for IPv4 and MTU - 83 for IPv6.


First Fragment
```````````````
The first fragment (fragment #0) of an I2NP message with a modified header.

This uses the same 9 bytes for the I2NP header
as in [NTCP2]_ (type, message id, short expiration).

Total number of fragments is not specified.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 4  |  size   |type|    msg id         |
  +----+----+----+----+----+----+----+----+
  |   short exp       |                   |
  +----+----+----+----+                   +
  |          partial message              |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 4
  size :: 2 bytes, big endian, size of data to follow
          Fragment size is (size - 9).
  type :: 1 byte, I2NP msg type, see I2NP spec
  msg id :: 4 bytes, big endian, I2NP message ID
  short exp :: 4 bytes, big endian, I2NP message expiration, Unix timestamp, unsigned seconds.
               Wraps around in 2106
  message :: Partial I2NP message body, bytes 0 - (size - 10)

{% endhighlight %}

Notes:

- This is the same 9-byte I2NP header format used in NTCP2.

- This is exactly the same format as the I2NP Message block,
  but the block type indicates that this is a the first fragment of a message.

- Partial message length must be greater than zero.

- As in SSU 1, it is recommended to send the last fragment first,
  so that the receiver knows the total number of fragments and can
  efficiently allocate receive buffers.

- Maximum size including 9-byte I2NP header is MTU - 63 for IPv4 and MTU - 83 for IPv6.


Follow-on Fragment
````````````````````````
An additional fragment (fragment number greater than zero) of an I2NP message.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 5  |  size   |frag|    msg id         |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +                                       +
  |          partial message              |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 5
  size :: 2 bytes, big endian, size of data to follow
          Fragment size is (size - 5).
  frag :: Fragment info:
          Bit order: 76543210 (bit 7 is MSB)
          bits 7-1: fragment number 1 - 127 (0 not allowed)
          bit 0: isLast (1 = true)
  msg id :: 4 bytes, big endian, I2NP message ID
  message :: Partial I2NP message body

{% endhighlight %}

Notes:

- Partial message length must be greater than zero.

- As in SSU 1, it is recommended to send the last fragment first,
  so that the receiver knows the total number of fragments and can
  efficiently allocate receive buffers.

- As in SSU 1, the maximum fragment number is 127, but the practical
  limit is 63 or less. Implementations may limit the maximum to
  what is practical for a maximum I2NP message size of about 64 KB,
  which is about 55 fragments with a 1280 minimum MTU.
  See the Max I2NP Message Size section below.

- Maximum partial message size (not including frag and message id) is MTU - 68 for IPv4 and MTU - 88 for IPv6.



Termination
```````````
Drop the connection.
This must be the last non-padding block in the payload.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 6  |  size   |    valid data packets  |
  +----+----+----+----+----+----+----+----+
      received   | rsn|     addl data     |
  +----+----+----+----+                   +
  ~               .   .   .               ~
  +----+----+----+----+----+----+----+----+

  blk :: 6
  size :: 2 bytes, big endian, value = 9 or more
  valid data packets received :: The number of valid packets received
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
         11: Session Request error
         12: Session Created error
         13: Session Confirmed error
         14: Timeout
         15: RI signature verification fail
         16: s parameter missing, invalid, or mismatched in RouterInfo
         17: banned
         18: bad token
         19: connection limits
         20: incompatible version
         21: wrong net ID
         22: replaced by new session
  addl data :: optional, 0 or more bytes, for future expansion, debugging,
               or reason text.
               Format unspecified and may vary based on reason code.

{% endhighlight %}

Notes:

- Not all reasons may actually be used, implementation dependent.
  Most failures will generally result in the message being dropped, not a termination.
  See notes in handshake message sections above.
  Additional reasons listed are for consistency, logging, debugging, or if policy changes.
- It is recommended that an ACK block be included with the Termination block.
- In the data phase, for any reason other than "termination received",
  the peer should respond with a termination block with the reason "termination received".


RelayRequest
``````````````

Sent in a Data message in-session, from Alice to Bob.
See Relay Process section below.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  7 |  size   |flag|       nonce       |
  +----+----+----+----+----+----+----+----+
  |     relay tag     |     timestamp     |
  +----+----+----+----+----+----+----+----+
  | ver| asz|AlicePort|  Alice IP address |
  +----+----+----+----+----+----+----+----+
  |              signature                |
  +            length varies              +
  |         64 bytes for Ed25519          |
  ~                                       ~
  |                 . . .                 |
  +----+----+----+----+----+----+----+----+

  blk :: 7
  size :: 2 bytes, big endian, size of data to follow
  flag :: 1 byte flags, Unused, set to 0 for future compatibility

  The data below here is covered
  by the signature, and Bob forwards it unmodified.

  nonce :: 4 bytes, randomly generated by Alice
  relay tag :: 4 bytes, the itag from Charlie's RI
  timestamp :: Unix timestamp, unsigned seconds.
               Wraps around in 2106
  ver ::  1 byte SSU version to be used for the introduction:
         1: SSU 1
         2: SSU 2
  asz :: 1 byte endpoint (port + IP) size (6 or 18)
  AlicePort :: 2 byte Alice's port number, big endian
  Alice IP :: (asz - 2) byte representation of Alice's IP address,
              network byte order
  signature :: length varies, 64 bytes for Ed25519.
               Signature of prologue, Bob's hash,
               and signed data above, as signed by
               Alice.

{% endhighlight %}

Notes:

* The IP address is always included (unlike in SSU 1)
  and may be different than the IP used for the session.


Signature:

Alice signs the request and includes it in this block; Bob forwards it in the Relay Intro block to Charlie.
Signature algorithm: Sign the following data with the Alice's router signing key:

- prologue: 16 bytes "RelayRequestData", not null-terminated (not included in the message)
- bhash: Bob's 32-byte router hash (not included in the message)
- chash: Charlie's 32-byte router hash (not included in the message)
- nonce: 4 byte nonce
- relay tag: 4 byte relay tag
- timestamp: 4 byte timestamp (seconds)
- ver: 1 byte SSU version
- asz: 1 byte endpoint (port + IP) size (6 or 18)
- AlicePort: 2 byte Alice's port number
- Alice IP: (asz - 2) byte Alice IP address


RelayResponse
``````````````

Sent in a Data message in-session, from Charlie to Bob
or from Bob to Alice, AND in the Hole Punch message
from Charlie to Alice.
See Relay Process section below.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  8 |  size   |flag|code|    nonce
  +----+----+----+----+----+----+----+----+
       |     timestamp     | ver| csz|Char
  +----+----+----+----+----+----+----+----+
   Port|   Charlie IP addr |              |
  +----+----+----+----+----+              +
  |              signature                |
  +            length varies              +
  |         64 bytes for Ed25519          |
  ~                                       ~
  |                 . . .                 |
  +----+----+----+----+----+----+----+----+
  |                 Token                 |
  +----+----+----+----+----+----+----+----+

  blk :: 8
  size :: 2 bytes, 6
  flag :: 1 byte flags, Unused, set to 0 for future compatibility
  code :: 1 byte status code:
         0: accept
         1: rejected by Bob, reason unspecified
         2: rejected by Bob, Charlie is banned
         3: rejected by Bob, limit exceeded
         4: rejected by Bob, signature failure
         5: rejected by Bob, relay tag not found
         6: rejected by Bob, Alice RI not found
         7-63: other rejected by Bob codes TBD
         64: rejected by Charlie, reason unspecified
         65: rejected by Charlie, unsupported address
         66: rejected by Charlie, limit exceeded
         67: rejected by Charlie, signature failure
         68: rejected by Charlie, Alice is already connected
         69: rejected by Charlie, Alice is banned
         70: rejected by Charlie, Alice is unknown
         71-127: other rejected by Charlie codes TBD
         128: reject, source and reason unspecified
         129-255: other reject codes TBD

  The data below is covered by the signature if the code is 0 (accept).
  Bob forwards it unmodified.

  nonce :: 4 bytes, as received from Bob or Alice

  The data below is present only if the code is 0 (accept).

  timestamp :: Unix timestamp, unsigned seconds.
               Wraps around in 2106
  ver ::  1 byte SSU version to be used for the introduction:
         1: SSU 1
         2: SSU 2
  csz :: 1 byte endpoint (port + IP) size (0 or 6 or 18)
         may be 0 for some rejection codes
  CharliePort :: 2 byte Charlie's port number, big endian
                 not present if csz is 0
  Charlie IP :: (csz - 2) byte representation of Charlie's IP address,
                network byte order
                not present if csz is 0
  signature :: length varies, 64 bytes for Ed25519.
               Signature of prologue, Bob's hash,
               and signed data above, as signed by
               Charlie.
               Not present if rejected by Bob.
  token :: Token generated by Charlie for Alice to use
           in the Session Request.
           Only present if code is 0 (accept)

{% endhighlight %}



Notes:

The token must be used immediately by Alice in the Session Request.



Signature:

If Charlie agrees (response code 0) or rejects (response code 64 or higher),
Charlie signs the response and includes it in this block; Bob forwards it in the Relay Response block to Alice.
Signature algorithm: Sign the following data with the Charlie's router signing key:

- prologue: 16 bytes "RelayAgreementOK", not null-terminated (not included in the message)
- bhash: Bob's 32-byte router hash (not included in the message)
- nonce: 4 byte nonce
- timestamp: 4 byte timestamp (seconds)
- ver: 1 byte SSU version
- csz: 1 byte endpoint (port + IP) size (0 or 6 or 18)
- CharliePort: 2 byte Charlie's port number (not present if csz is 0)
- Charlie IP: (csz - 2) byte Charlie IP address (not present if csz is 0)

If Bob rejects (response code 1-63),
Bob signs the response and includes it in this block.
Signature algorithm: Sign the following data with the Bob's router signing key:

- prologue: 16 bytes "RelayAgreementOK", not null-terminated (not included in the message)
- bhash: Bob's 32-byte router hash (not included in the message)
- nonce: 4 byte nonce
- timestamp: 4 byte timestamp (seconds)
- ver: 1 byte SSU version
- csz: 1 byte = 0


RelayIntro
``````````````

Sent in a Data message in-session, from Bob to Charlie.
See Relay Process section below.

Must be preceded by a RouterInfo block, or I2NP DatabaseStore message block (or fragment),
containing Alice's Router Info,
either in the same payload (if there's room), or in a previous message.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |  9 |  size   |flag|                   |
  +----+----+----+----+                   +
  |                                       |
  +                                       +
  |         Alice Router Hash             |
  +             32 bytes                  +
  |                                       |
  +                   +----+----+----+----+
  |                   |      nonce        |
  +----+----+----+----+----+----+----+----+
  |     relay tag     |     timestamp     |
  +----+----+----+----+----+----+----+----+
  | ver| asz|AlicePort|  Alice IP address |
  +----+----+----+----+----+----+----+----+
  |              signature                |
  +            length varies              +
  |         64 bytes for Ed25519          |
  ~                                       ~
  |                 . . .                 |
  +----+----+----+----+----+----+----+----+

  blk :: 9
  size :: 2 bytes, big endian, size of data to follow
  flag :: 1 byte flags, Unused, set to 0 for future compatibility
  hash :: Alice's 32-byte router hash,

  The data below here is covered
  by the signature, as received from Alice in the Relay Request,
  and Bob forwards it unmodified.

  nonce :: 4 bytes, as received from Alice
  relay tag :: 4 bytes, the itag from Charlie's RI
  timestamp :: Unix timestamp, unsigned seconds.
               Wraps around in 2106
  ver ::  1 byte SSU version to be used for the introduction:
         1: SSU 1
         2: SSU 2
  asz :: 1 byte endpoint (port + IP) size (6 or 18)
  AlicePort :: 2 byte Alice's port number, big endian
  Alice IP :: (asz - 2) byte representation of Alice's IP address,
              network byte order
  signature :: length varies, 64 bytes for Ed25519.
               Signature of prologue, Bob's hash,
               and signed data above, as signed by
               Alice.

{% endhighlight %}



Notes:

* For IPv4, Alice's IP address is always 4 bytes, because Alice is trying to connect to Charlie via IPv4.
  IPv6 is supported, and Alice's IP address may be 16 bytes.

* For IPv4, this message must be sent via an established IPv4 connection,
  as that's the only way that Bob knows Charlie's IPv4 address to return to Alice in the RelayResponse_.
  IPv6 is supported, and this message may be sent via an established IPv6 connection.

* Any SSU address published with introducers must contain "4" or "6" in the "caps" option.


Signature:

Alice signs the request and Bob forwards it in this block to Charlie.
Verification algorithm: Verify the following data with the Alice's router signing key:

- prologue: 16 bytes "RelayRequestData", not null-terminated (not included in the message)
- bhash: Bob's 32-byte router hash (not included in the message)
- chash: Charlie's 32-byte router hash (not included in the message)
- nonce: 4 byte nonce
- relay tag: 4 byte relay tag
- timestamp: 4 byte timestamp (seconds)
- ver: 1 byte SSU version
- asz: 1 byte endpoint (port + IP) size (6 or 18)
- AlicePort: 2 byte Alice's port number
- Alice IP: (asz - 2) byte Alice IP address


PeerTest
``````````````

Sent either in a Data message in-session,
or a Peer Test message out-of-session.
See Peer Test Process section below.

For message 2,
must be preceded by a RouterInfo block, or I2NP DatabaseStore message block (or fragment),
containing Alice's Router Info,
either in the same payload (if there's room), or in a previous message.

For message 4, if the relay is accepted (reason code 0),
must be preceded by a RouterInfo block, or I2NP DatabaseStore message block (or fragment),
containing Charlie's Router Info,
either in the same payload (if there's room), or in a previous message.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 10 |  size   | msg|code|flag|         |
  +----+----+----+----+----+----+         +
  | Alice router hash (message 2 only)    |
  +             or                        +
  | Charlie router hash (message 4 only)  |
  + or all zeros if rejected by Bob       +
  | Not present in messages 1,3,5,6,7     |
  +                             +----+----+
  |                             | ver|
  +----+----+----+----+----+----+----+----+
     nonce       |     timestamp     | asz|
  +----+----+----+----+----+----+----+----+
  |AlicePort|  Alice IP address |         |
  +----+----+----+----+----+----+         +
  |              signature                |
  +            length varies              +
  |         64 bytes for Ed25519          |
  ~                                       ~
  |                 . . .                 |
  +----+----+----+----+----+----+----+----+

  blk :: 10
  size :: 2 bytes, big endian, size of data to follow
  msg :: 1 byte message number 1-7
  code :: 1 byte status code:
         0: accept
         1: rejected by Bob, reason unspecified
         2: rejected by Bob, no Charlie available
         3: rejected by Bob, limit exceeded
         4: rejected by Bob, signature failure
         5: rejected by Bob, address unsupported
         6-63: other rejected by Bob codes TBD
         64: rejected by Charlie, reason unspecified
         65: rejected by Charlie, unsupported address
         66: rejected by Charlie, limit exceeded
         67: rejected by Charlie, signature failure
         68: rejected by Charlie, Alice is already connected
         69: rejected by Charlie, Alice is banned
         70: rejected by Charlie, Alice is unknown
         70-127: other rejected by Charlie codes TBD
         128: reject, source and reason unspecified
         129-255: other reject codes TBD
         reject codes only allowed in messages 3 and 4
  flag :: 1 byte flags, Unused, set to 0 for future compatibility
  hash :: Alice's or Charlie's 32-byte router hash,
          only present in messages 2 and 4.
          All zeros (fake hash) in message 4 if rejected by Bob.

  For messages 1-4, the data below here is covered
  by the signature, if present, and Bob forwards it unmodified.

  ver :: 1 byte SSU version:
         1: SSU 1 (not supported)
         2: SSU 2 (required)
  nonce :: 4 byte test nonce, big endian
  timestamp :: Unix timestamp, unsigned seconds.
               Wraps around in 2106
  asz :: 1 byte endpoint (port + IP) size (6 or 18)
  AlicePort :: 2 byte Alice's port number, big endian
  Alice IP :: (asz - 2) byte representation of Alice's IP address,
              network byte order
  signature :: length varies, 64 bytes for Ed25519.
               Signature of prologue, Bob's hash,
               and signed data above, as signed by
               Alice or Charlie.
               Only present for messages 1-4.
               Optional in message 5-7.


{% endhighlight %}


Notes:

* Unlike in SSU 1, message 1 must include Alice's IP address and port.

* Testing of IPv6 addresses is supported,
  and Alice-Bob and Alice-Charlie communication may be via IPv6,
  if Bob and Charlie indicate support with a 'B' capability in their published IPv6 address.
  See Proposal 126 for details.

  Alice sends the request to Bob using an existing session over the transport (IPv4 or IPv6) that she wishes to test.
  When Bob receives a request from Alice via IPv4, Bob must select a Charlie that advertises an IPv4 address.
  When Bob receives a request from Alice via IPv6, Bob must select a Charlie that advertises an IPv6 address.
  The actual Bob-Charlie communication may be via IPv4 or IPv6 (i.e., independent of Alice's address type).

* Messages 1-4 must be contained in a Data message in an existing session.

* Bob must send Alice's RI to Charlie prior to sending message 2.

* Bob must send Charlie's RI to Alice prior to sending message 4, if accepted (reason code 0).

* Messages 5-7 must be contained in a Peer Test message out-of-session.

* Messages 5 and 7 may contain the same signed data as sent in messages 3 and 4, or it may
  be regenerated with a new timestamp. Signature is optional.

* Message 6 may contain the same signed data as sent in messages 1 and 2, or it may
  be regenerated with a new timestamp. Signature is optional.


Signatures:

Alice signs the request and includes it in message 1; Bob forwards it in message 2 to Charlie.
Charlie signs the response and includes it in message 3; Bob forwards it in message 4 to Alice.
Signature algorithm: Sign or verify the following data with the Alice's or Charlie's signing key:

- prologue: 16 bytes "PeerTestValidate", not null-terminated (not included in the message)
- bhash: Bob's 32-byte router hash (not included in the message)
- ahash: Alice's 32-byte router hash
  (Only used in the signature for messages 3 and 4; not included in message 3 or 4)
- ver: 1 byte SSU version
- nonce: 4 byte test nonce
- timestamp: 4 byte timestamp (seconds)
- asz: 1 byte endpoint (port + IP) size (6 or 18)
- AlicePort: 2 byte Alice's port number
- Alice IP: (asz - 2) byte Alice IP address



NextNonce
``````````````

TODO only if we rotate keys


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 11 |  size   |      TBD               |
  +----+----+----+                        +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 11
  size :: 2 bytes, big endian, size of data to follow

{% endhighlight %}


Ack
``````````````
4 byte ack through, followed by an ack count
and zero or more nack/ack ranges.

This design is adapted and simplified from QUIC.
The design goals are as follows:

- We want to efficiently encode a "bitfield", which is a
  sequence of bits representing acked packets.
- The bitfield is mostly 1's. Both the 1's and the 0's
  generally come in sequential "clumps".
- The amount of room in the packet available for acks varies.
- The most important bit is the highest numbered one.
  Lower numbered ones are less important.
  Below a certain distance from the highest bit, the oldest
  bits will be "forgotten" and never sent again.

The encoding specified below accomplishes these design goals,
by sending the number of the highest bit that is set to 1,
together with additional consecutive bits lower than that
which are also set to 1.
After that, if there is room, one or more "ranges" specifying
the number of consectutive 0 bits and consecutive 1 bits
lower than that.
See QUIC [RFC-9000]_ section 13.2.3 for more background.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 12 |  size   |    Ack Through    |acnt|
  +----+----+----+----+----+----+----+----+
  |  range  |  range  |     .   .   .     |
  +----+----+----+----+                   +
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 12
  size :: 2 bytes, big endian, size of data to follow,
          5 minimum
  ack through :: highest packet number acked
  acnt :: number of acks lower than ack through also acked,
          0-255
  range :: If present,
           1 byte nack count followed by 1 byte ack count,
           0-255 each

{% endhighlight %}

Examples:

We want to ACK packet 10 only:

- Ack Through: 10
- acnt: 0
- no ranges are included

We want to ACK packets 8-10 only:

- Ack Through: 10
- acnt: 2
- no ranges are included

We want to ACK 10 9 8 6 5 2 1 0, and NACK 7 4 3.
The encoding of the ACK Block is:

- Ack Through: 10
- acnt: 2 (ack 9 8)
- range: 1 2 (nack 7, ack 6 5)
- range: 2 3 (nack 4 3, ack 2 1 0)


Notes:

- Ranges may not be present. Max number of ranges is not specified,
  may be as many as will fit in the packet.
- Range nack may be zero if acking more than 255 consecutive packets.
- Range ack may be zero if nacking more than 255 consecutive packets.
- Range nack and ack may not both be zero.
- After the last range, packets are neither acked nor nacked.
  Length of the ack block and how old acks/nacks are handled
  is up to the sender of the ack block.
  See ack sections below for discussion.
- The ack through should be the highest packet number received,
  and any packets higher have not been received.
  However, in limited situations, it could be lower, such as
  acking a single packet that "fills in a hole", or a simplified
  implementation that does not maintain the state of all received packets.
  Above the highest received, packets are neither acked nor nacked,
  but after several ack blocks, it may be appropriate to go
  into fast retransmit mode.
- This format is a simplified version of that in QUIC.
  It is designed to efficiently encode a large number of ACKs,
  together with bursts of NACKs.
- ACK blocks are used to acknowledge data phase packets.
  They are only to be included for in-session data phase packets.


Address
``````````````
2 byte port and 4 or 16 byte IP address.
Alice's address, sent to Alice by Bob,
or Bob's address, sent to Bob by Alice.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 13 | 6 or 18 |   Port  | IP Address    
  +----+----+----+----+----+----+----+----+
       |
  +----+

  blk :: 13
  size :: 2 bytes, big endian, 6 or 18
  port :: 2 bytes, big endian
  ip :: 4 byte IPv4 or 16 byte IPv6 address,
        big endian (network byte order)

{% endhighlight %}



Relay Tag Request
```````````````````````
This may be sent by Alice in a Session Request, Session Confirmed, or Data message.
Not supported in the Session Created message, as Bob doesn't have Alice's RI yet,
and doesn't know if Alice supports relay.
Also, if Bob is getting an incoming connection, he probably doesn't need introducers
(except perhaps for the other type ipv4/ipv6).

When sent in the Session Request,
Bob may respond with a Relay Tag in the Session Created message,
or may choose to wait until receiving Alice's RouterInfo in the
Session Confirmed to validate Alice's identity before responding in a Data message.
If Bob does not wish to relay for Alice, he does not send a Relay Tag block.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+
  | 15 |    0    |
  +----+----+----+

  blk :: 15
  size :: 2 bytes, big endian, value = 0

{% endhighlight %}


Relay Tag
```````````
This may be sent by Bob in a Session Confirmed or Data message,
in response to a Relay Tag Request from Alice.

When the Relay Tag Request is sent in the Session Request,
Bob may respond with a Relay Tag in the Session Created message,
or may choose to wait until receiving Alice's RouterInfo in the
Session Confirmed to validate Alice's identity before responding in a Data message.
If Bob does not wish to relay for Alice, he does not send a Relay Tag block.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+
  | 16 |    4    |    relay tag      |
  +----+----+----+----+----+----+----+

  blk :: 16
  size :: 2 bytes, big endian, value = 4
  relay tag :: 4 bytes, big endian, nonzero

{% endhighlight %}


New Token
```````````````
For a subsequent connection.
Generally included in the Session Created and Session Confirmed messages.
May also be sent again in the Data message of a long-lived session
if the previous token expires.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 17 |   12    |     expires       |
  +----+----+----+----+----+----+----+----+
                  token              |
  +----+----+----+----+----+----+----+

  blk :: 17
  size :: 2 bytes, big endian, value = 12
  expires :: Unix timestamp, unsigned seconds.
             Wraps around in 2106
  token :: 8 bytes, big endian

{% endhighlight %}


Path Challenge
``````````````
A Ping with arbitrary data to be returned in a Path Response,
used as a keep-alive or to validate an IP/Port change.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 18 |  size   |    Arbitrary Data      |
  +----+----+----+                        +
  |                                       |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 18
  size :: 2 bytes, big endian, size of data to follow
  data :: Arbitrary data to be returned in a Path Response
          length as selected by sender

{% endhighlight %}

Notes:

- A minimum data size of 8 bytes, containing random data,
  is recommended but not required.
- The max size is not specified, but it should be well under
  1280, because the PMTU during the path validation phase is 1280.
- Large challenge sizes are not recommended because they could
  be a vector for packet amplification attacks.


Path Response
``````````````
A Pong with the data received in the Path Challenge, as reply to the Path Challenge,
used as a keep-alive or to validate an IP/Port change.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  | 19 |  size   |                        |
  +----+----+----+                        +
  |    Data received in Path Challenge    |
  ~               .   .   .               ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  blk :: 19
  size :: 2 bytes, big endian, size of data to follow
  data :: As received in a Path Challenge

{% endhighlight %}




First Packet Number
``````````````````````
Optionally included in the handshake in each direction,
to specify the first packet number that will be sent.
This provides more security for header encryption,
similar to TCP.

Not fully specified, not currently supported.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+
  | 20 |  size   |  First pkt number |
  +----+----+----+----+----+----+----+

  blk :: 20
  size :: 4
  pkt num :: The first packet number to be sent in the data phase

{% endhighlight %}



Congestion
``````````````````````
This is block is designed to be an extensible method
to exchange congestion control information.
Congestion control can be complex and may evolve as
we get more experience with the protocol in live testing,
or after full rollout.

This keeps any congestion information out of the high-usage
I2NP, First Fragment, Followon Fragment, and ACK blocks,
where there is no space for flags allocated.
While there are three bytes of unused flags in the Data packet header,
that also provides limited space for extensibility,
and weaker encryption protection.

While it is somewhat wasteful to use a 4-byte block
for two bits of information, by putting this in a separate block,
we can easily extend it with additional data such as
current window sizes, measured RTT, or other flags.
Experience has shown that flag bits alone is often insufficient
and awkward for implementation of advanced congestion control schemes.
Trying to add support for any possible congestion control feature
in, for example, the ACK block, would waste space and add complexity
to the parsing of that block.

Implementations should not assume that the other router supports
any particular flag bit or feature included here,
unless implementation is required by a future version of this specification.

This block should probably be the last non-padding block in the payload.


.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+
  | 21 |  size   |flag|
  +----+----+----+----+

  blk :: 21
  size :: 1 (or more if extended)
  flag :: 1 byte flags
         bit order: 76543210 (bit 7 is MSB)
         bit 0: 1 to request immediate ack
         bit 1: 1 for explicit congestion notification (ECN)
         bits 7-2: Unused, set to 0 for future compatibility

{% endhighlight %}




Padding
```````
This is for padding inside AEAD payloads.
Padding for all messages are inside AEAD payloads.

Padding should roughly adhere to the negotiated parameters.
Bob sent his requested tx/rx min/max parameters in Session Created.
Alice sent her requested tx/rx min/max parameters in Session Confirmed.
Updated options may be sent during the data phase.
See options block information above.

If present, this must be the last block in the payload.



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

Notes:

- Size = 0 is allowed.
- Padding strategies TBD.
- Minimum padding TBD.
- Padding-only payloads are allowed.
- Padding defaults TBD.
- See options block for padding parameter negotiation
- See options block for min/max padding parameters
- Do not exceed the MTU. If more padding is necessary, send multiple messages.
- Router response on violation of negotiated padding is implementation-dependent.

- The padding length is either to be decided on a per-message basis and
  estimates of the length distribution, or random delays should be added.
  These countermeasures are to be included to resist DPI, as message sizes
  would otherwise reveal that I2P traffic is being carried by the transport
  protocol. The exact padding scheme is an area of future work, Appendix A
  of [NTCP2]_ provides more information on the topic.





Replay Prevention
=====================

SSU2 is designed to minimize the impact of messages replayed by an attacker.

Token Request, Retry, Session Request, Session Created, Hole Punch,
and out-of-session Peer Test messages must contain DateTime blocks.

Both Alice and Bob validate that the time for these messages is within a valid skew (recommended +/- 2 minutes).
For "probing resistance", Bob should not reply to Token Request or Session Request
messages if the skew is invalid, as these messages may be a replay or probing attack.

Bob may choose to reject duplicate Token Request and Retry messages,
even if the skew is valid, via a Bloom filter or other mechanism.
However, the size and CPU cost of replying to these messages is low.
At worst, a replayed Token Request message may invalidate a previously-sent
token.

The token system greatly minimizes the impact of replayed Session Request messages.
Since tokens may only be used once, a replayed Session Request message
will never have a valid token.
Bob may choose to reject duplicate Session Request messages,
even if the skew is valid, via a Bloom filter or other mechanism.
However, the size and CPU cost of replying with a Retry message is low.
At worst, sending a Retry message may invalidate a previously-sent
token.


Duplicate Session Created and Session Confirmed messages will
not validate because the Noise handshake state will not be in the correct state to decrypt them.
At worst, a peer may retransmit a Session Confirmed in response to an apparent
duplicate Session Created.

Replayed Hole Punch and Peer Test messages should have little or no impact.

Routers must use the data message packet number to
detect and drop duplicate data phase messages.
Each packet number should only be used once.
Replayed messages must be ignored.




Handshake Retransmission
===========================

Session Request
----------------
If no Session Created or Retry is received by Alice:

Maintain same source and connection IDs, ephemeral key, and packet number 0.
Or, just retain and retransmit the same encrypted packet.
Packet number must not be incremented, because that would change
the chained hash value used to encrypt the Session Created message.

Recommended retransmission intervals: 1.25, 2.5, and 5 seconds (1.25, 3.75, and 8.75 seconds after first sent).
Recommended timeout: 15 seconds total


Session Created
----------------
If no Session Confirmed is received by Bob:

Maintain same source and connection IDs, ephemeral key, and packet number 0.
Or, just retain the encrypted packet.
Packet number must not be incremented, because that would change
the chained hash value used to encrypt the Session Confirmed message.

Recommended retransmission intervals: 1, 2, and 4 seconds (1, 3,  and 7 seconds after first sent).
Recommended timeout: 12 seconds total


Session Confirmed
------------------
In SSU 1, Alice does not shift to the data phase until the first data packet is
received from Bob. This makes SSU 1 a two-round-trip setup.

For SSU 2,
Recommended Session Confirmed retransmission intervals: 1.25, 2.5, and 5 seconds (1.25, 3.75, and 8.75 seconds after first sent).

There are several alternatives. All are 1 RTT:

1) Alice assumes Session Confirmed was received, sends data messages immediately,
   never retransmit Session Confirmed. Data packets received out-of-order
   (before Session Confirmed) will be undecryptable, but will get retransmitted.
   If Session Confirmed is lost, all sent data messages will be dropped.

2) As in 1), send data messages immediately, but also retransmit Session Confirmed
   until a data message is received.

3) We could use IK instead of XK, as it has only two messages in the handshake, but
   it uses an extra DH (4 instead of 3).

The recommeded implementation is option 2).
Alice must retain the information required to retransmit the Session Confirmed message.
Alice should also retransmit all Data messages after the Session Confirmed
message is retransmitted.

When retransmitting Session Confirmed,
maintain same source and connection IDs, ephemeral key, and packet number 1.
Or, just retain the encrypted packet.
Packet number must not be incremented, because that would change
the chained hash value which is an input for the split() function.

Bob may retain (queue) the data messages received before the Session Confirmed message.
Neither the header protection keys nor the decryption keys are available
before the Session Confirmed message is received, so Bob does not know
that they are data messages, but that can be presumed.
After the Session Confirmed message is received, Bob is able to
decrypt and process the queued Data messages.
If this is too complex, Bob may just drop the undecryptable Data messages,
as Alice will retransmit them.

Note: If the session confirmed packets are lost, Bob will retransmit
session created. The session created header will not be decryptable
with Alice's intro key, as it is set with Bob's intro key
(unless fallback decryption is performed with Bob's intro key).
Bob may immediately retransmit the session confirmed packets
if not previously acked, and an undecryptable packet is received.


Token Request
----------------
If no Retry is received by Alice:

Maintain same source and connection IDs.
An implementation may generate a new random packet number and encrypt a new packet;
Or it may reuse the same packet number or just retain and retransmit the same encrypted packet.
Packet number must not be incremented, because that would change
the chained hash value used to encrypt the Session Created message.

Recommended retransmission intervals: 3 and 6 seconds (3 and 9 seconds after first sent).
Recommended timeout: 15 seconds total


Retry
---------
If no Session Confirmed is received by Bob:

A Retry message is not retransmitted on timeout, to reduce the impacts
of spoofed source addresses.

However, a Retry message may be retransmitted in response to a repeated
Session Request message being received with the original (invalid) token,
or in response to a repeated Token Request message.
In either case, this indicates that the Retry message was lost.

If a second Session Request message is received with a different
but still-invalid token, drop the pending session and do not respond.

If resending the Retry message:
Maintain same source and connection IDs and token.
An implementation may generate a new random packet number and encrypt a new packet;
Or it may reuse the same packet number or just retain and retransmit the same encrypted packet.



Total Timeout
--------------
Recommended total timeout for the handshake is 20 seconds.



Duplicates and Error Handling
-----------------------------
Duplicates of the three Noise handshake messages
Session Request, Session Created, and Session Confirmed
must be detected before MixHash() of the header.
While the Noise AEAD processing will presumably fail after that,
the handshake hash would already be corrupted.

If any of the three messages is corrupted and fails AEAD,
the handshake cannot subsequently be recovered even with retransmission,
because MixHash() was already called on the corrupted message.



Tokens
=============

The Token in the Session Request header is used for DoS mitigation,
to prevent source address spoofing, and as resistance to replay attacks.

If Bob does not accept the token in the Session Request message, Bob does NOT decrypt
the message, as it requires an expensive DH operation.
Bob simply sends a Retry message with a new token.

If a subsequent Session Request message then is received with that token,
Bob proceeds to decrypt that message and proceed with the handshake.

The token must be a randomly-generated 8 byte value, if the generator of the token
stores the values and associated IP and port (in-memory or persistently).
The generator may not generate an opaque value, for example,
using the SipHash (with a secret seed K0, K1) of the IP, port, and current hour or day,
to create tokens that do not need to be saved in-memory,
because this method makes it difficult to reject reused tokens and replay attacks.
However, it is a topic for further study if we may migrate to such a scheme,
as [WireGuard]_ does, using a 16-byte HMAC of a server secret and IP address.

Tokens may only be used once.
A token sent from Bob to Alice in a Retry message must be used immediately, and expires
in a few seconds.
A token sent in a New Token block in an established session
may be used in a subsequent connection, and it
expires at the time specified in that block.
Expiration is specified by the sender; recommended values are
several minutes minimum, one or more hours maximum, depending on
desired maximum overhead of stored tokens.

If a router's IP or port changes, it must delete all saved tokens
(both inbound and outbound) for the old IP or port, as they are no longer valid.
Tokens may optionally be persisted across router restarts, implementation dependent.
Acceptance of an unexpired token is not guaranteed; if Bob has forgotten or deleted
his saved tokens, he will send a Retry to Alice.
A router may choose to limit token storage, and remove the oldest stored tokens
even if they have not expired.

New Token blocks may be sent from Alice to Bob or Bob to Alice.
They would typically be sent at least once, during or soon after session establishment.
Due to validation checks of the RouterInfo in the Session Confirmed message,
Bob should not send a New Token block in the Session Created message,
it may be sent with the ACK 0 and Router Info after the Session Confirmed is received
and validated.

As session lifetimes are often longer than token expiration,
the token should be resent before or after expiration with a new expiration time,
or a new token should be sent.
Routers should assume that only the last token received is valid;
there is no requirement to store multiple inbound or outbound tokens for the same IP/port.

A token is bound to the combination of source IP/port and destination IP/port.
A token received on IPv4 may not be used for IPv6 or vice versa.

If either peer migrates to a new IP or port during the session
(see the Connection Migration section), any previously-exchanged tokens are invalited,
and new tokens must be exchanged.

Implementations may, but are not required to, save tokens on disk and
reload them on restart. If persisted, the implementation must
ensure that the IP and port have not changed since shutdown
before reloading them.



I2NP Message Fragmentation
===========================

Differences from SSU 1

Note: As in SSU 1, the initial fragment does not contain information
on the total number of fragments or the total length.
Follow-on fragments do not contain information on their offset.
This provides the sender the flexibility of fragmenting "on the fly"
based on available space in the packet.
(Java I2P does not do this; it "pre-fragments" before the first fragment is sent)
However, it does burden the receiver to store fragments
received out-of-order and delay reassembly until all fragments are received.

As in SSU 1, any retransmission of fragments must preserve the length (and implicit offset)
of the fragment's previous transmission.

SSU 2 does separate the three cases (full message, initial fragment, and follow-on fragment)
into three different block types, to improve processing efficiency.



I2NP Message Duplication
===========================

This protocol does NOT completely prevent duplicate delivery of I2NP messages.
IP-layer duplicates or replay attacks will be detected at the SSU2 layer,
because each packet number may only be used once.

When I2NP messages or fragments are retransmitted in new packets, however,
this is not detectable at the SSU2 layer.
The router should enforce I2NP expiration (both too old and too far in the future)
and use a Bloom filter or other mechanism based on the I2NP message ID.

Additional mechanisms may be used by the router, or in the SSU2 implementation,
to detect duplicates.
For example, SSU2 could maintain a cache of recently-received message IDs.
This is implementation-dependent.



Congestion Control
====================

This specification specifies the protocol for packet numbering and
ACK blocks. This provides sufficient real-time information for a
transmitter to implement an efficient and responsive congestion control algorithm,
while allowing flexibility and innovation in that implementation.
This section discusses implementation goals and provides suggestions.
General guidance may be found in [RFC-9002]_.
See also [RFC-6298]_ for guidance on retransmission timers.

ACK-only data packets should not count for bytes or packets in-flight
and are not congestion-controlled.
Unlike in TCP, SSU2 can detect the loss of these packets and
that information may be used to adjust the congestion state.
However, this document does not specify a mechanism for doing so.

Packets containing some other non-data blocks may also be excluded from congestion control
if desired, implementation-dependent. For example:

- Peer Test
- Relay request/intro/response
- Path challenge/response

It is recommended that the congestion control be based on byte count, not
packet count, following the guidance in TCP RFCs and QUIC [RFC-9002]_.
An additional packet count limit may be useful as well to prevent
buffer overflow in the kernel or in middleboxes, implementation dependent,
although this may add significant complexity.
If per-session and/or total packet output is bandwidth-limited and/or paced,
this may mitigate the need for packet count limiting.




Packet Numbers
--------------

In SSU 1, ACKs and NACKs contained I2NP message numbers and fragment bitmasks.
Transmitters tracked the ACK status of outbound messages (and their fragments)
and retransmitted fragments as required.

In SSU 2, ACKs and NACKs contain packet numbers.
Transmitters must maintain a data structure with a mapping of packet numbers to their contents.
When a packet is ACKed or NACKed, the transmitter must determine what
I2NP messages and fragments were in that packet, to decide what to retransmit.


Session Confirmed ACK
------------------------

Bob sends an ACK of packet 0, which acknowledges the Session Confirmed message and allows
Alice to proceed to the data phase, and discard the large Session Confirmed message
being saved for possible retransmission.
This replaces the DeliveryStatusMessage sent by Bob in SSU 1.

Bob should send an ACK as soon as possible after receiving the Session Confirmed message.
A small delay (no more than 50 ms) is acceptable, since at least one Data message should arrive almost
immediately after the Session Confirmed message, so that the ACK may acknowledge both
the Session Confirmed and the Data message.
This will prevent Bob from having to retransmit the Session Confirmed message.


Generating ACKs
--------------------

Definition: Ack-eliciting packets:
Packets that contain ack-eliciting blocks elicit an ACK from the receiver
within the maximum acknowledgment delay and are called ack-eliciting packets.

Routers acknowledge all packets they receive and process.  However,
only ack-eliciting packets cause an ACK block to be sent within the
maximum ack delay.  Packets that are not ack-eliciting are only
acknowledged when an ACK block is sent for other reasons.

When sending a packet for any reason, an endpoint should attempt to
include an ACK block if one has not been sent recently.  Doing so
helps with timely loss detection at the peer.

In general, frequent feedback from a receiver improves loss and
congestion response, but this has to be balanced against excessive
load generated by a receiver that sends an ACK block in response to
every ack-eliciting packet.  The guidance offered below seeks to
strike this balance.

In-session data packets containing any block
EXCEPT for the following are ack-eliciting:

- ACK block
- Address block
- DateTime block
- Padding block
- Termination block
- Others?

Out-of session packets, including handshake messages
and peer test messages 5-7, have their own acknowledgement mechanisms.
See below.


Handshake ACKs
--------------

These are special cases:


- Token Request is implicitly acked by Retry
- Session Request is implicitly acked by Session Created or Retry
- Retry is implicitly acked by Session Request
- Session Created is implicitly acked by Session Confirmed
- Session Confirmed should be acked immediately



Sending ACK Blocks
---------------------

ACK blocks are used to acknowledge data phase packets.
They are only to be included for in-session data phase packets.

Every packet should be acknowledged at least once, and ack-eliciting
packets must be acknowledged at least once within a maximum delay.

An endpoint must acknowledge all ack-eliciting handshake
packets immediately
within its maximum delay, with the following exception.
Prior to handshake confirmation, an endpoint might not have packet
header encryption keys for decrypting the packets
when they are received.  It might therefore buffer them and
acknowledge them when the requisite keys become available.

Since packets containing only ACK blocks are not congestion
controlled, an endpoint must not send more than one such packet in
response to receiving an ack-eliciting packet.

An endpoint must not send a non-ack-eliciting packet in response to a
non-ack-eliciting packet, even if there are packet gaps that precede
the received packet.  This avoids an infinite feedback loop of
acknowledgments, which could prevent the connection from ever
becoming idle.  Non-ack-eliciting packets are eventually acknowledged
when the endpoint sends an ACK block in response to other events.

An endpoint that is only sending ACK blocks will not receive
acknowledgments from its peer unless those acknowledgments are
included in packets with ack-eliciting blocks.  An endpoint should
send an ACK block with other blocks when there are new ack-eliciting
packets to acknowledge.  When only non-ack-eliciting packets need to
be acknowledged, an endpoint MAY choose not to send an ACK block with
outgoing blocks until an ack-eliciting packet has been received.

An endpoint that is only sending non-ack-eliciting packets might
choose to occasionally add an ack-eliciting block to those packets to
ensure that it receives an acknowledgment.  In
that case, an endpoint MUST NOT send an ack-eliciting block in all
packets that would otherwise be non-ack-eliciting, to avoid an
infinite feedback loop of acknowledgments.

In order to assist loss detection at the sender, an endpoint should
generate and send an ACK block without delay when it receives an ack-
eliciting packet in any of these cases:

*  When the received packet has a packet number less than another
   ack-eliciting packet that has been received

*  When the packet has a packet number larger than the highest-
   numbered ack-eliciting packet that has been received and there are
   missing packets between that packet and this packet.

*  When the ack-immediate flag in the packet header is set

The algorithms are expected to be resilient to
receivers that do not follow the guidance offered above.  However, an
implementation should only deviate from these requirements after
careful consideration of the performance implications of a change,
for connections made by the endpoint and for other users of the
network.


ACK Frequency
-----------------

A receiver determines how frequently to send acknowledgments in
response to ack-eliciting packets.  This determination involves a
trade-off.

Endpoints rely on timely acknowledgment to detect loss.
Window-based congestion controllers rely on
acknowledgments to manage their congestion window.  In both cases,
delaying acknowledgments can adversely affect performance.

On the other hand, reducing the frequency of packets that carry only
acknowledgments reduces packet transmission and processing cost at
both endpoints.  It can improve connection throughput on severely
asymmetric links and reduce the volume of acknowledgment traffic
using return path capacity; see Section 3 of [RFC-3449]_.

A receiver should send an ACK block after receiving at least two ack-eliciting packets.
This recommendation is general in nature and
consistent with recommendations for TCP endpoint behavior [RFC-5681]_.
Knowledge of network conditions, knowledge of the peer's congestion
controller, or further research and experimentation might suggest
alternative acknowledgment strategies with better performance
characteristics.

A receiver may process multiple available packets before determining
whether to send an ACK block in response.
In general, the receiver should not delay an ACK by more than RTT / 6,
or 150 ms max.

The ack-immediate flag in the data packet header is a request that
the receiver send an ack soon after reception, probably within
a few ms.
In general, the receiver should not delay an immediate ACK by more than RTT / 16,
or 5 ms max.


Immediate ACK Flag
-------------------

The receiver does not know the sender's send window size,
and so does not know how long to delay before sending an ACK.
The immediate ACK flag in the data packet header is an important way to
maintain maximum throughput by minimizing effective RTT.
The immediate ACK flag is header byte 13, bit 0, i.e. (header[13] & 0x01).
When set, an immediate ACK is requested.
See the short header section above for details.

There are several possible strategies a sender may use to determine
when to set the immediate-ack flag:

- Set once every N packets, for some small N
- Set on the last in a burst of packet
- Set whenver the send window is almost full, for example over 2/3 full
- Set on all packets with retransmitted fragments

Immediate ACK flags should only be necessary on data packets containing
I2NP messages or message fragments.



ACK Block Size
--------------------

When an ACK block is sent, one or more ranges of acknowledged packets
are included.  Including acknowledgments for older packets reduces
the chance of spurious retransmissions caused by losing previously
sent ACK blocks, at the cost of larger ACK blocks.

ACK blocks should always acknowledge the most recently received
packets, and the more out of order the packets are, the more
important it is to send an updated ACK block quickly, to prevent the
peer from declaring a packet as lost and spuriously retransmitting
the blocks it contains.  An ACK block must fit within a
single packet.  If it does not, then older ranges (those with
the smallest packet numbers) are omitted.

A receiver limits the number of ACK ranges it
remembers and sends in ACK blocks, both to limit the size of ACK
blocks and to avoid resource exhaustion.  After receiving
acknowledgments for an ACK block, the receiver should stop tracking
those acknowledged ACK ranges.  Senders can expect acknowledgments
for most packets, but this protocol does not guarantee receipt of an
acknowledgment for every packet that the receiver processes.

It is possible that retaining many ACK ranges could cause an ACK
block to become too large.  A receiver can discard unacknowledged ACK
Ranges to limit ACK block size, at the cost of increased
retransmissions from the sender.  This is necessary if an ACK block
would be too large to fit in a packet.  Receivers may also limit ACK
block size further to preserve space for other blocks or to limit the
bandwidth that acknowledgments consume.

A receiver must retain an ACK range unless it can ensure that it will
not subsequently accept packets with numbers in that range.
Maintaining a minimum packet number that increases as ranges are
discarded is one way to achieve this with minimal state.

Receivers can discard all ACK ranges, but they must retain the
largest packet number that has been successfully processed, as that
is used to recover packet numbers from subsequent packets.

The following section describes an exemplary approach for determining what
packets to acknowledge in each ACK block.  Though the goal of this
algorithm is to generate an acknowledgment for every packet that is
processed, it is still possible for acknowledgments to be lost.


Limiting Ranges by Tracking ACK Blocks
-------------------------------------------

When a packet containing an ACK block is sent, the Ack Through
field in that block can be saved.  When a packet
containing an ACK block is acknowledged, the receiver can stop
acknowledging packets less than or equal to the Ack Through
field in the sent ACK block.

A receiver that sends only non-ack-eliciting packets, such as ACK
blocks, might not receive an acknowledgment for a long period of
time.  This could cause the receiver to maintain state for a large
number of ACK blocks for a long period of time, and ACK blocks it
sends could be unnecessarily large.  In such a case, a receiver could
send a PING or other small ack-eliciting block occasionally, such as
once per round trip, to elicit an ACK from the peer.

In cases without ACK block loss, this algorithm allows for a minimum
of 1 RTT of reordering.  In cases with ACK block loss and reordering,
this approach does not guarantee that every acknowledgment is seen by
the sender before it is no longer included in the ACK block.  Packets
could be received out of order, and all subsequent ACK blocks
containing them could be lost.  In this case, the loss recovery
algorithm could cause spurious retransmissions, but the sender will
continue making forward progress.


Congestion
----------

I2P transports do not guarantee in-order delivery of I2NP messages.
Therefore, loss of a Data message containing one or more I2NP messages or fragments
does NOT prevent other I2NP messages from being delivered;
there is no head-of-line blocking.
Implementations should continue to send new messages during the loss recovery
phase if the send window allows it.


Retransmission
---------------

A sender should not retain the full contents of a message, to be retransmitted
identically (except for handshake messages, see above).
A sender must assemble messages containing up-to-date information
(ACKs, NACKs, and unacknowledged data) every time it sends a message.
A sender should avoid retransmitting information from messages once they are acknowledged.
This includes messages that are acknowledged after being declared lost,
which can happen in the presence of network reordering.

Window
-------

TBD.
General guidance may be found in [RFC-9002]_.


Connection Migration
=====================

A peer's IP or port may change during the lifetime of a session.
An IP change may be caused by IPv6 temporary address rotation,
ISP-driven periodic IP change, a mobile client transitioning
between WiFi and cellular IPs, or other local network changes.
A port change may be caused by a NAT rebinding after
the previous binding timed out.

A peer's IP or port may appear to change due to various
on- and off-path attacks, including modifying or injecting
packets.

Connection migration is the process by which a new source endpoint
(IP+port) is validated, while preventing changes that are not validated.
This process is a simplified version of that defined in QUIC [RFC-9000]_.
This process is defined only for the data phase of a session.
Migration is not permitted during the handshake. All handshake packets
must be verified to be from the same IP and port as previously
sent and received packets. In other words, a peer's IP and port
must be constant during the handshake.

Threat Model
-------------
(Adapted from QUIC [RFC-9000]_)

Peer Address Spoofing
`````````````````````````
A peer may spoofing its source address to cause an endpoint to send excessive amounts of data to an unwilling host.
If the endpoint sends significantly more data than the spoofing peer,
connection migration might be used to amplify the volume of data that an attacker can generate toward a victim.

On-Path Address Spoofing
`````````````````````````
An on-path attacker could cause a spurious connection migration by copying and forwarding a packet
with a spoofed address such that it arrives before the original packet.
The packet with the spoofed address will be seen to come from a migrating connection,
and the original packet will be seen as a duplicate and dropped.
After a spurious migration, validation of the source address will fail because the entity at the source address
does not have the necessary cryptographic keys to read or respond to the Path Challenge that is sent to it even if it wanted to.

Off-Path Packet Forwarding
````````````````````````````
An off-path attacker that can observe packets might forward copies of genuine packets to endpoints.
If the copied packet arrives before the genuine packet, this will appear as a NAT rebinding.
Any genuine packet will be discarded as a duplicate.
If the attacker is able to continue forwarding packets, it might be able to cause migration to a path via the attacker.
This places the attacker on-path, giving it the ability to observe or drop all subsequent packets.

Privacy Implications
`````````````````````
QUIC [RFC-9000]_ specified changing connection IDs when changing network paths.
Using a stable connection ID on multiple network paths would allow a passive observer to correlate activity between those paths.
An endpoint that moves between networks might not wish to have their activity correlated by any entity other than their peer.
However, QUIC does not encrypt the connection IDs in the header.
SSU2 does do that, so the privacy leak would require the passive observer to also
have access to the network database to get the introduction key required to decrypt the connection ID.
Even with the introduction key, this is not a strong attack, and we do not
change connection IDs after migration in SSU2, as this would be a significant complication.


Initiating Path Validation
---------------------------

During the data phase, peers must check that the source IP and port
of each received data packet. If the IP or port is different than
previously received, AND the packet is not a duplicate packet number,
AND the packet successfully decrypts, the session enters
the path validation phase.

Additionally, a peer must verify that the new IP and port
are valid according to local validation rules
(not blocked, not illegal ports, etc.).
Peers are NOT required to support migration between IPv4 and IPv6,
and may treat a new IP in the other address family as invalid,
since this is not expected behavior and may add significant implementation complexity.
On receiving a packet from an invalid IP/port, an implementation
may simply drop it, or may initiate a path validation with the old IP/port.

Upon entering the path validation phase, take the following steps:

- Start a path validation timeout timer of several seconds,
  or several times the current RTO (TBD)
- Reduce the congestion window to the minimum
- Reduce the PMTU to the minimum (1280)
- Send a data packet containing a Path Challenge block,
  an Address block (containing the new IP/port),
  and, typically, an ACK block, to the new IP and port.
  This packet uses the same connection ID and encryption keys
  as the current session.
  The Path Challenge block data must contain sufficient entropy
  (at least 8 bytes) so that it cannot be spoofed.
- Optionally, also send a Path Challenge to the old IP/port,
  with different block data. See below.
- Start a Path Response timeout timer based on the current
  RTO (typically RTT + a multiple of RTTdev)

While in the path validation phase, the session may continue to
process incoming packets. Whether from the old or new IP/port.
The session may also continue to send and acknowledge data packets.
However, the congestion window and PMTU must remain at the minimum
values during the path validation phase, to prevent
being used for deinal of service attacks by
sending large amounts of traffic to a spoofed address.

An implementation may, but is not required, to attempt to validate
multiple paths simultaneously. This is probably not worth the complexity.
It may, but is not required, to
remember a previous IP/port as being already validated, and to
skip path validation if a peer returns to its previous IP/port.

If a Path Response is received, containing the identical data
sent in the Path Challenge, the Path Validation has succeeded.
The source IP/port of the Path Response message is
not required to be the same as the Path Challenge was sent to.

If a Path Response is not received before the Path Response timer
expires, send another Path Challenge and double the Path Response timer.

If a Path Response is not received before the Path Validation timer
expires, the Path Validation has failed.

Message Contents
--------------------------
The Data messages should contain the following blocks.
Order is not specified except that Padding must be last:

- Path Challenge or Path Response block.
  Path Challenge contains opaque data, recommended 8 bytes minimum.
  Path Response contains the data from the Path Challenge.
- Address block containing the recipient's apparent IP
- DateTime block
- ACK block
- Padding block

It is not recommended to include any other blocks
(for example, I2NP) in the message.

It is allowed to include a Path Challenge block in the message
containing the Path Response, to initiate a validation
in the other direction.

Path Challenge and Path Response blocks are ACK-eliciting.
The Path Challenge will be ACKed by a Data message containing
the Path Response and ACK blocks.
The Path Response should be ACKed by a Data message containing an ACK block.


Routing during Path Validation
-------------------------------
The QUIC specification is not clear on where to send data packets
during path validation - to the old or new IP/port?
There is a balance to be struck between rapidly responding to
IP/port changes, and not sending traffic to spoofed addresses.
Also, spoofed packets must not be allowed to substantially impact
an existing session.
Port-only changes are likely to be caused by NAT rebinding after
an idle period; IP changes could happen during high-traffic phases
in one or both directions.

Strategies are subject to research and refinement.
Possibilities include:

- Not sending data packets to the new IP/port until validated
- Continuing to send data packets to the old IP/port until
  the new IP/port is validated
- Simultaneously revalidating the old IP/port
- Not sending any data until either the old or new IP/port is validated
- Different strategies for port-only change than for IP change
- Different strategies for an IPv6 change in the same /32, likely caused
  by temporary address rotation


Responding to Path Challenge
------------------------------
Upon receiving a Path Challenge, the peer must respond
with a data packet containing a Path Response, with the data
from the Path Challenge.

The Path Response must be sent to the IP/port from which the
Path Challenge was received. This is NOT NECESSARILY
the IP/port that was previously established for the peer.
This ensures that path validation by a peer only succeeds if the path is functional in both directions.
See the Validation after Local Change section below.

Unless the IP/port is different from the previously-known IP/port for the peer,
treat a Path Challenge as a simple ping, and simply respond unconditionally with a Path Response.
The receiver does not keep or change any state based on a received Path Challenge.
If the IP/port is different, a peer must verify that the new IP and port
are valid according to local validation rules
(not blocked, not illegal ports, etc.).
Peers are NOT required to support cross-address-family responses between IPv4 and IPv6,
and may treat a new IP in the other address family as invalid,
since this is not expected behavior.

Unless constrained by congestion control, the Path Response should be sent immediately.
Implementations should take measures to rate limit Path Responses or the bandwidth used
if necessary.

A Path Challenge block generally is accompanied by an Address block in the same message.
If the address block contains a new IP/port, a peer may
validate that IP/port and initiate peer testing of that new IP/port, with
the session peer or any other peer.
If the peer thinks it is firewalled, and only the port changed, this change is probably
due to NAT rebinding, and further peer testing is probably not required.


Successful Path Validation
---------------------------
On successful path validation, the connection is fully migrated to the new IP/port.
On success:

- Exit the path validation phase
- All packets are sent to the new IP and port.
- The restrictions on congestion window and PMTU are removed, and they
  are allowed to increase. Do not simply restore them to the
  old values, as the new path may have different characteristics.
- If the IP changed, set calculated RTT and RTO to initial values.
  Because port-only changes are commonly the result of NAT rebinding or other middlebox activity,
  the peer may instead retain its congestion control state and round-trip estimate in those cases
  instead of reverting to initial values.
- Delete (invalidate) any tokens sent or received for the old IP/port (optional)
- Send a new token block for the new IP/port (optional)


Cancelling Path Validation
---------------------------
While in the path validation phase, any valid, non-duplicate packets
that are received from the old IP/port and are successfully decrypted
will cause Path Validation to be cancelled.
It is important that a cancelled path validation, caused by a spoofed packet,
does not cause a valid session to be terminated or significantly disrupted.

On cancelled path validation:

- Exit the path validation phase
- All packets are sent to the old IP and port.
- The restrictions on congestion window and PMTU are removed, and they
  are allowed to increase, or, optionally, restore the previous values
- Retransmit any data packets that were previously sent to the new IP/port
  to the old IP/port.


Failed Path Validation
---------------------------
It is important that a failed path validation, caused by a spoofed packet,
does not cause a valid session to be terminated or significantly disrupted.

On failed path validation:

- Exit the path validation phase
- All packets are sent to the old IP and port.
- The restrictions on congestion window and PMTU are removed, and they
  are allowed to increase.
- Optionally, start a path validation on the old IP and port.
  If it fails, terminate the session.
- Otherwise, follow standard session timeout and termination rules.
- Retransmit any data packets that were previously sent to the new IP/port
  to the old IP/port.


Validation After Local Change
------------------------------
The above process is defined for peers who receive a packet from
a changed IP/port. However, it may also be initiated in the other direction,
by a peer who detects that his IP or port have changed.
A peer may be able to detect that his local IP changed; however, it is much less
likely to detect that his port changed because of a NAT rebinding.
Therefore, this is optional.

On receiving a path challenge from a peer whose IP or port has changed,
the other peer should initiate a path challenge in the other direction.


Use as Ping/Pong
-----------------
Path Challenge and Path Response blocks may be used at any time as Ping/Pong packets.
Reception of a Path Challenge block does not change any state at the receiver,
unless received from a different IP/port.



Multiple Sessions
==================

Peers should not establish multiple sessions with the same peer,
whether SSU 1 or 2, or with the same or different IP addresses.
However, this could happen, either due to bugs, or a previous
session termination message being lost, or in a race where the
termination message has not arrived yet.

If Bob has an existing session with Alice,
when Bob receives the Session Confirmed from Alice, completing the
handshake and establishing a new session, Bob should:

- Migrate any unsent or unacknowledged outbound I2NP messages from the
  old session to the new one
- Send a termination with reason code 22 on the old session
- Remove the old session and replace it with the new one



Session Termination
=====================

Handshake phase
------------------
Sessions in the handshake phase are generally terminated simply
by timing out, or not responding further. Optionally, they may be terminated
by including a Termination block in the response, but 
most errors are not possible to respond to due to a lack of cryptographic keys.
Even if keys are available for a response including a termination block,
it is usually not worth the CPU to perform the DH for the response.
An exception MAY be a Termination block in a retry message, which
is inexpensive to generate.


Data phase
------------------
Sessions in the data phase are terminated by sending a data
message that includes a Termination block.
This message should also include an ACK block.
It may, if the session has been up long enough that a previously
sent token has expired or is about to expire,
a New Token block.
This message is not ack-eliciting.
When receiving a Termination block with any reason except "Termination Received",
the peer responds with a data message containing a
Termination block with the reason "Termination Received".

After sending or receiving a Termination block,
the session should enter the closing phase for some maximum period of time TBD.
The closing state is necessary to protect against the
packet containing the Termination block being lost,
and packets in-flight in the other direction.
While in the closing phase, there is no requirement to process
any additional received packets.
A session in the closing state sends a packet containing a Termination block in response
to any incoming packet that it attributes to the session.
A sesssion should limit the rate at which it generates packets in
the closing state.  For instance, an session could wait for a
progressively increasing number of received packets or amount of time
before responding to received packets.

To minimize the state that a router
maintains for a closing session, sessions may, but are not required to, send the exact same
packet with the same packet number as-is in response to any received packet.
Note: Allowing retransmission of a termination packet is an
exception to the requirement that a new packet number be used
for each packet. Sending new packet numbers
is primarily of advantage to loss recovery and congestion
control, which are not expected to be relevant for a closed connection.
Retransmitting the final packet requires less state.

After receiving a Termination block with the reason "Termination Received",
the session may exit the closing phase.


Cleanup
------------------
Upon any normal or abnormal termination, routers should
zero-out any in-memory ephemeral data, including handshake ephemeral keys,
symmetric crypto keys, and related information.


MTU
========

Requirements vary, based on whether the published address is shared with SSU 1.
Current SSU 1 IPv4 minimum is 620, which is definitely too small.

The minimum SSU2 MTU is 1280 for both IPv4 and IPv6,
which is the same as specified in [RFC-9000]_.
See below.
By increasing the minimum MTU, 1 KB tunnel messages
and short tunnel build messages will fit in one datagram, greatly reducing the
typical amount of fragmentation. This also allows
an increase in the maximum I2NP message size.
1820-byte streaming messages should fit in two datagrams.

A router must not enable SSU2 or publish an SSU2 address unless
the MTU for that address is at least 1280.

Routers must publish a non-default MTU in each SSU or SSU2 router address.


SSU Address
------------
Shared address with SSU 1, must follow SSU 1 rules.
IPv4: Default and max is 1484. Min is 1292.
(IPv4 MTU + 4) must be a multiple of 16.
IPv6: Must be published, min is 1280 and the max is 1488.
IPv6 MTU must be a multiple of 16.

SSU2 Address
------------
IPv4: Default and max is 1500. Min is 1280.
IPv6: Default and max is 1500. Min is 1280.
No multiple of 16 rules, but should probably be a multiple of 2 at least.

PMTU Discovery
---------------
For SSU 1, current Java I2P performs PMTU discovery by starting with small packets and
gradually increasing the size, or increasing based on received packet size.
This is crude and greatly reduces the efficiency.
Continuing this feature in SSU 2 is TBD.

Recent studies [PMTU]_ suggest that a minimum for IPv4 of 1200 or more would work
for more than 99% of connections. QUIC [RFC-9000]_ requires a minimum IP
packet size of 1280 bytes.

quote [RFC-9000]_:

The maximum datagram size is defined as the largest size of UDP
payload that can be sent across a network path using a single UDP
datagram.  QUIC MUST NOT be used if the network path cannot support a
maximum datagram size of at least 1200 bytes.

QUIC assumes a minimum IP packet size of at least 1280 bytes.  This
is the IPv6 minimum size [IPv6] and is also supported by most modern
IPv4 networks.  Assuming the minimum IP header size of 40 bytes for
IPv6 and 20 bytes for IPv4 and a UDP header size of 8 bytes, this
results in a maximum datagram size of 1232 bytes for IPv6 and 1252
bytes for IPv4.  Thus, modern IPv4 and all IPv6 network paths are
expected to be able to support QUIC.

Note: This requirement to support a UDP payload of 1200 bytes
limits the space available for IPv6 extension headers to 32
bytes or IPv4 options to 52 bytes if the path only supports the
IPv6 minimum MTU of 1280 bytes.  This affects Initial packets
and path validation.

end quote


Handshake Min Size
-------------------------

QUIC requires that Initial datagrams in both directions be at least 1200 bytes,
to prevent amplification attacks. and ensure the PMTU supports it in both directions.

We could require this for Session Request and Session Created,
at substantial cost in bandwidth.
Perhaps we could do this only if we don't have a token,
or after a Retry message is received.
TBD

QUIC requires that Bob send no more than three times the amount of data
received until the client address is validated.
SSU2 meets this requirement inherently, because the Retry message
is about the same size as the Token Request message, and is
smaller than the Session Request message.
Also, the Retry message is only sent once.


Path Message Min Size
-------------------------

QUIC requires that messages containing PATH_CHALLENGE or PATH_RESPONSE blocks be at least 1200 bytes,
to prevent amplification attacks. and ensure the PMTU supports it in both directions.

We could require this as well, at substantial cost in bandwidth.
However, these cases should be rare.
TBD



Max I2NP Message Size
-----------------------

IPv4:
No IP fragmentation is assumed.
IP + datagram header is 28 bytes.
This assumes no IPv4 options.
Max message size is MTU - 28.
Data phase header is 16 bytes and MAC is 16 bytes, totaling 32 bytes.
Payload size is MTU - 60.
Max data phase payload is 1440 for a max 1500 MTU.
Max data phase payload is 1220 for a min 1280 MTU.


IPv6:
No IP fragmentation is allowed.
IP + datagram header is 48 bytes.
This assumes no IPv6 extension headers.
Max message size is MTU - 48.
Data phase header is 16 bytes and MAC is 16 bytes, totaling 32 bytes.
Payload size is MTU - 80.
Max data phase payload is 1420 for a max 1500 MTU.
Max data phase payload is 1200 for a min 1280 MTU.

In SSU 1, the guidelines were a strict maximum of about 32 KB for
a I2NP message based on 64 maximum fragments and a 620 minimum MTU.
Due to overhead for bundled LeaseSets and session keys, the practical limit
at the application level was about 6KB lower, or about 26KB.
The SSU 1 protocol allows for 128 fragments but current implementations
limit it to 64 fragments.

By raising the minimum MTU to 1280, with a data phase payload of
approximately 1200, an SSU 2 message of about 76 KB is possible in 64 fragments
and 152 KB in 128 fragments. This easily allows a maximum of 64 KB.

Due to fragmentation in tunnels, and fragmentation in SSU 2,
the chance of message loss increases exponentially with message size.
We continue to recommend a practical limit of about 10 KB at the
application layer for I2NP datagrams.


Peer Test Process
========================

See Peer Test Security above for an analysis of SSU1 Peer Test and
the goals for SSU2 Peer Test.

.. raw:: html

  {% highlight %}
Alice                     Bob                  Charlie
  1. PeerTest ------------------->
                              Alice RI ------------------->
  2.                          PeerTest ------------------->
  3.                             <------------------ PeerTest
          <---------------- Charlie RI
  4.      <------------------ PeerTest

  5.      <----------------------------------------- PeerTest
  6. PeerTest ----------------------------------------->
  7.      <----------------------------------------- PeerTest
{% endhighlight %}



When rejected by Bob:

.. raw:: html

  {% highlight %}
Alice                     Bob                  Charlie
  1. PeerTest ------------------->
  4.      <------------------ PeerTest (reject)
{% endhighlight %}



When rejected by Charlie:

.. raw:: html

  {% highlight %}
Alice                     Bob                  Charlie
  1. PeerTest ------------------->
                              Alice RI ------------------->
  2.                          PeerTest ------------------->
  3.                             <------------------ PeerTest (reject)
                        (optional: Bob could try another Charlie here)
  4.      <------------------ PeerTest (reject)
{% endhighlight %}


NOTE: RI may be sent either I2NP Database Store messages in I2NP blocks,
or as RI blocks (if small enough). These may be contained in the
same packets as the peer test blocks, if small enough.

Messages 1-4 are in-session using Peer Test blocks in a Data message.
Messages 5-7 are out-of-session using Peer Test blocks in a Peer Test message.

NOTE: As in SSU 1, messages 4 and 5 may arrive in either order.
Message 5 and/or 7 may not be received at all if Alice is firewalled.
When message 5 arrives before message 4,
Alice cannot immediately send message 6, because she does not
yet have Charlie's intro key to encrypt the header.
When message 4 arrives before message 5,
Alice should not immediately send message 6, because she should wait
to see if message 5 arrives without opening the firewall with message 6.


=========   ============    =============
Message     Path            Intro Key    
=========   ============    =============
1           A->B session    in-session   
2           B->C session    in-session   
3           C->B session    in-session   
4           B->A session    in-session   
5           C->A            Alice
6           A->C            Charlie      
7           C->A            Alice     
=========   ============    =============



Versions
------------------
Cross-version peer testing is not supported.
The only allowed version combination is where all peers are version 2.

=========   ===========   =============   =============
Alice/Bob   Bob/Charlie   Alice/Charlie   Supported
=========   ===========   =============   =============
1           1             1               SSU 1
1           1             2               no, use 1/1/1
1           2             1               no, Bob must select a version 1 Charlie
1           2             2               no, Bob must select a version 1 Charlie
2           1             1               no, Bob must select a version 2 Charlie
2           1             2               no, Bob must select a version 2 Charlie
2           2             1               no, use 2/2/2
2           2             2               yes
=========   ===========   =============   =============


Retransmissions
------------------
Messages 1-4 are in-session and are covered by the
data phase ACK and retransmission processes.
Peer Test blocks are ack-eliciting.

Messages 5-7 may be retransmitted, unchanged.


IPv6 Notes
------------------
As in SSU 1, testing of IPv6 addresses is supported,
and Alice-Bob and Alice-Charlie communication may be via IPv6,
if Bob and Charlie indicate support with a 'B' capability in their published IPv6 address.
See Proposal 126 for details.

As in SSU 1 prior to 0.9.50,
Alice sends the request to Bob using an existing session over the transport (IPv4 or IPv6) that she wishes to test.
When Bob receives a request from Alice via IPv4, Bob must select a Charlie that advertises an IPv4 address.
When Bob receives a request from Alice via IPv6, Bob must select a Charlie that advertises an IPv6 address.
The actual Bob-Charlie communication may be via IPv4 or IPv6 (i.e., independent of Alice's address type).
This is NOT the behavior of SSU 1 as of 0.9.50, where mixed IPv4/v6 requests are allowed.



Processing by Bob
-----------------------------
Unlike in SSU 1, Alice specifies the requested test IP and port in message 1.
Bob should validate this IP and port, and reject with code 5 if invalid.
Recommended IP validation is that, for IPv4, it matches Alice's IP,
and for IPv6, at least the first 8 bytes of the IP match.
Port validation should reject privileged ports and ports for well-known protocols.



Results State Machine
-----------------------------
Here we document how Alice may determine the results of a peer test,
based on which messages are received.
SSU2's enhancements provide us the opportunity to fix, improve, and better-document
the peer test result state machine compared to the one in [SSU]_.

For each address type tested (IPv4 or IPv6), the result can be one of
UNKNOWN, OK, FIREWALLED, or SYMNAT.
Additionally, other processing may be done to detect IP or port change,
or an external port different than the internal port.

Problems with the documented SSU state machine:

- We never send message 6 unless we got message 5, so we never know if we're SYMNAT
- If we DID get messages 4 and 7, how could we possibly be SYMNAT
- If the IP did not match but the port did, we aren't SYMNAT, we just changed our IP

So, in contrast to SSU, we recommend waiting several seconds after getting message 4,
then sending message 6 even if message 5 is not received.

A summary of the state machine, based on whether messages 4, 5, and 7 are
received (yes or no), is as follows:

.. raw:: html

  {% highlight %}
4 5 7  Result             Notes
  -----  ------             -----
  n n n  UNKNOWN
  y n n  FIREWALLED           (unless currently SYMNAT)
  n y n  OK                   (unless currently SYMNAT, which is unlikely)
  y y n  OK                   (unless currently SYMNAT, which is unlikely)
  n n y  n/a                  (can't send msg 6)
  y n y  FIREWALLED or SYMNAT (requires sending msg 6 w/o rcv msg 5)
  n y y  n/a                  (can't send msg 6)
  y y y  OK

{% endhighlight %}


A more detailed state machine, with checks of the IP/port received in
the address block of message 7, is below.
One challenge is to determine if you (Alice) are the one symmetric natted, or Charlie is.

Post-processing or additional logic to confirm state transitions by
requiring the same results on two or more peer tests is recommended.

Received IP/port validation and confirmation by two or more tests,
or with the address block in Session Created messages, is also recommended,
but is outside the scope of this specification.


.. raw:: html

  {% highlight %}
If Alice does not get msg 5:
     If Alice does not get msg 4: -> UNKNOWN
     If Alice does not get msg 7: -> UNKNOWN
     If Alice gets msgs 4/7 and IP/port match: -> FIREWALLED
     If Alice gets msgs 4/7 and IP matches, port does not match:
        -> SYMNAT, but needs confirmation with 2nd test
     If Alice gets msgs 4/7 and IP does not match, port matches:
        -> FIREWALLED, address change?
     If Alice gets msgs 4/7 and both IP and port do not match:
        -> SYMNAT, address change?

  If Alice gets msg 5:
     If Alice does not get msg 4: -> OK unless currently SYMNAT, else UNKNOWN
                                     (in SSU2 have to stop here)
     If Alice does not get msg 7: -> OK unless currently SYMNAT, else UNKNOWN
     If Alice gets msgs 4/5/7 and IP/port match: -> OK
     If Alice gets msgs 4/5/7 and IP matches, port does not match:
        -> OK, charlie is probably sym. natted
     If Alice gets msgs 4/5/7 and IP does not match, port matches:
        -> OK, address change?
     If Alice gets msgs 4/5/7 and both IP and port do not match:
        -> OK, address change?

{% endhighlight %}





Relay Process
========================

See Relay Security above for an analysis of SSU1 Relay and
the goals for SSU2 Relay.


.. raw:: html

  {% highlight %}
Alice                         Bob                  Charlie
     lookup Bob RI

     SessionRequest -------------------->
          <------------  SessionCreated
     SessionConfirmed  ----------------->

  1. RelayRequest ---------------------->
                                           Alice RI  ------------>
  2.                                       RelayIntro ----------->
  3.                                  <-------------- RelayResponse
  4.      <-------------- RelayResponse

  5.      <-------------------------------------------- HolePunch
  6. SessionRequest -------------------------------------------->
  7.      <-------------------------------------------- SessionCreated
  8. SessionConfirmed ------------------------------------------>

{% endhighlight %}


When rejected by Bob:

.. raw:: html

  {% highlight %}
Alice                         Bob                  Charlie
     lookup Bob RI

     SessionRequest -------------------->
          <------------  SessionCreated
     SessionConfirmed  ----------------->

  1. RelayRequest ---------------------->
  4.      <-------------- RelayResponse

{% endhighlight %}


When rejected by Charlie:


.. raw:: html

  {% highlight %}
Alice                         Bob                  Charlie
     lookup Bob RI

     SessionRequest -------------------->
          <------------  SessionCreated
     SessionConfirmed  ----------------->

  1. RelayRequest ---------------------->
                                           Alice RI  ------------>
  2.                                       RelayIntro ----------->
  3.                                  <-------------- RelayResponse
  4.      <-------------- RelayResponse

{% endhighlight %}

NOTE: RI may be sent either I2NP Database Store messages in I2NP blocks,
or as RI blocks (if small enough). These may be contained in the
same packets as the ralay blocks, if small enough.

In SSU 1, Charlie's router info contains the IP, port, intro key, relay tag, and expiration of each introducer.

In SSU 2, Charlie's router info contains the router hash, relay tag, and expiration of each introducer.

Alice should reduce the number of round trips required by first
selecting an introducer (Bob) that she already has a connection to.
Second, if none, select an introducer she already has the router info for.

Cross-version relaying should also be supported if possible.
This will facilitate a gradual transition from SSU 1 to SSU 2.
The allowed version combinations are (TODO):

=========   ===========   =============   =============
Alice/Bob   Bob/Charlie   Alice/Charlie   Supported
=========   ===========   =============   =============
1           1             1               SSU 1
1           1             2               no, use 1/1/1
1           2             1               yes?
1           2             2               no, use 1/2/1
2           1             1               yes?
2           1             2               yes?
2           2             1               no, use 2/2/2
2           2             2               yes
=========   ===========   =============   =============


Retransmissions
-----------------
Relay Request, Relay Intro, and Relay Response
are all in-session and are covered by the
data phase ACK and retransmission processes.
Relay Request, Relay Intro, and Relay Response blocks are ack-eliciting.

Note that usually, Charlie will respond immediately to a Relay Intro
with a Relay Response, which should include an ACK block.
In that case, no separate message with an ACK block is required.

Hole punch may be retransmitted, as in SSU 1.

Unlike I2NP messages, the Relay messages do not have unique identifiers,
so duplicates must be detected by the relay state machine, using the nonce.
Implementations may also need to maintain a cache of recently-used nonces,
so that received duplicates may be detected even after the state machine for that nonce has completed.



IPv4/v6
----------
All features of SSU 1 relay are supported, including those documented in
[Prop158]_ and supported as of 0.9.50.
IPv4 and IPv6 introductions are supported.
A Relay Request may be sent over an IPv4 session for an IPv6 introduction,
and a Relay Request may be sent over an IPv6 session for an IPv4 introduction.

Processing by Alice
-----------------------------
Following are differences from SSU 1 and recommendations for SSU 2 implementation.

Introducer Selection
`````````````````````
In SSU 1, introduction is relatively inexpensive, and Alice generally sends Relay Requests to all introducers.
In SSU 2, introduction is more expensive, as a connection must first be established with an introducer.
To minimize introduction latency and overhead, the recommended processing steps are as follows:

- Ignore any introducers that are expired based on the iexp value in the address
- If an SSU2 connection is already established to one or more introducers,
  pick one and send the Relay Request to that introducer only.
- Otherwise, if a Router Info is locally known for one or more introducers,
  pick one and connect to that introducer only.
- Otherwise, lookup the Router Infos for all introducers,
  connect to the introducer whose Router Info is received first.

Response Handling
```````````````````````
In both SSU 1 and SSU 2,
the Relay Response and Hole Punch may be received in either order,
or may not be received at all.

In SSU 1, Alice usually receives the Relay Response (1 RTT)
before the Hole Punch (1 1/2 RTT).
It may not be well-documented in those specifications, but
Alice must receive the Relay Response from Bob before continuing,
to receive Charlie's IP.
If the Hole Punch is received first, Alice will not recognize it,
because it contains no data and the source IP is not recognized.
After receiving the Relay Response, Alice should wait for
EITHER receiving the Hole Punch from Charlie, OR
a short delay (recommended 500 ms) before initiating the handshake with Charlie.

In SSU 2, Alice will usually receive the Hole Punch (1 1/2 RTT)
before the Relay Response (2 RTT).
The SSU 2 Hole Punch is easier to process than in SSU 1, because it is a full
message with defined connection IDs (derived from the relay nonce) and contents including Charlie's IP.
The Relay Response (Data message) and Hole Punch message contain the identical
signed Relay Response block.
Therefore, Alice may initiate the handshake with Charlie after
EITHER receiving the Hole Punch from Charlie, OR receiving the Relay Response from Bob.

The signature verification of the Hole Punch includes the introducer's (Bob's) router hash.
If Relay Requests have been sent to more than one introducer,
there are several options to validate the signature:

- Try each hash to which a request was sent
- Use different nonces for each introducer, and use that to determine which
  introducer this Hole Punch was in response to
- Don't re-validate the signature if the contents are identical
  to that in the Relay Response, if already received
- Don't validate the signature at all

If Charlie is behind a symmetric NAT, his reported port in the Relay Response and Hole Punch
may not be accurate. Therefore, Alice should check the UDP source port of the Hole Punch
message, and use that if it is different than the reported port.


Tag Requests by Bob
------------------------
In SSU 1, only Alice could request a tag, in the Session Request.
Bob could never request a tag, and Alice could not relay for Bob.

In SSU2, Alice generally requests a tag in the Session Request,
but either Alice or Bob may also request a tag in the data phase.
Bob generally is not firewalled after receiving an inbound request,
but it could be after a relay, or Bob's state may change,
or he may request an introducer for the other address type (IPv4/v6).
So, in SSU2, it is possible for both Alice and Bob to simultaneously be relays for the other party.



Published Router Info
=====================

Address Properties
-------------------

The following address properties may be published, unchanged from SSU 1,
including changes in [Prop158]_ supported as of API 0.9.50:

- caps: [B,C,4,6] capabilities

- host: IP (IPv4 or IPv6).
  Shortened IPv6 address (with "::") is allowed.
  May or may not be present if firewalled.
  Host names are not allowed.

- iexp[0-2]: Expiration of this introducer.
  ASCII digits, in seconds since the epoch.
  Only present if firewalled, and introducers are required.
  Optional (even if other properties for this introducer are present).

- ihost[0-2]: Introducer's IP (IPv4 or IPv6).
  Shortened IPv6 address (with "::") is allowed.
  Only present if firewalled, and introducers are required.
  Host names are not allowed.
  SSU address only.

- ikey[0-2]: Introducer's Base 64 introduction key.
  Only present if firewalled, and introducers are required.
  SSU address only.

- iport[0-2]: Introducer's port 1024 - 65535.
  Only present if firewalled, and introducers are required.
  SSU address only.

- itag[0-2]: Introducer's tag 1 - (2**32 - 1)
  ASCII digits.
  Only present if firewalled, and introducers are required.

- key: Base 64 introduction key.

- mtu: Optional. See MTU section above.

- port: 1024 - 65535
  May or may not be present if firewalled.



Published Addresses
-------------------

The published RouterAddress (part of the RouterInfo) will have a
protocol identifier of either "SSU" or "SSU2".

The RouterAddress must contain three options
to indicate SSU2 support:

- s=(Base64 key)
  The current Noise static public key (s) for this RouterAddress.
  Base 64 encoded using the standard I2P Base 64 alphabet.
  32 bytes in binary, 44 bytes as Base 64 encoded,
  little-endian X25519 public key.

- i=(Base64 key)
  The current introduction key for encrypting the headers for this RouterAddress.
  Base 64 encoded using the standard I2P Base 64 alphabet.
  32 bytes in binary, 44 bytes as Base 64 encoded,
  big-endian ChaCha20 key.

- v=2
  The current version (2).
  When published as "SSU", additional support for version 1 is implied.
  Support for future versions will be with comma-separated values,
  e.g. v=2,3
  Implementation should verify compatibility, including multiple
  versions if a comma is present. Comma-separated versions must
  be in numerical order.


Alice must verify that all three options are present and valid
before connecting using the SSU2 protocol.

When published as "SSU" with "s", "i", and "v" options,
and with "host" and "port" options,
the router must accept incoming connections on that host and port
for both SSU and SSU2 protocols, and automatically detect the protocol
version.

When published as "SSU2" with "s", "i", and "v" options,
and with "host" and "port" options,
the router accepts incoming connections on that host and port
for the SSU2 protocol only.

If a router supports both SSU1 and SSU2 connections but
does not implement automatic version detection for incoming connections,
it must advertise both "SSU" and "SSU2" addresses, and include
the SSU2 options in the "SSU2" address only.
The router should set a lower cost value (higher priority)
in the "SSU2" address than the "SSU" address, so SSU2 is preferred.

If multiple SSU2 RouterAddresses (either as "SSU" or "SSU2") are published
in the same RouterInfo (for additional IP addresses or ports),
all addresses specifying the same port must contain the identical SSU2 options and values.
In particular, all must contain the same static key "s" and introduction key "i".


Introducers
```````````
When published as SSU or SSU2 with introducers, the following options are present:

- ih[0-2]=(Base64 hash)
  A router hash for an introducer.
  Base 64 encoded using the standard I2P Base 64 alphabet.
  32 bytes in binary, 44 bytes as Base 64 encoded

- iexp[0-2]: Expiration of this introducer.
  Unchanged from SSU 1.

- itag[0-2]: Introducer's tag 1 - (2**32 - 1)
  Unchanged from SSU 1.

The following options are for SSU only and are not used for SSU2.
In SSU2, Alice gets this information from Charlie's RI instead.

- ihost[0-2]
- ikey[0-2]
- itag[0-2]

A router must not publish host or port in the address when publishing introducers.
A router must publish 4 and/or 6 caps in the address when publishing introducers
to indicate support for IPv4 and/or IPv6.
This is the same as the current practice for recent SSU 1 addresses.

Note: If published as SSU, and there is a mix of SSU 1 and SSU2 introducers,
the SSU 1 introducers should be at the lower indexes and
the SSU2 introducers should be at the higher indexes,
for compatibility with older routers.



Unpublished SSU2 Address
-------------------------

If Alice does not publish her SSU2 address (as "SSU" or "SSU2") for incoming connections,
she must publish a "SSU2" router address containing only her static key and SSU2 version,
so that Bob may validate the key after receiving Alice's RouterInfo in Session Confirmed part 2.

- s=(Base64 key)
  As defined above for published addresses.

- i=(Base64 key)
  As defined above for published addresses.

- v=2
  As defined above for published addresses.

This router address will not contain "host" or "port" options,
as these are not required for outbound SSU2 connections.
The published cost for this address does not strictly matter, as it is inbound only;
however, it may be helpful to other routers if the cost is set higher (lower priority)
than other addresses. The suggested value is 14.

Alice may also simply add the "i" "s" and "v" options to an existing published "SSU" address.



Public Key and IV Rotation
--------------------------

Using the same static keys for NTCP2 and SSU2 is allowed, but not recommended.

Due to caching of RouterInfos, routers must not rotate the static public key or IV
while the router is up, whether in a published address or not. Routers must
persistently store this key and IV for reuse after an immediate restart, so incoming
connections will continue to work, and restart times are not exposed.  Routers
must persistently store, or otherwise determine, last-shutdown time, so that
the previous downtime may be calculated at startup.

Subject to concerns about exposing restart times, routers may rotate this key or IV
at startup if the router was previously down for some time (several days at
least).

If the router has any published SSU2 RouterAddresses (as SSU or SSU2), the
minimum downtime before rotation should be much longer, for example one month,
unless the local IP address has changed or the router "rekeys".

If the router has any published SSU RouterAddresses, but not SSU2 (as SSU or
SSU2) the minimum downtime before rotation should be longer, for example one
day, unless the local IP address has changed or the router "rekeys".  This
applies even if the published SSU address has introducers.

If the router does not have any published RouterAddresses (SSU, SSU2, or
SSU), the minimum downtime before rotation may be as short as two hours, even
if the IP address changes, unless the router "rekeys".

If the router "rekeys" to a different Router Hash, it should generate a new
noise key and intro key as well.

Implementations must be aware that changing the static public key or IV will prohibit
incoming SSU2 connections from routers that have cached an older RouterInfo.
RouterInfo publishing, tunnel peer selection (including both OBGW and IB
closest hop), zero-hop tunnel selection, transport selection, and other
implementation strategies must take this into account.

Intro key rotation is subject to identical rules as key rotation.

Note: The minimum downtime before rekeying may be modified to ensure network
health, and to prevent reseeding by a router down for a moderate amount of
time.




Identity Hiding
```````````````
Deniability is not a goal. See overview above.

Each pattern is assigned properties describing the confidentiality supplied to
the initiator's static public key, and to the responder's static public key.
The underlying assumptions are that ephemeral private keys are secure, and that
parties abort the handshake if they receive a static public key from the other
party which they don't trust.

This section only considers identity leakage through static public key fields
in handshakes.  Of course, the identities of Noise participants might be
exposed through other means, including payload fields, traffic analysis, or
metadata such as IP addresses.

Alice: (8) Encrypted with forward secrecy to an authenticated party.

Bob: (3) Not transmitted, but a passive attacker can check candidates for the
responder's private key and determine whether the candidate is correct.

Bob publishes his static public key in the netdb. Alice may not, but must include it in the RI
sent to Bob.


Packet Guidelines
==========================


Outbound Packet Creation
-----------------------------

Handshake messages (Session Request/Created/Confirmed, Retry) basic steps, in order:

- Create 16 or 32 byte header
- Create payload
- mixHash() the header (except for Retry)
- Encrypt the payload using Noise (except for Retry, use ChaChaPoly with the header as AD)
- Encrypt the header, and for Session Request/Created, the ephemeral key


Data phase messages basic steps, in order:

- Create 16-byte header
- Create payload
- Encrypt the payload using ChaChaPoly using the header as AD
- Encrypt the header



Inbound Packet Handling
-----------------------------

Summary
```````````

Initial processing of all inbound messages:

- Decrypt the first 8 bytes of the header (the Destination Connection ID)
  with the intro key
- Lookup the connection by the Destination Connection ID
- If the connection is found and is in the data phase, go to the
  data phase section
- If the connection is not found, go to the handshake section
- Note: Peer Test and Hole Punch messages may also be looked up
  by the Destination Connection ID created from the test or relay nonce.


Handshake messages (Session Request/Created/Confirmed, Retry, Token Request)
and other out-of-session messages (Peer Test, Hole Punch)
processing:

- Decrypt bytes 8-15 of the header
  (the packet type, version, and net ID) with the intro key. If it is a
  valid Session Request, Token Request, Peer Test, or Hole Punch, continue
- If not a valid message, lookup a pending outbound connection by the packet
  source IP/port, treat the packet as a Session Created or Retry.
  Re-decrypt the first 8 bytes of the header with the correct key,
  and the bytes 8-15 of the header
  (the packet type, version, and net ID). If it is a
  valid Session Created or Retry, continue
- If not a valid message, fail, or queue as a possible out-of-order data phase packet
- For Session Request/Created, Retry, Token Request, Peer Test, and Hole Punch, decrypt bytes 16-31 of the header
- For Session Request/Created, decrypt the ephemeral key
- Validate all header fields, stop if not valid
- mixHash() the header
- For Session Request/Created/Confirmed, decrypt the payload using Noise
- For Retry and data phase, decrypt the payload using ChaChaPoly
- Process the header and payload


Data phase messages processing:

- Decrypt bytes 8-15 of the header
  (the packet type, version, and net ID) with the correct key
- Decrypt the payload using ChaChaPoly using the header as AD
- Process the header and payload


Details
`````````

In SSU 1, inbound packet classification is difficult, because there is no
header to indicate session number. Routers must first match the source IP and port
to an existing peer state, and if not found, attempt multiple decryptions with different
keys to find the appropriate peer state or start a new one.
In the event that the source IP or port for an existing session changes,
possibly due to NAT behavior,
the router may use expensive heuristics to attempt to match the packet to an existing session
and recover the contents.

SSU 2 is designed to minimize the inbound packet classification effort while maintaining
DPI resistance and other on-path threats. The Connection ID number is included in the header
for all message types, and encrypted (obfuscated) using ChaCha20 with a known key and nonce.
Additionally, the message type is also included in the header
(encrypted with header protection to a known key and then obfuscated with ChaCha20)
and may be used for additional classification.
In no case is a trial DH or other asymmetric crypto operation necessary to classify a packet.

For almost all messages from all peers, the ChaCha20 key for the Connection ID encryption is the destination router's
introduction key as published in the netdb.

The only exceptions are the first messages sent from Bob to Alice (Session Created or Retry)
where Alice's introduction key is not yet known to Bob. In these cases, Bob's introduction key
is used as the key.

The protocol is designed to minimize packet classification processing that
might require additional crypto operations in multiple
fallback steps or complex heuristics.
Additionally, the vast majority of received packets will not require
a (possibly expensive) fallback lookup by source IP/port
and a second header decryption.
Only Session Created and Retry (and possibly others TBD) will require
the fallback processing.
If an endpoint changes IP or port after session creation,
the connection ID is still used to lookup the session.
It is never necessary to use heuristics to find the session,
for example by looking for a different session with the same
IP but a different port.


Therefore, the recommended processing steps in the receiver loop logic are:

1) Decrypt the first 8 bytes with ChaCha20 using the local introduction key,
   to recover the Destination Connection ID.
   If the Connection ID matches a current or pending inbound session:

   a) Using the appropriate key, decrypt the header bytes 8-15
      to recover the version, net ID, and message type.
   b) If the message type is Session Confirmed, it is a long header.
      Verify the net ID and protocol version are valid.
      Decrypt the bytes 15-31 of the header with ChaCha20
      using the local intro key. Then MixHash() the
      decrypted 32 byte header and decrypt the message with Noise.
   c) If the message type is valid but not Session Confirmed,
      it is a short header.
      Verify the net ID and protocol version are valid.
      decrypt the rest of the message with ChaCha20/Poly1305
      using the session key, using the decrypted 16-byte header
      as the AD.
   d) (optional) If connection ID is a pending inbound session
      awaiting a Session Confirmed message,
      but the net ID, protocol, or message type is not valid,
      it could be a Data message received out-of-order before the
      Session Confirmed, so the data phase header protection keys are not yet known,
      and the header bytes 8-15 were incorrectly decrypted.
      Queue the message, and attempt to decrypt it once the
      Session Confirmed message is received.
   e) If b) or c) fails, drop the message.

2) If the connection ID does not match a current session:
   Check the plaintext header at bytes 8-15 are valid
   (without doing any header protection operation).
   Verify the net ID and protocol version are valid, and
   the message type is Session Request, or other message type
   allowed out-of-session (TBD).

   a) If all is valid and the message type is Session Request,
      decrypt bytes 16-31 of the header and the 32-byte X value
      with ChaCha20 using the local intro key.

   - If the token at header bytes 24-31 is accepted,
     then MixHash() the decrypted 32 byte header and
     decrypt the message with Noise.
     Send a Session Created in response.
   - If the token is not accepted, send a Retry message to the
     source IP/port with a token. Do not attempt to
     decrypt the message with Noise to avoid DDoS attacks.

   b) If the message type is some other message that is valid
      out-of-session, presumably with a short header,
      decrypt the rest of the message with ChaCha20/Poly1305
      using the intro key, and using the decrypted 16-byte header
      as the AD. Process the message.
   c) If a) or b) fails, go to step 3)


3) Look up a pending outbound session by the source IP/port of the packet.

   a) If found, re-decrypt the first 8 bytes with ChaCha20 using Bob's introduction key
      to recover the Destination Connection ID.
   b) If the connection ID matches the pending session:
      Using the correct key, decrypt bytes 8-15 of the header
      to recover the version, net ID, and message type.
      Verify the net ID and protocol version are valid, and
      the message type is Session Created or Retry, or other message type
      allowed out-of-session (TBD).

   - If all is valid and the message type is Session Created,
     decrypt the next 16 bytes of the header and the 32-byte Y value
     with ChaCha20 using Bob's intro key.
     Then MixHash() the decrypted 32 byte header and
     decrypt the message with Noise.
     Send a Session Confirmed in response.
   - If all is valid and the message type is Retry,
     decrypt bytes 16-31 of the header
     with ChaCha20 using Bob's intro key.
     Decrypt and validate the message using ChaCha20/Poly1305 using
     TBD as the key and TBD as the nonce and the decrypted 32-byte header as the AD.
     Resend a Session Request with the received token in response.
   - If the message type is some other message that is valid
     out-of-session, presumably with a short header,
     decrypt the rest of the message with ChaCha20/Poly1305
     using the intro key, and using the decrypted 16-byte header
     as the AD. Process the message.

    c) If a pending outbound session is not found,
       or the connection ID does not match the pending session, drop the message,
       unless the port is shared with SSU 1.

4) If running SSU 1 on the same port, attempt to process the message as an SSU 1 packet.


Error Handling
```````````````
In general, a session (in the handshake or data phase) should never be destroyed
after receiving a packet with an unexpected message type. This prevents
packet injection attacks. These packets will also commonly be received
after retransmission of a handshake packet, when the header decryption keys
are no longer valid.

In most cases, simply drop the packet. An implementation may, but is not required to,
retransmit the previously-sent packet (handshake message or ACK 0) in response.

After sending Session Created as Bob, unexpected packets are commonly Data packets
that cannot be decrypted because the Session Confirmed packets were lost or out-of-order.
Queue the packets and attempt to decrypt them after receiving the Session Confirmed packets.

After receiving Session Confirmed as Bob, unexpected packets are commonly retransmitted
Session Confirmed packets, because the ACK 0 of the Sesssion Confirmed was lost.
The unexpected packets may be dropped.
An implementation may, but is not required to, send a Data packet containing an ACK block in response.


Notes
-------

For Session Created and Session Confirmed, implementations must carefully validate
all decrypted header fields (Connection IDs, packet number, packet type, version, id, frag, and flags)
BEFORE calling mixHash() on the header and attempting to decrypt the
payload with Noise AEAD. If the Noise AEAD decryption fails, no further processing
may be done, because mixHash() will have corrupted the handshake state,
unless an implementation stores and "backs out" the hash state.


Version Detection
--------------------

It may not be possible to efficiently detect if incoming packets are version 1 or 2 on the same inbound port.
The steps above may make sense to do before SSU 1 processing, to avoid attempting trial DH operations
using both protocol versions.

TBD if required.


Recommended Constants
=======================

- Outbound handshake retransmission timeout: 1.25 seconds, with exponential backoff
  (retransmissions at 1.25, 3.75, and 8.75 seconds)
- Total outbound handshake timeout: 15 seconds
- Inbound handshake retransmission timeout: 1 second, with exponential backoff
  (retransmissions at 1, 3, and 7 seconds)
- Total inbound handshake timeout: 12 seconds
- Timeout after sending retry: 9 seconds
- ACK delay: max(10, min(rtt/6, 150)) ms
- Immediate ACK delay: min(rtt/16, 5) ms
- Max ACK ranges: 256?
- Max ACK depth: 512?
- Padding distribution: 0-15 bytes, or greater
- Data phase minimum retransmission timeout: 1 second, as in [RFC-6298]_
- See also [RFC-6298]_ for additional guidance on retransmission timers for the data phase.


Packet Overhead Analysis
=========================

Assumes IPv4, not including extra padding, not including IP and UDP header sizes.
Padding is mod-16 padding for SSU 1 only.

SSU 1

==================   ===========   =====   ======  =======  ======  =====
Message              Header+MAC    Keys    Data    Padding  Total   Notes
==================   ===========   =====   ======  =======  ======  =====
Session Request      40            256        5      3       304    Incl. extended options
Session Created      37            256       79      1       336    Incl. 64 byte Ed25519 sig
Session Confirmed    37                     462     13       512    Incl. 391 byte ident and 64 byte sig
Data (RI)            37                    1014             1051    Incl. 5 byte I2NP header, 1000 byte RI
Data (1 full msg)    37                      14               51    Incl. 5 byte I2NP header
Total                                                       2254
==================   ===========   =====   ======  =======  ======  =====


SSU 2

==================   ===========   =====   ======  =======  ======  =====
Message              Header+MACs   Keys    Data    Padding  Total   Notes
==================   ===========   =====   ======  =======  ======  =====
Session Request      48             32        7               87    DateTime block
Session Created      48             32       16               96    DateTime, Address blocks
Session Confirmed    48             32     1005             1085    1000 byte compressed RI block
Data (1 full msg)    32                      14               46
Total                                                       1314
==================   ===========   =====   ======  =======  ======  =====


Issues and Future Work
======================

Tokens
------

We specify above that the token must be a randomly-generated 8 byte value,
not generate an opaque value such as a hash or HMAC of a server secret
and the IP, port, due to reuse attacks.
However, this requires temporary and (optionally) persistent storage of
delivered tokens.
[WireGuard]_ uses a 16-byte HMAC of a server secret and IP address,
and the server secret rotates every two minutes.
We should investigate something similar, with a longer server secret lifetime.
If we embed a timestamp in the token, that may be a solution, but
an 8-byte token may not be large enough for that.



References
==========

.. [Common]
    {{ spec_url('common-structures') }}

.. [ECIES]
    {{ site_url('docs/spec/ecies', True) }}

.. [NetDB]
    {{ site_url('docs/how/network-database', True) }}

.. [NOISE]
    https://noiseprotocol.org/noise.html

.. [Nonces]
    https://eprint.iacr.org/2019/624.pdf

.. [NTCP]
    {{ site_url('docs/transport/ntcp', True) }}

.. [NTCP2]
    {{ site_url('docs/spec/ntcp2', True) }}

.. [PMTU]
    https://aura.abdn.ac.uk/bitstream/handle/2164/11693/tma2018_paper57.pdf

.. [Prop104]
    {{ proposal_url('104') }}

.. [Prop109]
    {{ proposal_url('109') }}

.. [Prop158]
    {{ proposal_url('158') }}

.. [Prop159]
    {{ proposal_url('159') }}

.. [RFC-2104]
    https://tools.ietf.org/html/rfc2104

.. [RFC-3449]
    https://tools.ietf.org/html/rfc3449

.. [RFC-3526]
    https://tools.ietf.org/html/rfc3526

.. [RFC-5681]
    https://tools.ietf.org/html/rfc3681

.. [RFC-5869]
    https://tools.ietf.org/html/rfc5869

.. [RFC-6151]
    https://tools.ietf.org/html/rfc6151

.. [RFC-6298]
    https://tools.ietf.org/html/rfc6298

.. [RFC-6437]
    https://tools.ietf.org/html/rfc6437

.. [RFC-7539]
    https://tools.ietf.org/html/rfc7539

.. [RFC-7748]
    https://tools.ietf.org/html/rfc7748

.. [RFC-7905]
    https://tools.ietf.org/html/rfc7905

.. [RFC-9000]
    https://datatracker.ietf.org/doc/html/rfc9000

.. [RFC-9001]
    https://datatracker.ietf.org/doc/html/rfc9001

.. [RFC-9002]
    https://datatracker.ietf.org/doc/html/rfc9002

.. [RouterAddress]
    {{ ctags_url('RouterAddress') }}

.. [RouterIdentity]
    {{ ctags_url('RouterIdentity') }}

.. [SigningPublicKey]
    {{ ctags_url('SigningPublicKey') }}

.. [SSU]
    {{ site_url('docs/transport/ssu', True) }}

.. [STS]
    Diffie, W.; van Oorschot P. C.; Wiener M. J., Authentication and
    Authenticated Key Exchanges

.. [Ticket1112]
    https://{{ i2pconv('trac.i2p2.i2p') }}/ticket/1112

.. [Ticket1849]
    https://{{ i2pconv('trac.i2p2.i2p') }}/ticket/1849

.. [WireGuard]
    https://www.wireguard.com/protocol/
