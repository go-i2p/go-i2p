===============================
Common structures Specification
===============================
.. meta::
    :category: Design
    :lastupdated: 2025-06
    :accuratefor: 0.9.67

.. contents::


This document describes some data types common to all I2P protocols, like
[I2NP]_, [I2CP]_, [SSU]_, etc.


Common type specification
=========================

.. _type-Integer:

Integer
-------

Description
```````````
Represents a non-negative integer.

Contents
````````
1 to 8 bytes in network byte order (big endian) representing an unsigned integer.

.. _type-Date:

Date
----

Description
```````````
The number of milliseconds since midnight on January 1, 1970 in the GMT timezone.
If the number is 0, the date is undefined or null.

Contents
````````
8 byte Integer_

.. _type-String:

String
------

Description
```````````
Represents a UTF-8 encoded string.

Contents
````````
1 or more bytes where the first byte is the number of bytes (not characters!)
in the string and the remaining 0-255 bytes are the non-null terminated UTF-8
encoded character array.  Length limit is 255 bytes (not characters). Length
may be 0.

.. _type-PublicKey:

PublicKey
---------

Description
```````````
This structure is used in ElGamal or other asymmetric encryption, representing only the exponent,
not the primes, which are constant and defined in the cryptography
specification [ELGAMAL]_.
Other encryption schemes are in the process of being defined, see the table below.

Contents
````````
Key type and length are inferred from context or are specified in the Key
Certificate of a Destination or RouterInfo, or the fields in a LeaseSet2_ or other data structure.
The default type is ElGamal.  As of release
0.9.38, other types may be supported, depending on context.
Keys are big-endian unless otherwise noted.

X25519 keys are supported in Destinations and LeaseSet2 as of release 0.9.44.
X25519 keys are supported in RouterIdentities as of release 0.9.48.



================    ================= ======  =====
 Type                 Length (bytes)  Since   Usage
================    ================= ======  =====
ElGamal                      256              Deprecated for Router Identities as of 0.9.58; use for Destinations, as the public key field is unused there; discouraged for leasesets
P256                          64       TBD    Reserved, see proposal 145
P384                          96       TBD    Reserved, see proposal 145
P521                         132       TBD    Reserved, see proposal 145
X25519                        32      0.9.38  Little-endian. See [ECIES]_ and [ECIES-ROUTERS]_
MLKEM512_X25519               32      0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM768_X25519               32      0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM1024_X25519              32      0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM512                     800      0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM768                    1184      0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM1024                   1568      0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM512_CT                  768      0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM768_CT                 1088      0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM1024_CT                1568      0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
================    ================= ======  =====

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/PublicKey.html

.. _type-PrivateKey:

PrivateKey
----------

Description
```````````
This structure is used in ElGamal or other asymmetric decryption, representing only the exponent,
not the primes which are constant and defined in the cryptography specification
[ELGAMAL]_.
Other encryption schemes are in the process of being defined, see the table below.

Contents
````````
Key type and length are inferred from context or are stored separately
in a data structure or a private key file.
The default type is ElGamal.  As of release
0.9.38, other types may be supported, depending on context.
Keys are big-endian unless otherwise noted.

================    ================== ======  =====
 Type                  Length (bytes)  Since   Usage
================    ================== ======  =====
ElGamal                      256               Deprecated for Router Identities as of 0.9.58; use for Destinations, as the public key field is unused there; discouraged for leasesets
P256                          32        TBD    Reserved, see proposal 145
P384                          48        TBD    Reserved, see proposal 145
P521                          66        TBD    Reserved, see proposal 145
X25519                        32       0.9.38  Little-endian. See [ECIES]_ and [ECIES-ROUTERS]_
MLKEM512_X25519               32       0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM768_X25519               32       0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM1024_X25519              32       0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM512                    1632       0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM768                    2400       0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
MLKEM1024                   3168       0.9.67  See [ECIES-HYBRID]_, for handshakes only, not for Leasesets, RIs or Destinations
================    ================== ======  =====

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/PrivateKey.html

.. _type-SessionKey:

SessionKey
----------

Description
```````````
This structure is used for symmetric AES256 encryption and decryption.

Contents
````````
32 bytes

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/SessionKey.html

.. _type-SigningPublicKey:

SigningPublicKey
----------------

Description
```````````
This structure is used for verifying signatures.

Contents
````````
Key type and length are inferred from context or are specified in the Key
Certificate of a Destination.  The default type is DSA_SHA1.  As of release
0.9.12, other types may be supported, depending on context.

======================  ==============  ======  =====
         Type           Length (bytes)  Since   Usage
======================  ==============  ======  =====
DSA_SHA1                     128                Deprecated for Router Identities as of 09.58; discouraged for Destinations
ECDSA_SHA256_P256             64        0.9.12  Deprecated Older Destinations
ECDSA_SHA384_P384             96        0.9.12  Deprecated Rarely used for Destinations
ECDSA_SHA512_P521            132        0.9.12  Deprecated Rarely used for Destinations
RSA_SHA256_2048              256        0.9.12  Deprecated Offline signing, never used for Router Identities or Destinations
RSA_SHA384_3072              384        0.9.12  Deprecated Offline signing, never used for Router Identities or Destinations
RSA_SHA512_4096              512        0.9.12  Offline signing, never used for Router Identities or Destinations
EdDSA_SHA512_Ed25519          32        0.9.15  Recent Router Identities and Destinations
EdDSA_SHA512_Ed25519ph        32        0.9.25  Offline signing, never used for Router Identities or Destinations
RedDSA_SHA512_Ed25519         32        0.9.39  For Destinations and encrypted leasesets only, never used for Router Identities
======================  ==============  ======  =====

Notes
`````
* When a key is composed of two elements (for example points X,Y), it is
  serialized by padding each element to length/2 with leading zeros if
  necessary.

* All types are Big Endian, except for EdDSA and RedDSA, which are stored and transmitted
  in a Little Endian format.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/SigningPublicKey.html

.. _type-SigningPrivateKey:

SigningPrivateKey
-----------------

Description
```````````
This structure is used for creating signatures.

Contents
````````
Key type and length are specified when created.  The default type is DSA_SHA1.
As of release 0.9.12, other types may be supported, depending on context.

======================  ==============  ======  =====
         Type           Length (bytes)  Since   Usage
======================  ==============  ======  =====
DSA_SHA1                      20                Deprecated for Router Identities as of 09.58; discouraged for Destinations
ECDSA_SHA256_P256             32        0.9.12  Deprecated Older Destinations
ECDSA_SHA384_P384             48        0.9.12  Deprecated Rarely used for Destinations
ECDSA_SHA512_P521             66        0.9.12  Deprecated Rarely used for Destinations
RSA_SHA256_2048              512        0.9.12  Deprecated Offline signing, never used for Router Identities or Destinations
RSA_SHA384_3072              768        0.9.12  Deprecated Offline signing, never used for Router Identities or Destinations
RSA_SHA512_4096             1024        0.9.12  Offline signing, never used for Router Identities or Destinations
EdDSA_SHA512_Ed25519          32        0.9.15  Recent Router Identities and Destinations
EdDSA_SHA512_Ed25519ph        32        0.9.25  Offline signing, never used for Router Identities or Destinations
RedDSA_SHA512_Ed25519         32        0.9.39  For Destinations and encrypted leasesets only, never used for Router Identities
======================  ==============  ======  =====

Notes
`````
* When a key is composed of two elements (for example points X,Y), it is
  serialized by padding each element to length/2 with leading zeros if
  necessary.

* All types are Big Endian, except for EdDSA and RedDSA, which are stored and transmitted
  in a Little Endian format.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/SigningPrivateKey.html

.. _type-Signature:

Signature
---------

Description
```````````
This structure represents the signature of some data.

Contents
````````
Signature type and length are inferred from the type of key used.  The default
type is DSA_SHA1.  As of release 0.9.12, other types may be supported,
depending on context.

======================  ==============  ======  =====
         Type           Length (bytes)  Since   Usage
======================  ==============  ======  =====
DSA_SHA1                      40                Deprecated for Router Identities as of 09.58; discouraged for Destinations
ECDSA_SHA256_P256             64        0.9.12  Deprecated Older Destinations
ECDSA_SHA384_P384             96        0.9.12  Deprecated Rarely used for Destinations
ECDSA_SHA512_P521            132        0.9.12  Deprecated Rarely used for Destinations
RSA_SHA256_2048              256        0.9.12  Deprecated Offline signing, never used for Router Identities or Destinations
RSA_SHA384_3072              384        0.9.12  Deprecated Offline signing, never used for Router Identities or Destinations
RSA_SHA512_4096              512        0.9.12  Offline signing, never used for Router Identities or Destinations
EdDSA_SHA512_Ed25519          64        0.9.15  Recent Router Identities and Destinations
EdDSA_SHA512_Ed25519ph        64        0.9.25  Offline signing, never used for Router Identities or Destinations
RedDSA_SHA512_Ed25519         64        0.9.39  For Destinations and encrypted leasesets only, never used for Router Identities
======================  ==============  ======  =====

Notes
`````
* When a signature is composed of two elements (for example values R,S), it is
  serialized by padding each element to length/2 with leading zeros if
  necessary.

* All types are Big Endian, except for EdDSA and RedDSA, which are stored and transmitted
  in a Little Endian format.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/Signature.html

.. _type-Hash:

Hash
----

Description
```````````
Represents the SHA256 of some data.

Contents
````````
32 bytes

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/Hash.html

.. _type-SessionTag:

Session Tag
-----------

Note: Session Tags for ECIES-X25519 destinations (ratchet) and ECIES-X25519 routers
are 8 bytes. See [ECIES]_ and [ECIES-ROUTERS]_.

Description
```````````
A random number

Contents
````````
32 bytes

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/SessionTag.html

.. _type-TunnelId:

TunnelId
--------

Description
```````````
Defines an identifier that is unique to each router in a tunnel.  A Tunnel ID
is generally greater than zero; do not use a value of zero except in special
cases.

Contents
````````
4 byte Integer_

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/TunnelId.html

.. _type-Certificate:

Certificate
-----------

Description
```````````
A certificate is a container for various receipts or proof of works used
throughout the I2P network.

Contents
````````
1 byte Integer_ specifying certificate type, followed by a 2 byte Integer_
specifying the size of the certificate payload, then that many bytes.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+-//
  |type| length  | payload
  +----+----+----+----+----+-//

  type :: `Integer`
          length -> 1 byte

          case 0 -> NULL
          case 1 -> HASHCASH
          case 2 -> HIDDEN
          case 3 -> SIGNED
          case 4 -> MULTIPLE
          case 5 -> KEY

  length :: `Integer`
            length -> 2 bytes

  payload :: data
             length -> $length bytes
{% endhighlight %}

Notes
`````
* For `Router Identities`_, the Certificate is always NULL through version
  0.9.15. As of 0.9.16, a Key Certificate is used to specify the
  key types. As of 0.9.48, X25519 encryption public key types
  are allowed. See below.

* For `Garlic Cloves`_, the Certificate is always NULL, no others are currently
  implemented.

* For `Garlic Messages`_, the Certificate is always NULL, no others are
  currently implemented.

* For `Destinations`_, the Certificate may be non-NULL. As of 0.9.12, a Key
  Certificate may be used to specify the signing public key type. See below.

* Implementers are cautioned to prohibit excess data in Certificates.
  The appropriate length for each certificate type should be enforced.

.. _Router Identities: #struct_RouterIdentity
.. _Garlic Cloves: {{ site_url('docs/spec/i2np') }}#struct_GarlicClove
.. _Garlic Messages: {{ site_url('docs/spec/i2np') }}#msg_Garlic
.. _Destinations: #struct_Destination

Certificate Types
`````````````````
The following certificate types are defined:

========  =========  ==============  ============  =====
Type      Type Code  Payload Length  Total Length  Notes
========  =========  ==============  ============  =====
Null          0             0              3
HashCash      1          varies         varies     Deprecated, unused. Payload contains an ASCII colon-separated hashcash string.
Hidden        2             0              3       Deprecated, unused. Hidden routers generally do not announce that they are hidden.
Signed        3         40 or 72       43 or 75    Deprecated, unused. Payload contains a 40-byte DSA signature,
                                                   optionally followed by the 32-byte Hash of the signing Destination.
Multiple      4          varies         varies     Deprecated, unused. Payload contains multiple certificates.
Key           5             4+             7+      Since 0.9.12. See below for details.
========  =========  ==============  ============  =====


Key Certificates
````````````````
Key certificates were introduced in release 0.9.12.  Prior to that release, all
PublicKeys were 256-byte ElGamal keys, and all SigningPublicKeys were 128-byte
DSA-SHA1 keys.  A key certificate provides a mechanism to indicate the type of
the PublicKey and SigningPublicKey in the Destination or RouterIdentity, and to
package any key data in excess of the standard lengths.

By maintaining exactly 384 bytes before the certificate, and putting any excess
key data inside the certificate, we maintain compatibility for any software
that parses Destinations and Router Identities.

The key certificate payload contains:

==================================  ======
              Data                  Length
==================================  ======
Signing Public Key Type (Integer_)    2
Crypto Public Key Type (Integer_)     2
Excess Signing Public Key Data        0+
Excess Crypto Public Key Data         0+
==================================  ======

Warning: The key type order is the opposite of what you may expect;
the Signing Public Key Type is first.


The defined Signing Public Key types are:

======================  ===========  =======================  ======  =====
        Type             Type Code   Total Public Key Length  Since   Usage
======================  ===========  =======================  ======  =====
DSA_SHA1                     0                  128           0.9.12  Deprecated for Router Identities as of 0.9.58; discouraged for Destinations
ECDSA_SHA256_P256            1                   64           0.9.12  Deprecated Older Destinations
ECDSA_SHA384_P384            2                   96           0.9.12  Deprecated Rarely if ever used for Destinations
ECDSA_SHA512_P521            3                  132           0.9.12  Deprecated Rarely if ever used for Destinations
RSA_SHA256_2048              4                  256           0.9.12  Deprecated Offline only; never used in Key Certificates for Router Identities or Destinations
RSA_SHA384_3072              5                  384           0.9.12  Deprecated Offline only; never used in Key Certificates for Router Identities or Destinations
RSA_SHA512_4096              6                  512           0.9.12  Offline only; never used in Key Certificates for Router Identities or Destinations
EdDSA_SHA512_Ed25519         7                   32           0.9.15  Recent Router Identities and Destinations
EdDSA_SHA512_Ed25519ph       8                   32           0.9.25  Offline only; never used in Key Certificates for Router Identities or Destinations
reserved  (GOST)             9                   64                   Reserved, see [Prop134]_
reserved  (GOST)            10                  128                   Reserved, see [Prop134]_
RedDSA_SHA512_Ed25519       11                   32           0.9.39  For Destinations and encrypted leasesets only; never used for Router Identities
reserved  (MLDSA)           12                                        Reserved, see [Prop169]_
reserved  (MLDSA)           13                                        Reserved, see [Prop169]_
reserved  (MLDSA)           14                                        Reserved, see [Prop169]_
reserved  (MLDSA)           15                                        Reserved, see [Prop169]_
reserved  (MLDSA)           16                                        Reserved, see [Prop169]_
reserved  (MLDSA)           17                                        Reserved, see [Prop169]_
reserved  (MLDSA)           18                                        Reserved, see [Prop169]_
reserved  (MLDSA)           19                                        Reserved, see [Prop169]_
reserved  (MLDSA)           20                                        Reserved, see [Prop169]_
reserved                65280-65534                                   Reserved for experimental use
reserved                   65535                                      Reserved for future expansion
======================  ===========  =======================  ======  =====

The defined Crypto Public Key types are:

================    ===========  ======================= ======  =====
  Type              Type Code    Total Public Key Length Since   Usage
================    ===========  ======================= ======  =====
ElGamal                  0                 256                   Deprecated for Router Identities as of 0.9.58; use for Destinations, as the public key field is unused there
P256                     1                  64                   Reserved, see proposal 145
P384                     2                  96                   Reserved, see proposal 145
P521                     3                 132                   Reserved, see proposal 145
X25519                   4                  32           0.9.38  See [ECIES]_ and proposal 156
MLKEM512_X25519          5                  32           0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM768_X25519          6                  32           0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
MLKEM1024_X25519         7                  32           0.9.67  See [ECIES-HYBRID]_, for Leasesets only, not for RIs or Destinations
reserved  (NONE)       255                                       Reserved, see [Prop169]_
reserved            65280-65534                                  Reserved for experimental use
reserved               65535                                     Reserved for future expansion
================    ===========  ======================= ======  =====

When a Key Certificate is not present, the preceeding 384 bytes in the
Destination or RouterIdentity are defined as the 256-byte ElGamal PublicKey
followed by the 128-byte DSA-SHA1 SigningPublicKey.  When a Key Certificate is
present, the preceeding 384 bytes are redefined as follows:

* Complete or first portion of Crypto Public Key

* Random padding if the total lengths of the two keys are less than 384 bytes

* Complete or first portion of Signing Public Key

The Crypto Public Key is aligned at the start and the Signing Public Key is
aligned at the end.  The padding (if any) is in the middle.  The lengths and
boundaries of the initial key data, the padding, and the excess key data
portions in the certificates are not explicitly specified, but are derived from
the lengths of the specified key types.  If the total lengths of the Crypto and
Signing Public Keys exceed 384 bytes, the remainder will be contained in the
Key Certificate.  If the Crypto Public Key length is not 256 bytes, the method
for determining the boundary between the two keys is to be specified in a
future revision of this document.

Example layouts using an ElGamal Crypto Public Key and the Signing Public Key
type indicated:

======================  ==============  ===============================
   Signing Key Type     Padding Length  Excess Signing Key Data in Cert
======================  ==============  ===============================
DSA_SHA1                       0                        0
ECDSA_SHA256_P256             64                        0
ECDSA_SHA384_P384             32                        0
ECDSA_SHA512_P521              0                        4
RSA_SHA256_2048                0                      128
RSA_SHA384_3072                0                      256
RSA_SHA512_4096                0                      384
EdDSA_SHA512_Ed25519          96                        0
EdDSA_SHA512_Ed25519ph        96                        0
======================  ==============  ===============================

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/Certificate.html

Notes
`````

* Implementers are cautioned to prohibit excess data in Key Certificates.
  The appropriate length for each certificate type should be enforced.

* A KEY certificate with types 0,0 (ElGamal,DSA_SHA1) is allowed but discouraged.
  It is not well-tested and may cause issues in some implementations.
  Use a NULL certificate in the canonical representation of a
  (ElGamal,DSA_SHA1) Destination or RouterIdentity, which will be 4 bytes shorter
  than using a KEY certificate.


.. _type-Mapping:

Mapping
-------

Description
```````````
A set of key/value mappings or properties

Contents
````````
A 2-byte size Integer followed by a series of String=String; pairs.

WARNING: Most uses of Mapping are in signed structures, where the
Mapping entries must be sorted by key, so the signature is immutable.
Failure to sort by key will result in signature failures!


.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |  size   | key_string (len + data)| =  |
  +----+----+----+----+----+----+----+----+
  | val_string (len + data)     | ;  | ...
  +----+----+----+----+----+----+----+
  size :: `Integer`
          length -> 2 bytes
          Total number of bytes that follow

  key_string :: `String`
                A string (one byte length followed by UTF-8 encoded characters)

  = :: A single byte containing '='

  val_string :: `String`
                A string (one byte length followed by UTF-8 encoded characters)

  ; :: A single byte containing ';'
{% endhighlight %}

Notes
`````
* The encoding isn't optimal - we either need the '=' and ';' characters, or
  the string lengths, but not both

* Some documentation says that the strings may not include '=' or ';' but this
  encoding supports them

* Strings are defined to be UTF-8 but in the current implementation, I2CP uses
  UTF-8 but I2NP does not. For example, UTF-8 strings in a RouterInfo options
  mapping in a I2NP Database Store Message will be corrupted.

* The encoding allows duplicate keys, however in any usage where the mapping is
  signed, duplicates may cause a signature failure.

* Mappings contained in I2NP messages (e.g. in a RouterAddress or RouterInfo)
  must be sorted by key so that the signature will be invariant. Duplicate keys
  are not allowed.

* Mappings contained in an `I2CP SessionConfig`_ must be sorted by key so that
  the signature will be invariant. Duplicate keys are not allowed.

* The sort method is defined as in Java String.compareTo(), using the Unicode
  value of the characters.

* While it is application-dependent, keys and values are generally
  case-sensitive.

* Key and value string length limits are 255 bytes (not characters) each, plus
  the length byte. Length byte may be 0.

* Total length limit is 65535 bytes, plus the 2 byte size field, or 65537
  total.

.. _I2CP SessionConfig: {{ site_url('docs/spec/i2cp') }}#struct_SessionConfig

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/DataHelper.html


Common structure specification
==============================

.. _struct-KeysAndCert:

KeysAndCert
-----------

Description
```````````
An encryption public key, a signing public key, and a certificate, used as
either a RouterIdentity or a Destination.

Contents
````````
A PublicKey_ followed by a SigningPublicKey_ and then a Certificate_.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | public_key                            |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | padding (optional)                    |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | signing_key                           |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | certificate                           |
  +----+----+----+-//

  public_key :: `PublicKey` (partial or full)
                length -> 256 bytes or as specified in key certificate

  padding :: random data
             length -> 0 bytes or as specified in key certificate
             public_key length + padding length + signing_key length == 384 bytes

  signing__key :: `SigningPublicKey` (partial or full)
                  length -> 128 bytes or as specified in key certificate

  certificate :: `Certificate`
                 length -> >= 3 bytes

  total length: 387+ bytes
{% endhighlight %}


Padding Generation Guidelines
`````````````````````````````````
These guidelines were proposed in Proposal 161 and implemented in API version 0.9.57.
These guidelines are backward-compatible with all versions since 0.6 (2005).
See Proposal 161 for background and further information.

For any currently-used combination of key types other than ElGamal + DSA-SHA1,
padding will be present. Additionally, for destinations, the 256-byte
public key field has been unused since version 0.6 (2005).

Implementers should generate the random data for
Destination public keys, and Destination and Router Identity padding,
so that it is compressible in various I2P protocols while
still being secure, and without having Base 64 representations appear to be corrupt or insecure.
This provides most of the benefits of removing the padding fields without any
disruptive protocol changes.

Strictly speaking, the 32-byte signing public key alone (in both Destinations and Router Identities)
and the 32-byte encryption public key (in Router Identities only) is a random number
that provides all the entropy necessary for the SHA-256 hashes of these structures
to be cryptographically strong and randomly distributed in the network database DHT.

However, out of an abundance of caution, we recommend a minimum of 32 bytes of random data
be used in the ElG public key field and padding. Additionally, if the fields were all zeros,
Base 64 destinations would contain long runs of AAAA characters, which may cause alarm
or confusion to users.

Repeat the 32 bytes of random data as necessary so the full KeysAndCert structure is highly compressible
in I2P protocols such as I2NP Database Store Message, Streaming SYN, SSU2 handshake, and repliable Datagrams.

Examples:

* A Router Identity with X25519 encryption type and Ed25519 signature type
  will contain 10 copies (320 bytes) of the random data, for a savings of approximately 288 bytes when compressed.

* A Destination with Ed25519 signature type
  will contain 11 copies (352 bytes) of the random data, for a savings of approximately 320 bytes when compressed.

Implementations must, of course, store the full 387+ byte structure because the SHA-256 hash of the structure
covers the full contents.



Notes
`````
* Do not assume that these are always 387 bytes! They are 387 bytes plus the
  certificate length specified at bytes 385-386, which may be non-zero.

* As of release 0.9.12, if the certificate is a Key Certificate, the boundaries
  of the key fields may vary. See the Key Certificate section above for
  details.

* The Crypto Public Key is aligned at the start and the Signing Public Key is
  aligned at the end. The padding (if any) is in the middle.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/KeysAndCert.html

.. _struct-RouterIdentity:

RouterIdentity
--------------

Description
```````````
Defines the way to uniquely identify a particular router

Contents
````````
Identical to KeysAndCert.

See KeysAndCert_ for guidelines on generating the random data for
the padding field.

Notes
`````
* The certificate for a RouterIdentity was always NULL until release 0.9.12.

* Do not assume that these are always 387 bytes! They are 387 bytes plus the
  certificate length specified at bytes 385-386, which may be non-zero.

* As of release 0.9.12, if the certificate is a Key Certificate, the boundaries
  of the key fields may vary. See the Key Certificate section above for
  details.

* The Crypto Public Key is aligned at the start and the Signing Public Key is
  aligned at the end. The padding (if any) is in the middle.

* RouterIdentities with a key certificate and a ECIES_X25519 public key
  are supported as of release 0.9.48.
  Prior to that, all RouterIdentities were ElGamal.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/router/RouterIdentity.html

.. _struct-Destination:

Destination
-----------

Description
```````````
A Destination defines a particular endpoint to which messages can be directed
for secure delivery.

Contents
````````
Identical to KeysAndCert_, except that the public key is never used,
and may contain random data instead of a valid ElGamal Public Key.

See KeysAndCert_ for guidelines on generating the random data for
the public key and padding fields.

Notes
`````
* The public key of the destination was used for the old i2cp-to-i2cp
  encryption which was disabled in version 0.6 (2005), it is currently unused except
  for the IV for LeaseSet encryption, which is deprecated. The public key in
  the LeaseSet is used instead.

* Do not assume that these are always 387 bytes! They are 387 bytes plus the
  certificate length specified at bytes 385-386, which may be non-zero.

* As of release 0.9.12, if the certificate is a Key Certificate, the boundaries
  of the key fields may vary. See the Key Certificate section above for
  details.

* The Crypto Public Key is aligned at the start and the Signing Public Key is
  aligned at the end. The padding (if any) is in the middle.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/Destination.html

.. _struct-Lease:

Lease
-----

Description
```````````
Defines the authorization for a particular tunnel to receive messages targeting
a Destination_.

Contents
````````
SHA256 Hash_ of the RouterIdentity_ of the gateway router, then the TunnelId_,
and finally an end Date_.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | tunnel_gw                             |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |     tunnel_id     |      end_date
  +----+----+----+----+----+----+----+----+
                      |
  +----+----+----+----+

  tunnel_gw :: Hash of the `RouterIdentity` of the tunnel gateway
               length -> 32 bytes

  tunnel_id :: `TunnelId`
               length -> 4 bytes

  end_date :: `Date`
              length -> 8 bytes
{% endhighlight %}

Notes
`````
* Total size: 44 bytes

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/Lease.html

.. _struct-LeaseSet:

LeaseSet
--------

Description
```````````
Contains all of the currently authorized Leases_ for a particular Destination_,
the PublicKey_ to which garlic messages can be encrypted, and then the
SigningPublicKey_ that can be used to revoke this particular version of the
structure. The LeaseSet is one of the two structures stored in the network
database (the other being RouterInfo_), and is keyed under the SHA256 of the
contained Destination_.

.. _Leases: #struct-lease

Contents
````````
Destination_, followed by a PublicKey_ for encryption, then a SigningPublicKey_
which can be used to revoke this version of the LeaseSet, then a 1 byte
Integer_ specifying how many Lease_ structures are in the set, followed by the
actual Lease_ structures and finally a Signature_ of the previous bytes signed
by the Destination_'s SigningPrivateKey_.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | destination                           |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | encryption_key                        |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | signing_key                           |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | num| Lease 0                          |
  +----+                                  +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | Lease 1                               |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | Lease ($num-1)                        |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | signature                             |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+

  destination :: `Destination`
                 length -> >= 387+ bytes

  encryption_key :: `PublicKey`
                    length -> 256 bytes

  signing_key :: `SigningPublicKey`
                 length -> 128 bytes or as specified in destination's key
                           certificate

  num :: `Integer`
         length -> 1 byte
         Number of leases to follow
         value: 0 <= num <= 16

  leases :: [`Lease`]
            length -> $num*44 bytes

  signature :: `Signature`
               length -> 40 bytes or as specified in destination's key
                         certificate
{% endhighlight %}

Notes
`````
* The public key of the destination was used for the old I2CP-to-I2CP
  encryption which was disabled in version 0.6, it is currently unused.

* The encryption key is used for end-to-end ElGamal/AES+SessionTag encryption
  [ELGAMAL-AES]_. It is currently generated anew at every router startup, it is
  not persistent.

* The signature may be verified using the signing public key of the
  destination.

* A LeaseSet with zero Leases is allowed but is unused.
  It was intended for LeaseSet revocation, which is unimplemented.
  All LeaseSet2 variants require at least one Lease.

* The signing_key is currently unused. It was intended for LeaseSet revocation,
  which is unimplemented. It is currently generated anew at every router
  startup, it is not persistent. The signing key type is always the same as the
  destination's signing key type.

* The earliest expiration of all the Leases is treated as the timestamp or
  version of the LeaseSet. Routers will generally not accept a store of a
  LeaseSet unless it is "newer" than the current one. Take care when publishing
  a new LeaseSet where the oldest Lease is the same as the oldest Lease in the
  previous LeaseSet. The publishing router should generally increment the
  expiration of the oldest Lease by at least 1 ms in that case.

* Prior to release 0.9.7, when included in a DatabaseStore Message sent by the
  originating router, the router set all the published leases' expirations to
  the same value, that of the earliest lease. As of release 0.9.7, the router
  publishes the actual lease expiration for each lease. This is an
  implementation detail and not part of the structures specification.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/LeaseSet.html


.. _struct-Lease2:

Lease2
------

Description
```````````
Defines the authorization for a particular tunnel to receive messages targeting
a Destination_.
Same as Lease_ but with a 4-byte end_date.
Used by LeaseSet2_.
Supported as of 0.9.38; see proposal 123 for more information.

Contents
````````
SHA256 Hash_ of the RouterIdentity_ of the gateway router, then the TunnelId_,
and finally a 4 byte end date.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | tunnel_gw                             |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |     tunnel_id     |      end_date     |
  +----+----+----+----+----+----+----+----+

  tunnel_gw :: Hash of the `RouterIdentity` of the tunnel gateway
               length -> 32 bytes

  tunnel_id :: `TunnelId`
               length -> 4 bytes

  end_date :: 4 byte date
              length -> 4 bytes
              Seconds since the epoch, rolls over in 2106.

{% endhighlight %}

Notes
`````
* Total size: 40 bytes

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/Lease2.html



.. _struct-OfflineSignature:

OfflineSignature
----------------

Description
```````````
This is an optional part of the LeaseSet2Header_.
Also used in streaming and I2CP.
Supported as of 0.9.38; see proposal 123 for more information.

Contents
````````

Contains an expiration, a sigtype and transient SigningPublicKey_, and a Signature_.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |     expires       | sigtype |         |
  +----+----+----+----+----+----+         +
  |       transient_public_key            |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |           signature                   |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  expires :: 4 byte date
             length -> 4 bytes
             Seconds since the epoch, rolls over in 2106.

  sigtype :: 2 byte type of the transient_public_key
             length -> 2 bytes

  transient_public_key :: `SigningPublicKey`
                          length -> As inferred from the sigtype

  signature :: `Signature`
               length -> As inferred from the sigtype of the signing public key
                         in the `Destination` that preceded this offline signature.
               Signature of expires timestamp, transient sig type, and public key,
               by the destination public key.

{% endhighlight %}

Notes
`````
* This section can, and should, be generated offline.


.. _struct-LeaseSet2Header:

LeaseSet2Header
---------------

Description
```````````
This is the common part of the LeaseSet2_ and MetaLeaseSet_.
Supported as of 0.9.38; see proposal 123 for more information.

Contents
````````

Contains the Destination_, two timestamps, and an optional OfflineSignature_.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | destination                           |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |     published     | expires |  flags  |
  +----+----+----+----+----+----+----+----+
  | offline_signature (optional)          |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  destination :: `Destination`
                 length -> >= 387+ bytes

  published :: 4 byte date
               length -> 4 bytes
               Seconds since the epoch, rolls over in 2106.

  expires :: 2 byte time
             length -> 2 bytes
             Offset from published timestamp in seconds, 18.2 hours max

  flags :: 2 bytes
    Bit order: 15 14 ... 3 2 1 0
    Bit 0: If 0, no offline keys; if 1, offline keys
    Bit 1: If 0, a standard published leaseset.
           If 1, an unpublished leaseset. Should not be flooded, published, or
           sent in response to a query. If this leaseset expires, do not query the
           netdb for a new one, unless bit 2 is set.
    Bit 2: If 0, a standard published leaseset.
           If 1, this unencrypted leaseset will be blinded and encrypted when published.
           If this leaseset expires, query the blinded location in the netdb for a new one.
           If this bit is set to 1, set bit 1 to 1 also.
           As of release 0.9.42.
    Bits 15-3: set to 0 for compatibility with future uses

  offline_signature :: `OfflineSignature`
                       length -> varies
                       Optional, only present if bit 0 is set in the flags.

{% endhighlight %}

Notes
`````
* Total size: 395 bytes minimum

* Maximum actual expires time is about 660 (11 minutes) for
  LeaseSet2_ and 65535 (the full 18.2 hours) for MetaLeaseSet_.

* LeaseSet_ (1) did not have a 'published' field, so versioning required
  a search for the earliest lease. LeaseSet2 adds a 'published' field
  with a resolution of one second. Routers should rate-limit sending
  new leasesets to floodfills to a rate much slower than once a second (per destination).
  If this is not implemented, then the code must ensure that each new leaseset
  has a 'published' time at least one second later than the one before, or else
  floodills will not store or flood the new leaseset.


.. _struct-LeaseSet2:

LeaseSet2
---------

Description
```````````
Contained in a I2NP DatabaseStore message of type 3.
Supported as of 0.9.38; see proposal 123 for more information.

Contains all of the currently authorized Lease2_ for a particular Destination_,
and the PublicKey_ to which garlic messages can be encrypted.
A LeaseSet is one of the two structures stored in the network
database (the other being RouterInfo_), and is keyed under the SHA256 of the
contained Destination_.


Contents
````````
LeaseSet2Header_, followed by a options, then one or more PublicKey_ for encryption,
Integer_ specifying how many Lease2_ structures are in the set, followed by the
actual Lease2_ structures and finally a Signature_ of the previous bytes signed
by the Destination_'s SigningPrivateKey_ or the transient key.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |         ls2_header                    |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |          options                      |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |numk| keytype0| keylen0 |              |
  +----+----+----+----+----+              +
  |          encryption_key_0             |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | keytypen| keylenn |                   |
  +----+----+----+----+                   +
  |          encryption_key_n             |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | num| Lease2 0                         |
  +----+                                  +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | Lease2($num-1)                        |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | signature                             |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  ls2header :: `LeaseSet2Header`
               length -> varies

  options :: `Mapping`
             length -> varies, 2 bytes minimum

  numk :: `Integer`
          length -> 1 byte
          Number of key types, key lengths, and `PublicKey`s to follow
          value: 1 <= numk <= max TBD

  keytype :: The encryption type of the `PublicKey` to follow.
             length -> 2 bytes

  keylen :: The length of the `PublicKey` to follow.
            Must match the specified length of the encryption type.
            length -> 2 bytes

  encryption_key :: `PublicKey`
                    length -> keylen bytes

  num :: `Integer`
         length -> 1 byte
         Number of `Lease2`s to follow
         value: 0 <= num <= 16

  leases :: [`Lease2`]
            length -> $num*40 bytes

  signature :: `Signature`
               length -> 40 bytes or as specified in destination's key
                         certificate, or by the sigtype of the transient public key,
                         if present in the header

{% endhighlight %}


Encryption Key Preference
`````````````````````````

For published (server) leasesets, the encryption keys are in order of server preference,
most-preferred first. If clients support more than one encryption type, it is recommended
that they honor the server preference and select the first supported type as the
encryption method to use to connect to the server.
Generally, the newer (higher-numbered) key types are more secure or efficient and
are preferred, so the keys should be listed in reverse order of key type.

However, clients may, implementation-dependent, select based on their preference instead,
or use some method to determine the "combined" preference. This may be useful as
a configuration option, or for debugging.

The key order in unpublished (client) leasesets effectively does not matter, because
connections will usually not be attempted to unpublished clients.
Unless this order is used to determine a combined preference, as described above.


Options
```````
As of API 0.9.66, a standard format for service record options
is defined. See proposal 167 for details.
Options other than service records, using a different format,
may be defined in the future.

LS2 options MUST be sorted by key, so the signature is invariant.

Service record options are defined as follows:

- serviceoption := optionkey optionvalue
- optionkey := _service._proto
- service := The symbolic name of the desired service. Must be lower case. Example: "smtp".
  Allowed chars are [a-z0-9-] and must not start or end with a '-'.
  Standard identifiers from [REGISTRY]_ or Linux /etc/services must be used if defined there.
- proto := The transport protocol of the desired service. Must be lower case, either "tcp" or "udp".
  "tcp" means streaming and "udp" means repliable datagrams.
  Protocol indicators for raw datagrams and datagram2 may be defined later.
  Allowed chars are [a-z0-9-] and must not start or end with a '-'.
- optionvalue := self | srvrecord[,srvrecord]*
- self := "0" ttl port [appoptions]
- srvrecord := "1" ttl priority weight port target [appoptions]
- ttl := time to live, integer seconds. Positive integer. Example: "86400".
  A minimum of 86400 (one day) is recommended, see Recommendations section below for details.
- priority := The priority of the target host, lower value means more preferred. Non-negative integer. Example: "0"
  Only useful if more than one record, but required even if just one record.
- weight := A relative weight for records with the same priority. Higher value means more chance of getting picked. Non-negative integer. Example: "0"
  Only useful if more than one record, but required even if just one record.
- port := The I2CP port on which the service is to be found. Non-negative integer. Example: "25"
  Port 0 is supported but not recommended.
- target := The hostname or b32 of the destination providing the service. A valid hostname as in [NAMING]_. Must be lower case.
  Example: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p" or "example.i2p".
  b32 is recommended unless the hostname is "well known", i.e. in official or default address books.
- appoptions := arbitrary text specific to the application, must not contain " " or ",". Encoding is UTF-8.

Examples:

In LS2 for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p, pointing to one SMTP server:

"_smtp._tcp" "1 86400 0 0 25 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.b32.i2p"

In LS2 for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p, pointing to two SMTP servers:

"_smtp._tcp" "1 86400 0 0 25 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.b32.i2p,86400 1 0 25 cccccccccccccccccccccccccccccccccccccccccccc.b32.i2p"

In LS2 for bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.b32.i2p, pointing to itself as a SMTP server:

"_smtp._tcp" "0 999999 25"


Notes
`````
* The public key of the destination was used for the old I2CP-to-I2CP
  encryption which was disabled in version 0.6, it is currently unused.

* The encryption keys are used for end-to-end ElGamal/AES+SessionTag encryption
  [ELGAMAL-AES]_ (type 0) or other end-to-end encryption schemes.
  See [ECIES]_ and proposals 145 and 156.
  They may be generated anew at every router startup
  or they may be persistent.
  X25519 (type 4, see [ECIES]_) is supported as of release 0.9.44.

* The signature is over the data above, PREPENDED with the single byte
  containing the DatabaseStore type (3).

* The signature may be verified using the signing public key of the
  destination, or the transient signing public key, if an offline signature
  is included in the leaseset2 header.

* The key length is provided for each key, so that floodfills and clients
  may parse the structure even if not all encryption types are known or supported.

* See note on the 'published' field in LeaseSet2Header_

* The options mapping, if the size is greater than one, must be sorted by key, so the signature is invariant.


JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/LeaseSet2.html


.. _struct-MetaLease:

MetaLease
---------

Description
```````````
Defines the authorization for a particular tunnel to receive messages targeting
a Destination_.
Same as Lease2_ but with flags and cost instead of a tunnel id.
Used by MetaLeaseSet_.
Contained in a I2NP DatabaseStore message of type 7.
Supported as of 0.9.38; see proposal 123 for more information.

Contents
````````
SHA256 Hash_ of the RouterIdentity_ of the gateway router, then flags and cost,
and finally a 4 byte end date.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | tunnel_gw                             |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+
  |    flags     |cost|      end_date     |
  +----+----+----+----+----+----+----+----+

  tunnel_gw :: Hash of the `RouterIdentity` of the tunnel gateway,
               or the hash of another `MetaLeaseSet`.
               length -> 32 bytes

  flags :: 3 bytes of flags
           Bit order: 23 22 ... 3 2 1 0
           Bits 3-0: Type of the entry.
           If 0, unknown.
           If 1, a `LeaseSet`.
           If 3, a `LeaseSet2`.
           If 5, a `MetaLeaseSet`.
           Bits 23-4: set to 0 for compatibility with future uses
           length -> 3 bytes

  cost :: 1 byte, 0-255. Lower value is higher priority.
          length -> 1 byte

  end_date :: 4 byte date
              length -> 4 bytes
              Seconds since the epoch, rolls over in 2106.

{% endhighlight %}

Notes
`````
* Total size: 40 bytes

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/MetaLease.html



.. _struct-MetaLeaseSet:

MetaLeaseSet
------------

Description
```````````
Contained in a I2NP DatabaseStore message of type 7.
Defined as of 0.9.38; scheduled to be working as of 0.9.40;
see proposal 123 for more information.

Contains all of the currently authorized MetaLease_ for a particular Destination_,
and the PublicKey_ to which garlic messages can be encrypted.
A LeaseSet is one of the two structures stored in the network
database (the other being RouterInfo_), and is keyed under the SHA256 of the
contained Destination_.


Contents
````````
LeaseSet2Header_, followed by a options,
Integer_ specifying how many Lease2_ structures are in the set, followed by the
actual Lease2_ structures and finally a Signature_ of the previous bytes signed
by the Destination_'s SigningPrivateKey_ or the transient key.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |         ls2_header                    |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |          options                      |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | num| MetaLease 0                      |
  +----+                                  +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | MetaLease($num-1)                     |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |numr|                                  |
  +----+                                  +
  |          revocation_0                 |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |          revocation_n                 |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | signature                             |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  ls2header :: `LeaseSet2Header`
               length -> varies

  options :: `Mapping`
             length -> varies, 2 bytes minimum

  num :: `Integer`
          length -> 1 byte
          Number of `MetaLease`s to follow
          value: 1 <= num <= max TBD

  leases :: `MetaLease`s
            length -> $numr*40 bytes

  numr :: `Integer`
          length -> 1 byte
          Number of `Hash`es to follow
          value: 0 <= numr <= max TBD

  revocations :: [`Hash`]
                 length -> $numr*32 bytes

  signature :: `Signature`
               length -> 40 bytes or as specified in destination's key
                         certificate, or by the sigtype of the transient public key,
                         if present in the header

{% endhighlight %}

Notes
`````
* The public key of the destination was used for the old I2CP-to-I2CP
  encryption which was disabled in version 0.6, it is currently unused.

* The signature is over the data above, PREPENDED with the single byte
  containing the DatabaseStore type (7).

* The signature may be verified using the signing public key of the
  destination, or the transient signing public key, if an offline signature
  is included in the leaseset2 header.

* See note on the 'published' field in LeaseSet2Header_


JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/MetaLeaseSet.html



.. _struct-EncryptedLeaseSet:

EncryptedLeaseSet
-----------------

Description
```````````
Contained in a I2NP DatabaseStore message of type 5.
Defined as of 0.9.38; working as of 0.9.39;
see proposal 123 for more information.

Only the blinded key and expiration are visible in cleartext.
The actual lease set is encrypted.

Contents
````````
A two byte signature type, the blinded SigningPrivateKey_,
published time, expiration, and flags.
Then, a two byte length followed by encrypted data.
Finally, a Signature_ of the previous bytes signed
by the blinded SigningPrivateKey_ or the transient key.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | sigtype |                             |
  +----+----+                             +
  |        blinded_public_key             |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |     published     | expires |  flags  |
  +----+----+----+----+----+----+----+----+
  | offline_signature (optional)          |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |  len    |                             |
  +----+----+                             +
  |         encrypted_data                |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | signature                             |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  sigtype :: A two byte signature type of the public key to follow
             length -> 2 bytes

  blinded_public_key :: `SigningPublicKey`
                        length -> As inferred from the sigtype

  published :: 4 byte date
               length -> 4 bytes
               Seconds since the epoch, rolls over in 2106.

  expires :: 2 byte time
             length -> 2 bytes
             Offset from published timestamp in seconds, 18.2 hours max

  flags :: 2 bytes
    Bit order: 15 14 ... 3 2 1 0
    Bit 0: If 0, no offline keys; if 1, offline keys
    Bit 1: If 0, a standard published leaseset.
           If 1, an unpublished leaseset. Should not be flooded, published, or
           sent in response to a query. If this leaseset expires, do not query the
           netdb for a new one.
    Bits 15-2: set to 0 for compatibility with future uses

  offline_signature :: `OfflineSignature`
                       length -> varies
                       Optional, only present if bit 0 is set in the flags.

  len :: `Integer`
          length -> 2 bytes
          length of encrypted_data to follow
          value: 1 <= num <= max TBD

  encrypted_data :: Data encrypted
                    length -> len bytes

  signature :: `Signature`
               length -> As specified by the sigtype of the blinded pubic key,
                         or by the sigtype of the transient public key,
                         if present in the header

{% endhighlight %}

Notes
`````
* The public key of the destination was used for the old I2CP-to-I2CP
  encryption which was disabled in version 0.6, it is currently unused.

* The signature is over the data above, PREPENDED with the single byte
  containing the DatabaseStore type (5).

* The signature may be verified using the signing public key of the
  destination, or the transient signing public key, if an offline signature
  is included in the leaseset2 header.

* Blinding and encryption are specified in `EncryptedLeaseSet`_

* This structure does not use the LeaseSet2Header_.

* Maximum actual expires time is about 660 (11 minutes), unless
  it is an encrypted MetaLeaseSet_.

* See proposal 123 for notes on using offline signatures
  with encrypted leasesets.

* See note on the 'published' field in LeaseSet2Header_
  (same issue, even though we do not use the LeaseSet2Header format here)


.. _EncryptedLeaseSet: {{ site_url('docs/spec/encryptedleaseset') }}

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/EncryptedLeaseSet.html



.. _struct-RouterAddress:

RouterAddress
-------------

Description
```````````
This structure defines the means to contact a router through a transport
protocol.

Contents
````````
1 byte Integer_ defining the relative cost of using the address, where 0 is
free and 255 is expensive, followed by the expiration Date_ after which the
address should not be used, or if null, the address never expires. After that
comes a String_ defining the transport protocol this router address uses.
Finally there is a Mapping_ containing all of the transport specific options
necessary to establish the connection, such as IP address, port number, email
address, URL, etc.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |cost|           expiration
  +----+----+----+----+----+----+----+----+
       |        transport_style           |
  +----+----+----+----+-//-+----+----+----+
  |                                       |
  +                                       +
  |               options                 |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+

  cost :: `Integer`
          length -> 1 byte

          case 0 -> free
          case 255 -> expensive

  expiration :: `Date` (must be all zeros, see notes below)
                length -> 8 bytes

                case null -> never expires

  transport_style :: `String`
                     length -> 1-256 bytes

  options :: `Mapping`
{% endhighlight %}

Notes
`````
* Cost is typically 5 or 6 for SSU, and 10 or 11 for NTCP.

* Expiration is currently unused, always null (all zeroes). As of release
  0.9.3, the expiration is assumed zero and not stored, so any non-zero
  expiration will fail in the RouterInfo signature verification. Implementing
  expiration (or another use for these bytes) will be a backwards-incompatible
  change. Routers MUST set this field to all zeros. As of release 0.9.12, a
  non-zero expiration field is again recognized, however we must wait several
  releases to use this field, until the vast majority of the network recognizes
  it.

* The following options, while not required, are standard and expected to be
  present in most router addresses: "host" (an IPv4 or IPv6 address or host
  name) and "port".

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/router/RouterAddress.html

.. _struct-RouterInfo:

RouterInfo
----------

Description
```````````
Defines all of the data that a router wants to publish for the network to see.
The RouterInfo_ is one of two structures stored in the network database (the
other being LeaseSet_), and is keyed under the SHA256 of the contained
RouterIdentity_.

Contents
````````
RouterIdentity_ followed by the Date_, when the entry was published

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  | router_ident                          |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | published                             |
  +----+----+----+----+----+----+----+----+
  |size| RouterAddress 0                  |
  +----+                                  +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | RouterAddress 1                       |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  | RouterAddress ($size-1)               |
  +                                       +
  |                                       |
  ~                                       ~
  ~                                       ~
  |                                       |
  +----+----+----+----+-//-+----+----+----+
  |psiz| options                          |
  +----+----+----+----+-//-+----+----+----+
  | signature                             |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +                                       +
  |                                       |
  +----+----+----+----+----+----+----+----+

  router_ident :: `RouterIdentity`
                  length -> >= 387+ bytes

  published :: `Date`
               length -> 8 bytes

  size :: `Integer`
          length -> 1 byte
          The number of `RouterAddress`es to follow, 0-255

  addresses :: [`RouterAddress`]
               length -> varies

  peer_size :: `Integer`
               length -> 1 byte
               The number of peer `Hash`es to follow, 0-255, unused, always zero
               value -> 0

  options :: `Mapping`

  signature :: `Signature`
               length -> 40 bytes or as specified in router_ident's key
                         certificate
{% endhighlight %}

Notes
`````
* The peer_size Integer_ may be followed by a list of that many router hashes.
  This is currently unused. It was intended for a form of restricted routes,
  which is unimplemented.
  Certain implementations may require the list to be sorted so the signature is invariant.
  To be researched before enabling this feature.

* The signature may be verified using the signing public key of the
  router_ident.

* See the network database page [NETDB-ROUTERINFO]_ for standard options that
  are expected to be present in all router infos.

* Very old routers required the addresses to be sorted by the SHA256 of their data
  so the signature is invariant.
  This is no longer required, and not worth implementing for backward compatibility.

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/data/router/RouterInfo.html

.. _struct-DeliveryInstructions:

Delivery Instructions
---------------------

Tunnel Message Delivery Instructions are defined in the Tunnel Message
Specification [TUNNEL-DELIVERY]_.

Garlic Message Delivery Instructions are defined in the I2NP Message
Specification [GARLIC-DELIVERY]_.


References
==========

.. [ECIES]
   {{ spec_url('ecies') }}

.. [ECIES-HYBRID]
   {{ spec_url('ecies-hybrid') }}

.. [ECIES-ROUTERS]
   {{ spec_url('ecies-routers') }}

.. [ELGAMAL]
    {{ site_url('docs/how/cryptography', True) }}#elgamal

.. [ELGAMAL-AES]
    {{ site_url('docs/how/elgamal-aes', True) }}

.. [GARLIC-DELIVERY]
    {{ ctags_url('GarlicCloveDeliveryInstructions') }}

.. [I2CP]
    {{ site_url('docs/protocol/i2cp', True) }}

.. [I2NP]
    {{ site_url('docs/protocol/i2np', True) }}

.. [NAMING]
    {{ site_url('docs/naming', True) }}

.. [NETDB-ROUTERINFO]
    {{ site_url('docs/how/network-database', True) }}#routerInfo

.. [Prop134]
    {{ proposal_url('134') }}

.. [Prop169]
    {{ proposal_url('169') }}

.. [REGISTRY]
    http://www.dns-sd.org/ServiceTypes.html

.. [SSU]
    {{ site_url('docs/transport/ssu', True) }}

.. [TUNNEL-DELIVERY]
    {{ ctags_url('TunnelMessageDeliveryInstructions') }}
