package common

/*

https://geti2p.net/spec/common-structures#leaseset2
LeaseSet2
Description

Contained in a I2NP DatabaseStore message of type 3. Supported as of 0.9.38; see proposal 123 for more information.

Contains all of the currently authorized Lease2 for a particular Destination, and the PublicKey to which garlic messages can be encrypted. A LeaseSet is one of the two structures stored in the network database (the other being RouterInfo), and is keyed under the SHA256 of the contained Destination.
Contents

LeaseSet2Header, followed by a options, then one or more PublicKey for encryption, Integer specifying how many Lease2 structures are in the set, followed by the actual Lease2 structures and finally a Signature of the previous bytes signed by the Destination's SigningPrivateKey or the transient key.

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

ls2header :: LeaseSet2Header
             length -> varies

options :: Mapping
           length -> varies, 2 bytes minimum

numk :: Integer
        length -> 1 byte
        Number of key types, key lengths, and PublicKeys to follow
        value: 1 <= numk <= max TBD

keytype :: The encryption type of the PublicKey to follow.
           length -> 2 bytes

keylen :: The length of the PublicKey to follow.
          Must match the specified length of the encryption type.
          length -> 2 bytes

encryption_key :: PublicKey
                  length -> 256 bytes

num :: Integer
       length -> 1 byte
       Number of Lease2s to follow
       value: 0 <= num <= 16

leases :: [Lease2]
          length -> $num*40 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key
                       certificate, or by the sigtype of the transient public key,
                       if present in the header

Notes

    The public key of the destination was used for the old I2CP-to-I2CP encryption which was disabled in version 0.6, it is currently unused.
    The encryption keys are used for end-to-end ElGamal/AES+SessionTag encryption [ELGAMAL-AES] (type 0) or other end-to-end encryption schemes. See [ECIES] and proposals 145 and 156. They may be generated anew at every router startup or they may be persistent. X25519 (type 4, see [ECIES]) is supported as of release 0.9.44.
    The signature is over the data above, PREPENDED with the single byte containing the DatabaseStore type (3).
    The signature may be verified using the signing public key of the destination, or the transient signing public key, if an offline signature is included in the leaseset2 header.
    The key length is provided for each key, so that floodfills and clients may parse the structure even if not all encryption types are known or supported.

JavaDoc: http://echelon.i2p/javadoc/net/i2p/data/LeaseSet2.html

*/
