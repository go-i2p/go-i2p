============================
Tunnel Message Specification
============================
.. meta::
    :category: Design
    :lastupdated: 2021-01
    :accuratefor: 0.9.49

.. contents::


Overview
========

This document specifies the format of tunnel messages.  For general information
about tunnels see the tunnel documentation [TUNNEL-IMPL]_.


Message preprocessing
=====================

A *tunnel gateway* is the entrance, or first hop, of a tunnel.  For an outbound
tunnel, the gateway is the creator of the tunnel.  For an inbound tunnel, the
gateway is at the opposite end from the creator of the tunnel.

A gateway *preprocesses* [I2NP]_ messages by fragmenting and combining them
into tunnel messages.

While I2NP messages are variable size from 0 to almost 64 KB, tunnel messages
are fixed-size, approximately 1 KB.  Fixed message size restricts several types
of attacks that are possible from observing message size.

After the tunnel messages are created, they are encrypted as described in the
tunnel documentation [TUNNEL-IMPL]_.

.. _msg-Tunnel:

Tunnel Message (Encrypted)
--------------------------

These are the contents of a tunnel data message after encryption.

.. raw:: html

  {% highlight lang='dataspec' -%}
+----+----+----+----+----+----+----+----+
  |    Tunnel ID      |       IV          |
  +----+----+----+----+                   +
  |                                       |
  +                   +----+----+----+----+
  |                   |                   |
  +----+----+----+----+                   +
  |                                       |
  +           Encrypted Data              +
  ~                                       ~
  |                                       |
  +                   +-------------------+
  |                   |
  +----+----+----+----+

  Tunnel ID :: `TunnelId`
         4 bytes
         the ID of the next hop, nonzero

  IV ::
         16 bytes
         the initialization vector

  Encrypted Data ::
         1008 bytes
         the encrypted tunnel message

  total size: 1028 Bytes
{% endhighlight %}

Tunnel Message (Decrypted)
--------------------------

These are the contents of a tunnel data message when decrypted.

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |    Tunnel ID      |       IV          |
  +----+----+----+----+                   +
  |                                       |
  +                   +----+----+----+----+
  |                   |     Checksum      |
  +----+----+----+----+----+----+----+----+
  |          nonzero padding...           |
  ~                                       ~
  |                                       |
  +                                  +----+
  |                                  |zero|
  +----+----+----+----+----+----+----+----+
  |                                       |
  |       Delivery Instructions  1        |
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +       I2NP Message Fragment 1         +
  |                                       |
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  |       Delivery Instructions 2...      |
  ~                                       ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |                                       |
  +       I2NP Message Fragment 2...      +
  |                                       |
  ~                                       ~
  |                                       |
  +                   +-------------------+
  |                   |
  +----+----+----+----+

  Tunnel ID :: `TunnelId`
         4 bytes
         the ID of the next hop, nonzero

  IV ::
         16 bytes
         the initialization vector

  Checksum ::
         4 bytes
         the first 4 bytes of the SHA256 hash of (the contents of the message
         (after the zero byte) + IV)

  Nonzero padding ::
         0 or more bytes
         random nonzero data for padding

  Zero ::
         1 byte
         the value 0x00

  Delivery Instructions :: `TunnelMessageDeliveryInstructions`
         length varies but is typically 7, 39, 43, or 47 bytes
         Indicates the fragment and the routing for the fragment

  Message Fragment ::
         1 to 996 bytes, actual maximum depends on delivery instruction size
         A partial or full I2NP Message

  total size: 1028 Bytes
{% endhighlight %}

Notes
`````
* The padding, if any, must be before the instruction/message pairs.
  There is no provision for padding at the end.

* The checksum does NOT cover the padding or the zero byte.
  Take the message starting at the first delivery instructions, concatenate the
  IV, and take the Hash of that.


.. _struct-TunnelMessageDeliveryInstructions:

Tunnel Message Delivery Instructions
====================================

The instructions are encoded with a single control byte, followed by any
necessary additional information.  The first bit (MSB) in that control byte
determines how the remainder of the header is interpreted - if it is not set,
the message is either not fragmented or this is the first fragment in the
message.  If it is set, this is a follow on fragment.

This specification is for Delivery Instructions inside Tunnel Messages only.
Note that "Delivery Instructions" are also used inside Garlic Cloves
[I2NP-GC]_, where the format is significantly different.  See the I2NP
documentation [I2NP-GCDI]_ for details.  Do NOT use the following specification
for Garlic Clove Delivery Instructions!

First Fragment Delivery Instructions
------------------------------------

If the MSB of the first byte is 0, this is an initial I2NP message fragment,
or a complete (unfragmented) I2NP message, and the instructions are:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+----+
  |flag|  Tunnel ID (opt)  |              |
  +----+----+----+----+----+              +
  |                                       |
  +                                       +
  |         To Hash (optional)            |
  +                                       +
  |                                       |
  +                        +--------------+
  |                        |dly | Message  
  +----+----+----+----+----+----+----+----+
   ID (opt) |extended opts (opt)|  size   |
  +----+----+----+----+----+----+----+----+

  flag ::
         1 byte
         Bit order: 76543210
         bit 7: 0 to specify an initial fragment or an unfragmented message
         bits 6-5: delivery type
                   0x0 = LOCAL
                   0x01 = TUNNEL
                   0x02 = ROUTER
                   0x03 = unused, invalid
                   Note: LOCAL is used for inbound tunnels only, unimplemented
                   for outbound tunnels
         bit 4: delay included?  Unimplemented, always 0
                                 If 1, a delay byte is included
         bit 3: fragmented?  If 0, the message is not fragmented, what follows
                             is the entire message
                             If 1, the message is fragmented, and the
                             instructions contain a Message ID
         bit 2: extended options?  Unimplemented, always 0
                                   If 1, extended options are included
         bits 1-0: reserved, set to 0 for compatibility with future uses

  Tunnel ID :: `TunnelId`
         4 bytes
         Optional, present if delivery type is TUNNEL
         The destination tunnel ID, nonzero

  To Hash ::
         32 bytes
         Optional, present if delivery type is ROUTER or TUNNEL
            If ROUTER, the SHA256 Hash of the router
            If TUNNEL, the SHA256 Hash of the gateway router

  Delay ::
         1 byte
         Optional, present if delay included flag is set
         In tunnel messages: Unimplemented, never present; original
         specification:
            bit 7: type (0 = strict, 1 = randomized)
            bits 6-0: delay exponent (2^value minutes)

  Message ID ::
         4 bytes
         Optional, present if this message is the first of 2 or more fragments
            (i.e. if the fragmented bit is 1)
         An ID that uniquely identifies all fragments as belonging to a single
         message (the current implementation uses `I2NPMessageHeader.msg_id`)

  Extended Options ::
         2 or more bytes
         Optional, present if extend options flag is set
         Unimplemented, never present; original specification:
         One byte length and then that many bytes

  size ::
         2 bytes
         The length of the fragment that follows
         Valid values: 1 to approx. 960 in a tunnel message

  Total length: Typical length is:
         3 bytes for LOCAL delivery (tunnel message);
         35 bytes for ROUTER delivery or 39 bytes for TUNNEL
         delivery (unfragmented tunnel message);
         39 bytes for ROUTER delivery or 43 bytes for TUNNEL delivery (first
         fragment)
{% endhighlight %}

Follow-on Fragment Delivery Instructions
----------------------------------------

If the MSB of the first byte is 1, this is a follow-on fragment, and the
instructions are:

.. raw:: html

  {% highlight lang='dataspec' %}
+----+----+----+----+----+----+----+
  |frag|     Message ID    |  size   |
  +----+----+----+----+----+----+----+

  frag ::
         1 byte
         Bit order: 76543210
         binary 1nnnnnnd
                bit 7: 1 to indicate this is a follow-on fragment
                bits 6-1: nnnnnn is the 6 bit fragment number from 1 to 63
                bit 0: d is 1 to indicate the last fragment, 0 otherwise

  Message ID ::
         4 bytes
         Identifies the fragment sequence that this fragment belongs to.
         This will match the message ID of an initial fragment (a fragment
         with flag bit 7 set to 0 and flag bit 3 set to 1).

  size ::
         2 bytes
         the length of the fragment that follows
         valid values: 1 to 996

  total length: 7 bytes
{% endhighlight %}

JavaDoc: http://{{ i2pconv('idk.i2p/javadoc-i2p') }}/net/i2p/router/tunnel/FragmentHandler.html


Notes
=====

I2NP Message Maximum Size
-------------------------

While the maximum I2NP message size is nominally 64 KB, the size is further
constrained by the method of fragmenting I2NP messages into multiple 1 KB
tunnel messages.  The maximum number of fragments is 64, and the initial
fragment may not be perfectly aligned at the start of a tunnel message.  So the
message must nominally fit in 63 fragments.

The maximum size of an initial fragment is 956 bytes (assuming TUNNEL delivery
mode); the maximum size of a follow-on fragment is 996 bytes.  Therefore the
maximum size is approximately 956 + (62 * 996) = 62708 bytes, or 61.2 KB.

Ordering, Batching, Packing
---------------------------

Tunnel messages may be dropped or reordered.  The tunnel gateway, who creates
tunnel messages, is free to implement any batching, mixing, or reordering
strategy to fragment I2NP messages and efficiently pack fragments into tunnel
messages.  In general, an optimal packing is not possible (the "packing
problem").  The gateways may implement various delay and reordering strategies.

Cover Traffic
-------------

Tunnel messages may contain only padding (i.e. no delivery instructions or
message fragments at all) for cover traffic. This is unimplemented.


References
==========

.. [I2NP]
    {{ site_url('docs/protocol/i2np', True) }}

.. [I2NP-GC]
    {{ ctags_url('GarlicClove') }}

.. [I2NP-GCDI]
    {{ ctags_url('GarlicCloveDeliveryInstructions') }}

.. [TUNNEL-IMPL]
    {{ site_url('docs/tunnels/implementation', True) }}
