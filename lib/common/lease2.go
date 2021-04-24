package common

/*
Lease2
https://geti2p.net/spec/common-structures#lease2
Description

Defines the authorization for a particular tunnel to receive messages targeting a Destination. Same as Lease but with a 4-byte end_date. Used by LeaseSet2. Supported as of 0.9.38; see proposal 123 for more information.
Contents

SHA256 Hash of the RouterIdentity of the gateway router, then the TunnelId, and finally a 4 byte end date.

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

tunnel_gw :: Hash of the RouterIdentity of the tunnel gateway
             length -> 32 bytes

tunnel_id :: TunnelId
             length -> 4 bytes

end_date :: 4 byte date
            length -> 4 bytes
            Seconds since the epoch, rolls over in 2106.

Notes

    Total size: 40 bytes

JavaDoc: http://echelon.i2p/javadoc/net/i2p/data/Lease2.html
*/
