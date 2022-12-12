Weekly notes about what I'm working on
======================================

I finally got back to work on go-i2p last Friday, continuing work on the Noise transport(also enhanced marek's privs as a reddit mod which has been helpful, also the Dread community does appear to have begun to step a little re: onboarding eachother)
I can now make a socket, instantiate a noise transport using the socket, and begin to use it to manage "incoming" and "outgoing" handshakes.
They don't complete yet, still working on that, but it's more like debugging now and less figuring out how to actually do it, I more or less know where the pieces go now
I'm beginning to notice drawbacks of what I've done here already, I think noiseSocket is intended at times as example of a way to use flynn/noise which is not exactly like I would do it or how a P2P application needs to do it
Some of the functions are very long and hard to break down, and they use a different Noise flavor than NTCP2 by default, so I'm breaking things down into steps until I have exactly one step of a Noise handshake, exactly one function
Which should finally give me what I've been hoping for all along, an interface where I can modify steps(i.e. add padding, eventually turn it into NTCP2) by instantiating it with different versions of that function, so I get to think about reusability now
I'm going to attempt to ask a question I don't quite know how to ask yet, and maybe won't know the answer until I try it out for myself:
Supposing:
0. Go network structures can be "nested" if they implement the common interface(`net.Conn`, `net.PacketConn`), and use the common interface to store the information about the socket in their implmentation, and only use the functions of the common interface(This is true)
1. That I can instantiate this Noise-framework Transport struct with functions to modify the process in a granular enough way that turning it into NTCP2 is a matter of writing a few custom functions and plugging them in to an instance of the struct(Sort of like what you would do with inheritance)(which I think is true)
2. that I can instantiate it with both a `net.Conn(TCP Socket interface)` and a `net.PacketConn(UDP Socket interface)` because I only use the common features of those 2 interfaces, (Which isn't true yet but I'm thinking about how to do it)
Does that potential definition of a moddable Noise-over-many-transports library mean that I can approach SSU2 mostly in terms of connection management and peer testing, because the crypto would be similar enough to NTCP2 that I could re-use the custom functions?
I'll find out the hard way eventually the first time I have to do it with SSU2, but it would be exciting to have come up with a design that has accelerating returns in such a way.