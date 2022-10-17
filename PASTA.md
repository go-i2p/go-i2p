Weekly notes about what I'm working on
======================================

I made a ton of progress on Noise last week, I've got a fully working handshake and I think I'll be able to send an I2NP message to another Go Transport soon with a Go TransportSession
The logic of my Noise transport is basically identical to the logic of NoiseSocket, which is because I only made it through the process by writing it side-by-side with NoiseSocket
In particular I took all the locking logic from NoiseSocket, which was important and seemed really hard to get right so I started with theirs and sort of re-factored it into what I needed to satisfy the interfaces
The specific flavor of Noise it's using is Noise IK
My Noise transport will be able to act as a net.Conn and a net.Listener so it should be easy to write a test app that just "echoes" something soon
I plan to do that(Implement as a standard Go interface) with NTCP2 as well, and would like to something similar for SSU2(which would be a different interface, net.PacketConn)
All the interesting stuff is happening in `lib/transport/noise/*.go` right now
