package messages

/**
	Messages
	========

	All NTCP2 messages are less than or equal to 65537 bytes in length. The message
	format is based on Noise messages, with modifications for framing and indistinguishability.
	Implementations using standard Noise libraries may need to pre-process received
	messages to/from the Noise message format. All encrypted fields are AEAD
	ciphertexts.


	The establishment sequence is as follows:

	Alice                           Bob

	SessionRequest ------------------->
	<------------------- SessionCreated
	SessionConfirmed ----------------->


	Using Noise terminology, the establishment and data sequence is as follows:
	(Payload Security Properties)

	XK(s, rs):           Authentication   Confidentiality
		<- s
		...
		-> e, es                  0                2
		<- e, ee                  2                1
		-> s, se                  2                5
		<-                        2                5



	Once a session has been established, Alice and Bob can exchange Data messages.

	All message types (SessionRequest, SessionCreated, SessionConfirmed, Data and
	TimeSync) are specified in this section.

	Some notations::

	- RH_A = Router Hash for Alice (32 bytes)
	- RH_B = Router Hash for Bob (32 bytes)
**/

type MessageType uint8

const (
	MessageTypeSessionRequest   = 0x00
	MessageTypeSessionCreated   = 0x01
	MessageTypeSessionConfirmed = 0x02
	MessageTypeData             = 0x03
)

type Options interface {
	Data() []byte
}

type Message interface {
	// Type returns the message type
	Type() MessageType
	// Payload returns the message payload
	Payload() []byte
	// PayloadSize returns the message payload size
	PayloadSize() int
	// PayloadSecurityProperties returns the message payload security properties
	// PayloadSecurityProperties() PayloadSecurityProperties
}
