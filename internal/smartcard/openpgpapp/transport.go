package openpgpapp

import "time"

// Transport is what this layer needs from a card reader. A transport is the one thing the layer talks
// to, and it is defined here so that the layer imports no reader code.
//
// The contract is one command in, one response out. Transmit sends one command APDU and returns the
// card's one response APDU, data and status word. An error from Transmit means the state of the
// exchange is unknown: the card may or may not have received the command, and may or may not have
// carried it out. The layer does not ask the transport anything more about it, does not retry, and
// calls it no more once any call has failed.
//
// Every byte slice that a transport returns belongs to the caller from then on, and the transport
// keeps no reference to it; the layer overwrites it when it has copied what it needs. A transport
// keeps no reference to the command it was given either: the layer overwrites a command that held a
// secret as soon as Transmit returns. An error that a transport returns must not contain a byte of a
// command. A budget is the longest the call may take, from the caller's side; a transport that cannot
// keep to it returns an error.
//
// Once a [Session] exists on a transport, only the session calls PowerOn and PowerOff, through its own
// helpers, because a power cycle ends the selection of the application and the verification of a PIN,
// and the session must forget what it knew of them. This layer assumes that no other program talks to
// the card while a session is open: opening the reader exclusively is the transport's part of the
// contract, and a layer on top of a reader that is shared cannot know what the card has selected.
type Transport interface {
	// PowerOn powers the card and returns its answer to reset.
	PowerOn(budget time.Duration) ([]byte, error)
	// Transmit sends one command APDU and returns the one response APDU.
	Transmit(command []byte, budget time.Duration) ([]byte, error)
	// PowerOff powers the card off.
	PowerOff(budget time.Duration) error
	// Close releases the reader.
	Close() error
	// ExtendedAPDU reports whether the reader accepts extended-length command APDUs and returns
	// extended-length responses.
	ExtendedAPDU() bool
}
