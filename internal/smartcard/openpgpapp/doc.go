// Package openpgpapp speaks the OpenPGP application of a smart card (OpenPGP smart card application,
// version 3.4.1). It is the code that speaks to a card, in internal/smartcard; package internal/cards
// is a different thing, the reader of the card files of a bundle, and the two share nothing.
//
// This is the foundation of the package: the [Transport] that the layer needs from a reader, the
// [Session] that owns one, and the one function through which every command goes, send. Nothing
// here selects the application or reads or writes a data object; the commands come in later pieces.
// What is here is what no later piece can get around:
//
//   - A list of the commands that this layer may ever send (the table in allowlist.go), as data. A command that is
//     not in the list is refused before anything reaches the transport ([ErrNotAllowed]); a command
//     that is in the list but changes the card, or needs a PIN, is refused in a read-only session
//     ([ErrReadOnly]). A command that must never be sent (terminate, activate, reset retry counter,
//     key import, decipher, a write to a data object outside the list, an empty verification) is
//     simply not in the list.
//   - Encoding in the short form or, when both the reader and the card allow it, the extended form
//     (section 7.1 and clause 6.1 of the card specification); command chaining for data that one
//     command cannot carry (section 7.4: the class byte's chaining bit on every block but the last,
//     blocks of at most 255 bytes, each intermediate block answered by 9000); and response
//     continuation, GET RESPONSE after a 61xx word (section 7.2.9), up to [MaxResponse] bytes.
//   - One rule for every other status word: it is final, and is returned as a [*StatusError] that
//     names the operation, never a command byte. The layer never retries, and a 6Cxx word is an error
//     like the rest, because no source gives a resend for this application.
//   - Nothing but the selection of the application is sent before it succeeded ([ErrNotSelected]); a
//     failed selection takes the state back, so a write never goes to whatever else the card has selected.
//   - One rule for a failed exchange: an error from the transport, a panic of the transport, a
//     response that cannot be read or that is longer than its form carries, a block of a chain that
//     the card refuses, and any ending but success once the card has begun to answer with 61xx, all
//     leave the state of the card unknown, so the session is dead. Every later call returns
//     [ErrSessionDead] without touching the transport, and the error of the failing call is a
//     [*LostError] that says whether the command was one that changes the card.
//   - A PIN is held in an [apdu.Secret], and a command carries it as one (as two for a change of a
//     PIN), never in plain Data: the rows of the PIN commands refuse a PIN in Data, so no way of
//     printing a command can show it. The encoded bytes of such a command are overwritten as soon as
//     the transport has returned, and every response buffer that is not handed to the caller is
//     overwritten.
//
// For the piece that reads the algorithm information object (FA): the vendor's library shows that some
// firmware sends it with an outer length that is two bytes longer than its data, and the strict reader
// of package tlv refuses that. That piece needs a tolerant reading of that one object, and of no other.
//
// The package imports no transport and opens no device; the reader is given as a [Transport], and
// the tests use a scripted one.
package openpgpapp
