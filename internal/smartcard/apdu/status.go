package apdu

import "fmt"

// Status is the status word of a response: SW1 in the high byte, SW2 in the low byte. The values below
// are the ones that the application layer reads by name (the status table of the OpenPGP smart card
// application, specification 3.4.1, section 7.9, and the status bytes of ISO/IEC 7816-4). Any other word is
// final: the layer reports it and does not act on it.
type Status uint16

// The status words that the application layer names.
const (
	// StatusSuccess is the command executed (9000).
	StatusSuccess Status = 0x9000
	// StatusWrongLength is a wrong length of the command data or of Le (6700).
	StatusWrongLength Status = 0x6700
	// StatusSecurityNotSatisfied is the security status not satisfied: a wrong PIN, or a command
	// that needs a verification that was not made (6982).
	StatusSecurityNotSatisfied Status = 0x6982
	// StatusAuthBlocked is the authentication method blocked: the error counter of the PIN is
	// zero (6983).
	StatusAuthBlocked Status = 0x6983
	// StatusInstructionNotSupported is the instruction code not supported or invalid (6D00): what a
	// card answers when the application that is selected does not know the command.
	StatusInstructionNotSupported Status = 0x6D00
	// StatusClassNotSupported is the class not supported (6E00), likewise.
	StatusClassNotSupported Status = 0x6E00
	// StatusNotFound is the referenced data, or the data object, not found (6A88).
	StatusNotFound Status = 0x6A88

	// statusMoreData is the base of 61xx: the command is done and SW2 bytes are waiting.
	statusMoreData Status = 0x6100
)

// MoreData reports whether the word is 61xx, success with more data to fetch, and how many bytes the
// card announces: SW2, where 00 stands for 256. A 6Cxx word is not "more data" and is not treated as
// it (there is no source for resending a command with the length the card names).
func (s Status) MoreData() (count int, ok bool) {
	if s&0xFF00 != statusMoreData {
		return 0, false
	}
	if n := int(s & 0xFF); n != 0 {
		return n, true
	}
	return 256, true
}

// IsSuccess reports whether the word is 9000.
func (s Status) IsSuccess() bool { return s == StatusSuccess }

// String is the word as four hexadecimal digits, with its name when the layer has one.
func (s Status) String() string {
	var name string
	switch {
	case s == StatusSuccess:
		name = "success"
	case s == StatusWrongLength:
		name = "wrong length"
	case s == StatusSecurityNotSatisfied:
		name = "security status not satisfied"
	case s == StatusAuthBlocked:
		name = "authentication method blocked"
	case s == StatusInstructionNotSupported:
		name = "instruction not supported"
	case s == StatusClassNotSupported:
		name = "class not supported"
	case s == StatusNotFound:
		name = "referenced data not found"
	case s&0xFF00 == statusMoreData:
		name = "more data available"
	default:
		return fmt.Sprintf("%04X", uint16(s))
	}
	return fmt.Sprintf("%04X (%s)", uint16(s), name)
}
