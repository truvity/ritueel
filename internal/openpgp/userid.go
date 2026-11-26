package openpgp

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxUserID is the longest user ID, in bytes, that the builders write.
	maxUserID = 1024
	// maxName is the longest name of a root, in characters (docs/reference/bundle.md, the key
	// `name` of ritueel.yaml).
	maxName = 45

	releaseRoot = " Release Root "
	testMark    = " (TEST ONLY)"
)

// UserID is the user ID of a root key's primary: "<name> Release Root <label> <address>", with the
// address in angle brackets; a test root adds " (TEST ONLY)" before the address. It holds no
// person's name (record 0009, rule 2; docs/reference/bundle.md, "The OpenPGP primary"). The parts
// follow the rules of the pages, and a part that breaks them is refused with [ErrParams]:
//
//   - the name is 1 to 45 characters: the ASCII letters, the digits, single spaces and hyphens,
//     with no space at the start or the end (the key `name` of ritueel.yaml);
//   - the label is one ASCII capital letter, A to Z (the key `label`);
//   - the address is printable ASCII with no space, no '<' and no '>', and exactly one '@', with
//     something on each side of it. No page gives a rule for the address: this one is the smallest
//     that keeps the angle brackets and the shape of the user ID safe.
//
// The text that comes out is at most 1024 bytes, the limit that [NewPrimary] and [ExtendPrimary]
// apply, and is accepted by both; those two refuse any other user ID that does not have exactly
// this shape.
func UserID(name, label, address string, test bool) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	if err := checkLabel(label); err != nil {
		return "", err
	}
	if err := checkAddress(address); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(name)
	b.WriteString(releaseRoot)
	b.WriteString(label)
	if test {
		b.WriteString(testMark)
	}
	b.WriteString(" <")
	b.WriteString(address)
	b.WriteString(">")
	if b.Len() > maxUserID {
		return "", fail(ErrParams, "the user ID is longer than %d bytes", maxUserID)
	}
	return b.String(), nil
}

// checkName applies the rule of the key `name` (docs/reference/bundle.md). A '<' or a '>' is outside
// its characters, so the name cannot open or close the address.
func checkName(name string) error {
	if name == "" || len(name) > maxName {
		return fail(ErrParams, "the name is not 1 to %d characters", maxName)
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		case c == ' ':
			if i == 0 || i == len(name)-1 || name[i-1] == ' ' {
				return fail(ErrParams, "the name has a space at its start or its end, or two spaces in a row")
			}
		default:
			return fail(ErrParams, "the name holds a character other than an ASCII letter, a digit, a space or a hyphen")
		}
	}
	return nil
}

// checkLabel applies the rule of the key `label` (docs/reference/bundle.md, root-list.md): one ASCII
// capital letter, which is never '<' or '>'.
func checkLabel(label string) error {
	if len(label) != 1 || label[0] < 'A' || label[0] > 'Z' {
		return fail(ErrParams, "the label is not one capital letter from A to Z")
	}
	return nil
}

// checkAddress applies the rule for the address: printable ASCII, no space, no '<', no '>', and
// exactly one '@' with a part before it and a part after it.
func checkAddress(address string) error {
	at := 0
	for i := 0; i < len(address); i++ {
		switch c := address[i]; {
		case c == '<' || c == '>':
			return fail(ErrParams, "the address holds an angle bracket")
		case c <= ' ' || c > '~':
			return fail(ErrParams, "the address holds a character that is not printable ASCII without a space")
		case c == '@':
			at++
		}
	}
	if at != 1 {
		return fail(ErrParams, "the address does not hold exactly one '@'")
	}
	if address[0] == '@' || address[len(address)-1] == '@' {
		return fail(ErrParams, "the address has nothing before or after its '@'")
	}
	return nil
}

// checkUserID refuses a user ID that is empty, is longer than 1024 bytes, is not UTF-8, or holds a
// character that no person can read as written: a control character (a line break, a NUL, an
// escape), a format character (the direction marks and the zero-width characters), a combining
// mark, a code point with no assigned meaning, a line or paragraph separator, a private-use code
// point, a noncharacter, or a space other than the plain space U+0020. It then requires the shape
// that [UserID] writes, and applies the rules of that function to each part.
func checkUserID(id string) error {
	if err := checkUserIDText(id); err != nil {
		return err
	}
	return checkUserIDShape(id)
}

// checkUserIDText is the character rules of [checkUserID], with no shape.
func checkUserIDText(id string) error {
	if id == "" {
		return fail(ErrParams, "the user ID is empty")
	}
	if len(id) > maxUserID {
		return fail(ErrParams, "the user ID is longer than %d bytes", maxUserID)
	}
	if !utf8.ValidString(id) {
		return fail(ErrParams, "the user ID is not UTF-8")
	}
	for _, r := range id {
		switch {
		case r == ' ':
		case unicode.IsControl(r):
			return fail(ErrParams, "the user ID holds a control character (U+%04X)", r)
		case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs, unicode.Co, unicode.Cs):
			return fail(ErrParams, "the user ID holds a format, separator or private-use character (U+%04X)", r)
		case unicode.In(r, unicode.M):
			return fail(ErrParams, "the user ID holds a combining mark (U+%04X)", r)
		case isNoncharacter(r):
			return fail(ErrParams, "the user ID holds a noncharacter (U+%04X)", r)
		case !isAssigned(r):
			return fail(ErrParams, "the user ID holds a code point with no assigned meaning (U+%04X)", r)
		}
	}
	return nil
}

// checkPersonUserID is the rule for a NEW user ID of a person's own key (record 0008, rule 16), which has
// the name and the address that the person gives, in any form and with no shape of a release root's. It is
// printable ASCII only: the bytes 0x20 to 0x7E, with no space at the start or the end, not empty and at
// most 1024 bytes. The wanted files that feed it are ASCII, and a text of ASCII has no letter that is
// invisible, no letter that is read from right to left, and no two letters that look the same. A user ID
// that the key already has keeps its exact bytes and is held to [checkExistingUserID].
func checkPersonUserID(id string) error {
	if id == "" {
		return fail(ErrParams, "the user ID is empty")
	}
	if len(id) > maxUserID {
		return fail(ErrParams, "the user ID is longer than %d bytes", maxUserID)
	}
	for i := 0; i < len(id); i++ {
		if id[i] < ' ' || id[i] > '~' {
			return fail(ErrParams, "the user ID holds a character that is not printable ASCII (byte %d)", i)
		}
	}
	if id[0] == ' ' || id[len(id)-1] == ' ' {
		return fail(ErrParams, "the user ID has a space at its start or its end")
	}
	return nil
}

// checkExistingUserID is the rule for a user ID that a person's key already has and that a later
// signature covers again, by its exact bytes from the snapshot of the reader: whatever its shape (a
// comment, letters outside ASCII, no address), it is accepted when it is not empty, is UTF-8, is at
// most [MaxForeignUserIDBytes] bytes (the limit of the reader), and holds no control character, no format
// character and no line or paragraph separator. A combining mark, which a decomposed accent is, passes
// here and not in [checkPersonUserID]: the user ID is the person's own, and the bytes are not changed.
func checkExistingUserID(text []byte) error {
	if len(text) == 0 {
		return fail(ErrParams, "the user ID is empty")
	}
	if len(text) > MaxForeignUserIDBytes {
		return fail(ErrParams, "the user ID is longer than MaxForeignUserIDBytes (%d bytes)", MaxForeignUserIDBytes)
	}
	if !utf8.Valid(text) {
		return fail(ErrParams, "the user ID is not UTF-8")
	}
	for _, r := range string(text) {
		switch {
		case unicode.IsControl(r):
			return fail(ErrParams, "the user ID holds a control character (U+%04X)", r)
		case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			return fail(ErrParams, "the user ID holds a format character or a line or paragraph separator (U+%04X)", r)
		}
	}
	return nil
}

// checkUserIDShape requires "NAME Release Root LABEL[ (TEST ONLY)] <ADDRESS>" with each part as
// [UserID] requires. The name has no '<', so the last " Release Root " and the last " <" split
// the text in one way only.
func checkUserIDShape(id string) error {
	rest, ok := strings.CutSuffix(id, ">")
	if !ok {
		return fail(ErrParams, "the user ID does not end with the address in angle brackets")
	}
	i := strings.LastIndex(rest, " <")
	if i < 0 {
		return fail(ErrParams, "the user ID has no address in angle brackets")
	}
	head, address := rest[:i], rest[i+2:]
	head, _ = strings.CutSuffix(head, testMark)
	j := strings.LastIndex(head, releaseRoot)
	if j < 0 {
		return fail(ErrParams, "the user ID is not \"<name> Release Root <label> <address>\"")
	}
	if err := checkName(head[:j]); err != nil {
		return err
	}
	if err := checkLabel(head[j+len(releaseRoot):]); err != nil {
		return err
	}
	return checkAddress(address)
}

// isAssigned tells whether r has a meaning in the Unicode version of the standard library: it is in one
// of the categories that a code point can have except unassigned (Cn). The table unicode.C is no help
// here, since it holds the unassigned code points too: its parts are named.
func isAssigned(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
		unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
}

// isNoncharacter tells whether r is one of the 66 code points that Unicode keeps out of text.
func isNoncharacter(r rune) bool {
	return (r >= 0xFDD0 && r <= 0xFDEF) || r&0xFFFE == 0xFFFE
}
