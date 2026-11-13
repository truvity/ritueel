package strictjson

import (
	"fmt"
	"strings"
)

// Helpers for the tests of the member-name rule, of Quote and of the texts that show a name. A JSON
// escape of the form backslash, u and four digits is never written out in the test files: qesc
// builds one from a code point, so that no tool can turn it into the character on the way.

// qesc is the escape that jsonset.Quote writes for a character that is not printable ASCII: the
// escape of its code point in lower case, and for a character above U+FFFF the escapes of its two
// surrogates (worked out here by hand).
func qesc(r rune) string {
	if r > 0xFFFF {
		v := r - 0x10000
		return fmt.Sprintf("%cu%04x%cu%04x", '\\', 0xD800+(v>>10), '\\', 0xDC00+(v&0x3FF))
	}
	return fmt.Sprintf("%cu%04x", '\\', r)
}

// quotedName is a name as an error shows it when it is not plain: in quotes, a quote or a
// backslash after a backslash, printable ASCII as it is and everything else as qesc.
func quotedName(name string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range name {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			b.WriteString(qesc(r))
		}
	}
	b.WriteByte('"')
	return b.String()
}

// shownName is a name as an error shows it: itself when it is plain (ASCII letters, digits,
// underscores and hyphens, and not longer than 40 bytes), else quotedName.
func shownName(name string) string {
	plain := name != "" && len(name) <= 40
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			plain = false
		}
	}
	if plain {
		return name
	}
	return quotedName(name)
}

// pathStep is the member step of a path for the name: a dot and the name as shownName writes it.
func pathStep(name string) string { return "." + shownName(name) }
