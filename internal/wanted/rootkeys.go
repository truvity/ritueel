package wanted

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// The limits of the keys of a root file.
const (
	// MaxKeys is the most entries of keys.
	MaxKeys = 8
	// FingerprintLen is the length of the fingerprint of a version 4 OpenPGP key: 40 hexadecimal digits.
	FingerprintLen = 40
	// firstYear and lastYear are the years that a date of a root file may have.
	firstYear, lastYear = 2000, 2105
)

// PlaceholderFingerprint is the fingerprint that the starter of a personal bundle holds until the person
// writes the fingerprint of their own key: 40 zeros. It is refused by name.
var PlaceholderFingerprint = strings.Repeat("0", FingerprintLen)

// KeyRole is the role of a key of a root file.
type KeyRole string

// The roles of a key. Only [RoleAdopted] is built. The roles published and standby belong to stage two, which
// is not built: the reader refuses them by name and reads nothing else of such a key (see [Key]).
const (
	// RoleAdopted is a key the person already has, taken over as it is.
	RoleAdopted   KeyRole = "adopted"
	rolePublished KeyRole = "published"
	roleStandby   KeyRole = "standby"
)

// reservedKeyMembers are the members of a key that belong to stage two, which is not built. They are refused by
// name, and their values are never read or checked.
var reservedKeyMembers = []string{"card", "replaces", "overlap_until", "retire_on", "retire_reason"}

// keyMembers is the table of the members of a key that this version reads. fingerprint and valid_until are
// required for the role adopted, which is the only role built, and are checked by the code.
var keyMembers = []member{
	{name: "label", required: true},
	{name: "role", required: true},
	{name: "fingerprint"},
	{name: "valid_until"},
}

// Date is a day of the calendar, from the year 2000 to the year 2105. The zero value is no date.
type Date struct {
	year  int
	month time.Month
	day   int
}

// IsZero reports whether d is no date.
func (d Date) IsZero() bool { return d.year == 0 }

// String is the date as YYYY-MM-DD, and "" for no date.
func (d Date) String() string {
	if d.IsZero() {
		return ""
	}
	return fmt.Sprintf("%04d-%02d-%02d", d.year, int(d.month), d.day)
}

// Time is 00:00 UTC of the day, which is the moment a key that is valid until it expires. It is the zero time
// for no date.
func (d Date) Time() time.Time {
	if d.IsZero() {
		return time.Time{}
	}
	return time.Date(d.year, d.month, d.day, 0, 0, 0, 0, time.UTC)
}

// Key is one key of an OpenPGP root file. Only the role adopted is built: a key the person already has, with
// its fingerprint and the day it expires. The roles published and standby and the members card, replaces,
// overlap_until, retire_on and retire_reason are reserved for stage two, which is not built yet: a file that
// holds one is refused by name, and nothing of it is read, so a stage-one file stays valid when stage two is
// built. A Key has no reference inside it, so a copy is a whole copy.
type Key struct {
	// Label is one letter, A to Z, that is not used by another key of the file.
	Label string
	// Role is [RoleAdopted].
	Role KeyRole
	// Fingerprint is 40 hexadecimal digits in lower case.
	Fingerprint string
	// ValidUntil is the day the key expires, at 00:00 UTC of that day, set once at adoption.
	ValidUntil Date

	line int
}

// keys reads the member keys: 1 to [MaxKeys] entries. The length is checked before the first entry is read.
func (m *mapping) keys() ([]Key, error) {
	v := m.val[rootMemberKeys]
	if v.Kind != yaml.SequenceNode {
		return nil, m.d.fail(v, rootMemberKeys+" must be a list")
	}
	if len(v.Content) == 0 || len(v.Content) > MaxKeys {
		return nil, m.d.fail(v, fmt.Sprintf("%s must hold 1 to %d entries", rootMemberKeys, MaxKeys))
	}
	out := make([]Key, 0, len(v.Content))
	for i, e := range v.Content {
		at := fmt.Sprintf("%s[%d]", rootMemberKeys, i+1)
		k, err := m.keyEntry(e, at)
		if err != nil {
			return nil, err
		}
		for _, p := range out {
			switch {
			case p.Label == k.Label:
				return nil, m.d.fail(e, at+".label is used twice: each key has its own label")
			case p.Fingerprint == k.Fingerprint:
				return nil, m.d.fail(e, at+".fingerprint is the fingerprint of an earlier key: a key is listed once")
			case p.Role == k.Role:
				return nil, m.d.fail(e, at+".role adopted is used twice: at most one key is adopted")
			}
		}
		out = append(out, k)
	}
	return out, nil
}

// keyEntry reads one entry of keys; at names it in a message.
func (m *mapping) keyEntry(e *yaml.Node, at string) (Key, error) {
	if e.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(e.Content); i += 2 {
			if name := e.Content[i].Value; slices.Contains(reservedKeyMembers, name) {
				return Key{}, m.d.fail(e.Content[i], at+": the member "+name+" is reserved for stage two, which is not built yet; remove it")
			}
		}
	}
	km, err := m.d.mappingOf(e, at, keyMembers)
	if err != nil {
		return Key{}, err
	}
	k := Key{line: e.Line}
	if k.Label, err = km.str("label"); err != nil {
		return Key{}, err
	}
	if len(k.Label) != 1 || k.Label[0] < 'A' || k.Label[0] > 'Z' {
		return Key{}, km.fail("label", at+".label is one letter from A to Z")
	}
	role, err := km.str("role")
	if err != nil {
		return Key{}, err
	}
	switch KeyRole(role) {
	case RoleAdopted:
		k.Role = RoleAdopted
	case rolePublished, roleStandby:
		return Key{}, km.fail("role", at+".role "+role+" is reserved for stage two, which is not built yet; the role adopted is read now")
	default:
		return Key{}, km.fail("role", at+".role must be adopted (the roles published and standby are reserved for stage two, which is not built yet)")
	}
	if err := km.adopted(&k, at); err != nil {
		return Key{}, err
	}
	return k, nil
}

// adopted reads the members of a key of the role adopted: its fingerprint and the day it expires.
func (km *mapping) adopted(k *Key, at string) error {
	for _, name := range []string{"fingerprint", "valid_until"} {
		if !km.has(name) {
			return km.d.fail(km.node, "the member "+at+"."+name+" is required for the role adopted")
		}
	}
	fp, err := km.str("fingerprint")
	if err != nil {
		return err
	}
	if len(fp) != FingerprintLen || strings.Trim(fp, "0123456789abcdefABCDEF") != "" {
		return km.fail("fingerprint", at+".fingerprint is 40 hexadecimal digits")
	}
	if k.Fingerprint = strings.ToLower(fp); k.Fingerprint == PlaceholderFingerprint {
		return km.fail("fingerprint", at+".fingerprint is the placeholder of the starter: replace the placeholder with the fingerprint of your key")
	}
	day, err := km.str("valid_until")
	if err != nil {
		return err
	}
	var why string
	if k.ValidUntil, why = parseDate(day); why != "" {
		return km.fail("valid_until", at+".valid_until "+why)
	}
	return nil
}

// parseDate reads a day written YYYY-MM-DD, and says what is wrong in fixed words and numbers: the text of the
// date is never echoed.
func parseDate(s string) (Date, string) {
	const form = "is a date written \"YYYY-MM-DD\" in quotes, such as \"2029-11-26\""
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return Date{}, form
	}
	num := func(from, to int) (int, bool) {
		n := 0
		for _, c := range []byte(s[from:to]) {
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		return n, true
	}
	y, okY := num(0, 4)
	mo, okM := num(5, 7)
	d, okD := num(8, 10)
	switch {
	case !okY || !okM || !okD:
		return Date{}, form
	case y < firstYear || y > lastYear:
		return Date{}, fmt.Sprintf("has a year from %d to %d", firstYear, lastYear)
	}
	if t := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC); t.Year() != y || int(t.Month()) != mo || t.Day() != d {
		return Date{}, "is not a day of the calendar"
	}
	return Date{year: y, month: time.Month(mo), day: d}, ""
}
