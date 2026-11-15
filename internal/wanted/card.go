package wanted

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"ritueel.id/ritueel/internal/fsx"
)

// The limits of a card file. Passing one is an error. The values are proposed: no page states them.
const (
	// MaxCards is the most card files that one bundle holds and that a reader of the whole folder accepts.
	// [ListCardNames] does not apply it: that is the caller's check, so that one rule judges the folder
	// in one place.
	MaxCards = 64
	// MaxSerialDigits is the most digits of a serial: ten, the most that a 32-bit number has.
	MaxSerialDigits = 10
	// MaxApplications is the most entries of the member applications: the three that exist, none twice.
	MaxApplications = 3
	// FirstBundleRow is the first row of the card that a bundle may hold. Row 1 is the card's own jobs
	// (record 0003, rule 3).
	FirstBundleRow = 2
	// LastRow is the last row of the card (record 0003, rule 3).
	LastRow = 6
	// MaxOtherRows is the most rows of other bundles that one card file declares: the rows [FirstBundleRow]
	// to [LastRow], each once. It is not one less: the row that stays free in a steady state (record 0003,
	// rule 7) is filled by a replacement born beside the old keys, so a card in that state can have all five
	// rows in use, and a bundle that holds none of them declares all five.
	MaxOtherRows = LastRow - FirstBundleRow + 1
)

// otherRowsMember is the name of the member that declares the rows of other bundles (record 0003, rule 10:
// "declared in the wanted card file"; docs/reference/cards.md, "The card file", names the member).
const otherRowsMember = "other_rows"

// CardKind is one of the four kinds of card (record 0003, rule 11). A card has one kind and never changes it.
type CardKind string

// The four kinds of card.
const (
	// CardRoot holds root keys by row.
	CardRoot CardKind = "root"
	// CardDayToDay holds a person's signing and authentication subkeys, and passkeys.
	CardDayToDay CardKind = "day-to-day"
	// CardServer stays plugged into a server of a requester system.
	CardServer CardKind = "server"
	// CardRehearsal is for practice and tests.
	CardRehearsal CardKind = "rehearsal"
)

// Application is an application of a card that a bundle uses.
type Application string

// The applications of a card that a card file may list.
const (
	// AppPIV is the PIV application: the four slots of a row hold the keys of a bundle.
	AppPIV Application = "piv"
	// AppOpenPGP is the OpenPGP application.
	AppOpenPGP Application = "openpgp"
	// AppFIDO2 is the FIDO2 application.
	AppFIDO2 Application = "fido2"
)

// cardMembers is the table of the members of a wanted card file, in the order of docs/reference/cards.md,
// "The card file". A test compares it with the schema block of that page.
var cardMembers = []member{
	{name: "version", required: true},
	{name: "serial", required: true},
	{name: "kind", required: true, enum: cardKindEnum},
	{name: "applications", required: true, enum: applicationEnum},
	{name: otherRowsMember},
}

// Card is a wanted card file as it was read: the serial, the kind, the applications that the bundle uses
// and the rows of other bundles that the card declares. Only [ParseCard] and [LoadCard] make a usable
// one: see [Card.Valid]. It holds no state of a card and was made without reading one.
type Card struct {
	// File is the file as stored, with its bytes and digest.
	File File
	// Name is the name of the card: the file name without ".yaml".
	Name string
	// Serial is 1 to [MaxSerialDigits] digits, as written. Compare serials only through [SerialKey].
	Serial string
	// Kind is the kind of the card.
	Kind CardKind
	// Applications are 1 to [MaxApplications] applications, none twice, in the order written.
	Applications []Application
	// OtherRows are the rows of other bundles that the card declares, [FirstBundleRow] to [LastRow], none
	// twice, in the order written. It is nil when the member is absent or empty.
	OtherRows []int

	made bool
}

// Valid reports whether c was made by [ParseCard] or [LoadCard]. It is false for a nil Card, for the zero
// value and for a Card that a caller built by hand.
func (c *Card) Valid() bool { return c != nil && c.made }

// SerialKey returns the one identity of the serial of c: the digits without leading zeros, and "0" for a
// serial of only zeros. It is "" for a nil Card and for a Card with no usable serial. Two cards are the
// same card when their SerialKey is equal and not empty. Comparisons use SerialKey, never the text of
// Serial, which is kept as written.
func (c *Card) SerialKey() string {
	if c == nil {
		return ""
	}
	return SerialKey(c.Serial)
}

// cardPath is the path of the wanted card file of a name, which is a valid name.
func cardPath(name string) string { return CardsDir + "/" + name + yamlSuffix }

// SerialKey returns the form of a serial in which two serials of one number are equal: the digits without
// leading zeros, and "0" for a serial of only zeros. It returns "" for a text that is not 1 to
// [MaxSerialDigits] ASCII digits. A caller compares serials only through this function.
func SerialKey(serial string) string {
	if serial == "" || len(serial) > MaxSerialDigits {
		return ""
	}
	for i := 0; i < len(serial); i++ {
		if serial[i] < '0' || serial[i] > '9' {
			return ""
		}
	}
	if key := strings.TrimLeft(serial, "0"); key != "" {
		return key
	}
	return "0"
}

// LoadCard reads want/cards/NAME.yaml through package fsx and parses it with [ParseCard]. A file that does
// not exist is an error that wraps fs.ErrNotExist, and a file over the limit of a read is one that wraps
// [fsx.ErrTooLarge]; a file over [MaxBytes] and under that limit is an [*Error] with no cause. A caller that
// judges a whole folder tells a fault of the file from a fault of the system by that difference.
func LoadCard(fsys fsx.FS, name string) (*Card, error) {
	if err := ValidName(name); err != nil {
		return nil, errorf(cardPath(name), 0, err.Error())
	}
	data, err := readFile(fsys, cardPath(name))
	if err != nil {
		return nil, err
	}
	return ParseCard(name, data)
}

// ListCardNames lists want/cards once and returns the names (without ".yaml"), in the order of the names,
// and reads no file. It judges the folder as [ListRootNames] judges want/roots: a folder that does not
// exist gives no name; an entry whose name starts with ".rt-", in any case of the letters, is the
// leftover of a stopped write and is skipped, whatever kind of entry it is, and it does not count toward
// [MaxFiles] (record 0006, rule 45); any other name that is not NAME.yaml with a NAME that passes
// [ValidName] is an error; a link, a folder or a FIFO is an error; more than [MaxFiles] names is an error.
// It does not apply [MaxCards]: that is the caller's check. An error returns no name.
func ListCardNames(fsys fsx.FS) ([]string, error) {
	return listNames(fsys, CardsDir, ValidName)
}

// ParseCard reads the bytes of the wanted card file NAME: version 1, serial, kind, applications and the
// optional other_rows. It reads no other file and no card. The member holder and the member kept, which the
// pages of the bundle once listed, are an error that says a later version may read them. It returns a card or
// an error, never both.
func ParseCard(name string, data []byte) (*Card, error) {
	path := cardPath(name)
	if err := ValidName(name); err != nil {
		return nil, errorf(path, 0, err.Error())
	}
	d, err := read(path, data)
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		k := d.root.Content[i]
		if k.Value == "holder" || k.Value == "kept" {
			return nil, d.fail(k, "the member \""+shown(k.Value)+"\" is not read in this version: a card file holds version, serial, kind, applications and "+otherRowsMember+" now")
		}
	}
	top, err := d.mappingOf(d.root, "", cardMembers)
	if err != nil {
		return nil, err
	}
	c := &Card{File: d.file, Name: name}
	if _, err := top.version(); err != nil {
		return nil, err
	}
	if c.Serial, err = top.serial(); err != nil {
		return nil, err
	}
	kind, err := top.enumStr("kind", cardKindEnum)
	if err != nil {
		return nil, err
	}
	c.Kind = CardKind(kind)
	if c.Applications, err = top.applications(); err != nil {
		return nil, err
	}
	if top.has(otherRowsMember) {
		if c.OtherRows, err = top.otherRows(slices.Contains(c.Applications, AppPIV)); err != nil {
			return nil, err
		}
	}
	c.made = true
	return c, nil
}

// serial reads the member serial: a string of 1 to [MaxSerialDigits] ASCII digits, written in quotes.
func (m *mapping) serial() (string, error) {
	s, err := m.str("serial")
	if err != nil {
		return "", err
	}
	if SerialKey(s) == "" {
		return "", m.d.fail(m.val["serial"], fmt.Sprintf("serial must be 1 to %d digits and nothing else", MaxSerialDigits))
	}
	return s, nil
}

// applications reads the member applications: 1 to [MaxApplications] entries, each one of the three, none
// twice. The length is checked before the first entry is read.
func (m *mapping) applications() ([]Application, error) {
	v := m.val["applications"]
	if v.Kind == yaml.SequenceNode && len(v.Content) > MaxApplications {
		return nil, m.d.fail(v, fmt.Sprintf("applications must hold at most %d entries", MaxApplications))
	}
	list, err := m.strings("applications", 1, applicationEnum)
	if err != nil {
		return nil, err
	}
	out := make([]Application, len(list))
	for i, s := range list {
		out[i] = Application(s)
	}
	return out, nil
}

// otherRows reads the member other_rows: 0 to [MaxOtherRows] rows, each from [FirstBundleRow] to [LastRow],
// none twice. A row is four PIV slots, so a non-empty list needs the application piv (hasPIV). An empty list
// means the same as no member and gives nil.
func (m *mapping) otherRows(hasPIV bool) ([]int, error) {
	rows, err := m.integers(otherRowsMember, MaxOtherRows, FirstBundleRow, LastRow)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if !hasPIV {
		return nil, m.fail(otherRowsMember, otherRowsMember+" needs piv in applications: a row is four PIV slots")
	}
	return rows, nil
}
