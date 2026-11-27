package wanted

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"ritueel.id/ritueel/internal/fsx"
)

// RootKind is the kind of a root: the kind of key it holds.
type RootKind string

// The three kinds of a root.
const (
	// RootX509 is an X.509 root.
	RootX509 RootKind = "x509"
	// RootOpenPGP is an OpenPGP root.
	RootOpenPGP RootKind = "openpgp"
	// RootSSH is an SSH CA root.
	RootSSH RootKind = "ssh"
)

// The members of a wanted root file that only a root of the kind openpgp holds.
const (
	rootMemberReasons    = "revocation_reasons"
	rootMemberKeys       = "keys"
	rootMemberEncryption = "encryption"
)

// maxReasons is the most words that revocation_reasons holds: the four reasons, none twice.
const maxReasons = 4

// reasonWords are the four reasons for revocation that a root file may list, in the order that the plan makes
// them (record 0007, rule 21; docs/reference/revocation-material.md, "What is made"). The first two are made
// for every OpenPGP primary whether the file lists them or not. The array is not exported: a caller gets a copy
// from [RevocationReasonWords].
var reasonWords = [maxReasons]string{"compromised", "superseded", "retired", "no-reason"}

// RevocationReasonWords returns a copy of the four words that revocation_reasons may hold: compromised,
// superseded, retired and no-reason.
func RevocationReasonWords() []string { return slices.Clone(reasonWords[:]) }

// rootMembers is the table of the members of a wanted root file that this version reads. keys, encryption and
// revocation_reasons are for the OpenPGP root of a personal bundle (the members of a key that belong to stage
// two are reserved: see [Key]); the retirement date is read by a later version, and the first apply of a company
// bundle makes two keys of each root by default (record 0005, rule 20).
var rootMembers = []member{
	{name: "version", required: true},
	{name: "kind", required: true, enum: rootKindEnum},
	{name: "test"},
	{name: rootMemberReasons},
	{name: rootMemberKeys},
	{name: rootMemberEncryption},
}

// Root is a wanted root file: its kind, whether it is a test root and, for an OpenPGP root, the revocation
// reasons, the encryption switch and the keys that it lists. The members that only an OpenPGP root holds are
// not exported: read them with [Root.RevocationReasons], [Root.Encryption] and [Root.Keys], which return
// copies, and a later step that needs them re-parses the bytes of File with [ParseRoot] and never trusts a
// field of what it was handed. Only [ParseRoot] and [LoadRoot] make a usable Root: see [Root.Valid].
type Root struct {
	// File is the file as stored, with its bytes and digest.
	File File
	// Name is the name of the root, the file name without ".yaml".
	Name string
	// Kind is the kind of the root.
	Kind RootKind
	// Test is true for a test root. It is false when the member is not there.
	Test bool

	reasons     [maxReasons]string
	nReasons    int
	encryption  bool
	encryptionS bool
	keys        []Key

	made bool
}

// RevocationReasons returns a copy of the words of revocation_reasons, in the order of the file: none to four of
// [RevocationReasonWords], none twice. It is empty when the member is not there, and for a root that is not of
// the kind openpgp.
func (r *Root) RevocationReasons() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.reasons[:r.nReasons])
}

// Encryption returns the value of the member encryption (true: an encryption subkey on every day-to-day card)
// and whether the file has the member at all.
func (r *Root) Encryption() (value, set bool) {
	if r == nil {
		return false, false
	}
	return r.encryption, r.encryptionS
}

// Keys returns a copy of the keys of the file, in the order written. It is empty when the member is not there.
func (r *Root) Keys() []Key {
	if r == nil {
		return nil
	}
	return slices.Clone(r.keys)
}

// Valid reports whether r was made by [ParseRoot] or [LoadRoot]. It is false for a nil Root and for the zero
// value.
func (r *Root) Valid() bool { return r != nil && r.made }

// rootPath is the path of the wanted root file of a name, which is a valid name.
func rootPath(name string) string { return RootsDir + "/" + name + ".yaml" }

// LoadRoot reads want/roots/NAME.yaml through package fsx and parses it.
func LoadRoot(fsys fsx.FS, name string) (*Root, error) {
	if err := ValidName(name); err != nil {
		return nil, errorf(rootPath(name), 0, err.Error())
	}
	data, err := readFile(fsys, rootPath(name))
	if err != nil {
		return nil, err
	}
	return ParseRoot(name, data)
}

// ParseRoot reads the bytes of the wanted root file NAME: version 1, kind (x509, openpgp or ssh), the optional
// test and, in a file of the kind openpgp only, revocation_reasons (at most four words of
// [RevocationReasonWords], none twice), encryption (true or false) and keys (see [Key]). The three members in a
// file of another kind are an error that says they are for the OpenPGP root. Any other member is an error that
// says that a later version reads the other members.
func ParseRoot(name string, data []byte) (*Root, error) {
	path := rootPath(name)
	if err := ValidName(name); err != nil {
		return nil, errorf(path, 0, err.Error())
	}
	d, err := read(path, data)
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		k := d.root.Content[i]
		known := false
		for _, t := range rootMembers {
			known = known || t.name == k.Value
		}
		if !known {
			return nil, d.fail(k, "the member \""+shown(k.Value)+"\" is not read yet: a root file holds version, kind, test, revocation_reasons, keys and encryption now, and its retirement date is read by a later version, and the first apply of a company bundle makes two keys of each root by default")
		}
	}
	top, err := d.mappingOf(d.root, "", rootMembers)
	if err != nil {
		return nil, err
	}
	r := &Root{File: d.file, Name: name}
	if _, err := top.version(); err != nil {
		return nil, err
	}
	kind, err := top.enumStr("kind", rootKindEnum)
	if err != nil {
		return nil, err
	}
	r.Kind = RootKind(kind)
	if top.has("test") {
		if r.Test, err = top.boolean("test"); err != nil {
			return nil, err
		}
	}
	if err := r.takeOpenPGP(top); err != nil {
		return nil, err
	}
	r.made = true
	return r, nil
}

// takeOpenPGP reads the members that only the root of the kind openpgp holds, and refuses them in a file of
// another kind.
func (r *Root) takeOpenPGP(top *mapping) error {
	for _, name := range []string{rootMemberReasons, rootMemberEncryption, rootMemberKeys} {
		if top.has(name) && r.Kind != RootOpenPGP {
			return top.fail(name, "the member "+name+" is for the OpenPGP root file (kind: openpgp) only")
		}
	}
	var err error
	if top.has(rootMemberReasons) {
		var words []string
		if words, err = top.reasons(); err != nil {
			return err
		}
		r.nReasons = copy(r.reasons[:], words)
	}
	if top.has(rootMemberEncryption) {
		if r.encryption, err = top.boolean(rootMemberEncryption); err != nil {
			return err
		}
		r.encryptionS = true
	}
	if top.has(rootMemberKeys) {
		if r.keys, err = top.keys(); err != nil {
			return err
		}
	}
	return nil
}

// reasons reads revocation_reasons: a list of at most [maxReasons] strings, each one of the reason words, none
// twice. The error names the entry and shows the word escaped and cut.
func (m *mapping) reasons() ([]string, error) {
	v := m.val[rootMemberReasons]
	if v.Kind != yaml.SequenceNode {
		return nil, m.d.fail(v, rootMemberReasons+" must be a list")
	}
	if len(v.Content) > maxReasons {
		return nil, m.d.fail(v, fmt.Sprintf("%s holds more than %d words, and there are only %d reasons", rootMemberReasons, maxReasons, maxReasons))
	}
	out := make([]string, 0, len(v.Content))
	for i, e := range v.Content {
		at := fmt.Sprintf("%s entry %d", rootMemberReasons, i+1)
		if e.Kind != yaml.ScalarNode || e.Tag != "!!str" {
			return nil, m.d.fail(e, at+" must be a string: write it in quotes when it looks like a number, a boolean or a date")
		}
		if !slices.Contains(reasonWords[:], e.Value) {
			return nil, m.d.fail(e, at+" is \""+shown(e.Value)+"\", and it must be one of "+strings.Join(reasonWords[:], ", "))
		}
		if slices.Contains(out, e.Value) {
			return nil, m.d.fail(e, at+" repeats an earlier entry, \""+shown(e.Value)+"\"")
		}
		out = append(out, e.Value)
	}
	return out, nil
}
