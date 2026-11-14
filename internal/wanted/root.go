package wanted

import (
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

// rootMembers is the table of the members of a wanted root file that this version reads. The page lists what
// the file holds, and gives no more member names (issue #8): the keys, the retirement date and the revocation
// reasons are read from the first apply on.
var rootMembers = []member{
	{name: "version", required: true},
	{name: "kind", required: true, enum: rootKindEnum},
	{name: "test"},
}

// Root is the smallest wanted root file: its kind and whether it is a test root. Only [ParseRoot] and
// [LoadRoot] make a usable one: see [Root.Valid].
type Root struct {
	// File is the file as stored, with its bytes and digest.
	File File
	// Name is the name of the root, the file name without ".yaml".
	Name string
	// Kind is the kind of the root.
	Kind RootKind
	// Test is true for a test root. It is false when the member is not there.
	Test bool

	made bool
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

// ParseRoot reads the bytes of the wanted root file NAME: version 1, kind (x509, openpgp or ssh) and the
// optional test. Any other member is an error that says the other members are read from the first apply on.
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
			return nil, d.fail(k, "the member \""+shown(k.Value)+"\" is not read yet: a root file holds version, kind and test now, and its keys, the retirement date and the revocation reasons are read from the first apply on")
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
	r.made = true
	return r, nil
}
