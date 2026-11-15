package trustset

import (
	"io/fs"
	"slices"

	"ritueel.id/ritueel/internal/rootlist"
)

// The names of the files of a trust set. They are the three files that the bundle page lists in
// "The layout" for a trust set (record 0006, rule 12 says that a trust set is one numbered folder
// and links to that row). This block and fileTable are the one place in this package that names
// a file; a fourth file is one more row of fileTable.
const (
	// RootListFile is the root list, in the canonical form of RFC 8785.
	RootListFile = "root-list.json"
	// RootListJWSFile is the detached general JWS over RootListFile.
	RootListJWSFile = "root-list.jws"
	// CABundleFile is the certificates of the active root keys, with the trust sequence in the
	// first line.
	CABundleFile = "ca-bundle.pem"
)

// FileMode is the mode of every file of a trust set: public material that a host and a person
// read, so 0o644. It is a proposed value (the pages are silent); a file system that ignores modes
// ignores it.
const FileMode fs.FileMode = 0o644

// Limits. Passing one is an error that wraps ErrParams.
const (
	// MaxRoots is the most root keys in one list, the most entries in removals and the most
	// signatures in one file: a label is one of A to Z (list page, "The list").
	MaxRoots = 26
	// MaxBytes is the most bytes of root-list.json, of root-list.jws, of ca-bundle.pem, of one
	// removal authorisation and of one certificate.
	MaxBytes = rootlist.MaxBytes
	// MaxEarlier is the most earlier root lists that a caller may give to the builder of a draft.
	MaxEarlier = 4096
)

// fileTable lists the files of a trust set in the order they are written.
var fileTable = [...]string{RootListFile, RootListJWSFile, CABundleFile}

// FileNames returns the names of the files of a trust set in the order they are written. The
// result is a new list on every call.
func FileNames() []string {
	return slices.Clone(fileTable[:])
}
