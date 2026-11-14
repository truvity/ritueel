package software

import (
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
)

// MaxKeyFileSize is the most bytes of a key file that the package reads or writes. It is checked
// before anything is parsed (docs/reference/bundle.md has no limit; this one is proposed).
const MaxKeyFileSize = 64 << 10

// Limits of the small files, each stated once.
const (
	// maxRevocationSize is the most bytes of one OpenPGP signature packet.
	maxRevocationSize = 1 << 10
	// maxRemovalSize is the most bytes of a compact JWS.
	maxRemovalSize = 4 << 10
	// keyFilePerm is the mode that every key file is written with.
	keyFilePerm = 0o600
)

// FileKind is one of the four kinds of key file of a root.
type FileKind string

// The four kinds of key file (docs/reference/bundle.md, "The software root's key files").
const (
	// FileX509 is the X.509 root key.
	FileX509 FileKind = "x509"
	// FileOpenPGP is the OpenPGP primary.
	FileOpenPGP FileKind = "openpgp"
	// FileRevocation is a revocation signature of the primary.
	FileRevocation FileKind = "revocation"
	// FileRemoval is the removal authorisation of the X.509 root key.
	FileRemoval FileKind = "removal"
)

// Purpose says which key a passphrase is for: the root's label and the kind of file.
type Purpose struct {
	Label string
	File  FileKind
}

// reasons are the reasons of a revocation signature (docs/reference/revocation-material.md, "What
// is made"). The list is the one of internal/openpgp; there is no second copy.
var reasons = []openpgp.Reason{openpgp.Compromised, openpgp.Superseded, openpgp.Retired, openpgp.NoReason}

// reasonOK reports whether reason is one of the four.
func reasonOK(reason string) bool {
	for _, r := range reasons {
		if r.Text == reason {
			return true
		}
	}
	return false
}

// labelOK reports whether label is one upper-case ASCII letter (docs/reference/bundle.md,
// root.json `label`).
func labelOK(label string) bool {
	return len(label) == 1 && label[0] >= 'A' && label[0] <= 'Z'
}

// The names of the key files of each mode, in one table (docs/reference/bundle.md, "The software
// root's key files"). Proposed for a test root (issue 136); the names of the passphrase files are
// the page's. A name is <label> + a suffix; the suffix of a revocation file holds the reason.
const (
	// suffix of the files of a test root
	testX509    = ".x509.key.pem"
	testOpenPGP = ".openpgp.key.asc"
	testRevoke  = ".asc" // after ".revocation.<reason>"
	testRemoval = ".removal.jws"
	// suffix of the files of a passphrase root
	ageX509    = ".x509.key.age"
	ageOpenPGP = ".openpgp.key.age"
	ageRevoke  = ".pgp.age" // after ".revocation.<reason>"
	ageRemoval = ".removal.jws.age"
)

// fileName is the name of the key file of a label, kind and reason in a mode. The label and the
// reason have been checked.
func fileName(mode Mode, label string, kind FileKind, reason string) string {
	age := mode == ModePassphrase
	switch kind {
	case FileX509:
		return label + pick(age, ageX509, testX509)
	case FileOpenPGP:
		return label + pick(age, ageOpenPGP, testOpenPGP)
	case FileRevocation:
		return label + ".revocation." + reason + pick(age, ageRevoke, testRevoke)
	case FileRemoval:
		return label + pick(age, ageRemoval, testRemoval)
	}
	return ""
}

func pick(age bool, ageText, testText string) string {
	if age {
		return ageText
	}
	return testText
}

// nameMode tells which mode a file name belongs to: ModeTest or ModePassphrase for the name of a
// key file of that mode, and 0 for any other name. The name has passed [fsx.CheckName].
func nameMode(name string) Mode {
	if len(name) < 2 || !labelOK(name[:1]) {
		return 0
	}
	rest := name[1:]
	switch rest {
	case testX509, testOpenPGP, testRemoval:
		return ModeTest
	case ageX509, ageOpenPGP, ageRemoval:
		return ModePassphrase
	}
	if after, ok := strings.CutPrefix(rest, ".revocation."); ok {
		for _, r := range reasons {
			switch after {
			case r.Text + testRevoke:
				return ModeTest
			case r.Text + ageRevoke:
				return ModePassphrase
			}
		}
	}
	return 0
}

// isKeyFileName reports whether a name listed in the key directory is the name of a key file of
// either mode. A name that is not a valid file name, or that starts with the temporary prefix,
// is not.
func isKeyFileName(name string) (Mode, bool) {
	if fsx.CheckName(name) != nil {
		return 0, false
	}
	m := nameMode(name)
	return m, m != 0
}
