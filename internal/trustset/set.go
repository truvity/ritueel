package trustset

import (
	"slices"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/rootlist"
)

// Set is the files of one trust set, whole and checked: the three that every set has and, when its
// root list pins OpenPGP primaries, the keyring file. It holds no key. A Set is immutable and every
// accessor returns copies. A zero Set refuses everything.
type Set struct {
	sequence int64
	signers  []string
	listJSON []byte
	listJWS  []byte
	caBundle []byte
	// keyring is the keyring file; nil exactly when the list pins no OpenPGP primary.
	keyring []byte
}

// valid reports whether s was made by Draft.Sign.
func (s *Set) valid() bool {
	return s != nil && s.sequence >= 1 && len(s.listJSON) > 0 && len(s.listJWS) > 0 && len(s.caBundle) > 0
}

// Sequence returns the sequence of the list; 0 for a zero or nil Set.
func (s *Set) Sequence() int64 {
	if !s.valid() {
		return 0
	}
	return s.sequence
}

// Name returns the name of the folder of the trust set: its sequence, a hyphen and the first eight
// characters of the SHA-256 of root-list.json, the result of SetName for them. It is the empty text
// for a zero or nil Set.
func (s *Set) Name() string {
	if !s.valid() {
		return ""
	}
	name, err := SetName(s.sequence, hexSHA256(s.listJSON))
	if err != nil {
		return ""
	}
	return name
}

// Signers returns the labels that signed, in the order of the signatures, which is label order.
func (s *Set) Signers() []string {
	if !s.valid() {
		return nil
	}
	return slices.Clone(s.signers)
}

// ListJSON returns a copy of the bytes of root-list.json.
func (s *Set) ListJSON() []byte {
	if !s.valid() {
		return nil
	}
	return slices.Clone(s.listJSON)
}

// ListJWS returns a copy of the bytes of root-list.jws.
func (s *Set) ListJWS() []byte {
	if !s.valid() {
		return nil
	}
	return slices.Clone(s.listJWS)
}

// CABundle returns a copy of the bytes of ca-bundle.pem.
func (s *Set) CABundle() []byte {
	if !s.valid() {
		return nil
	}
	return slices.Clone(s.caBundle)
}

// Keyring returns a copy of the bytes of the keyring file; nil for a set whose list pins no OpenPGP
// primary, and for a zero or nil Set.
func (s *Set) Keyring() []byte {
	if !s.valid() || s.keyring == nil {
		return nil
	}
	return slices.Clone(s.keyring)
}

// hasKeyring reports whether the set holds a keyring file, and whether that agrees with its list:
// a list that pins OpenPGP primaries needs the file, and a list that pins none must not have one
// (bundle page, "The layout"; keyring page, "The first form of the keyring file"). A set whose list
// cannot be read agrees with nothing.
func (s *Set) hasKeyring() (has, ok bool) {
	list, err := rootlist.ParseList(s.listJSON)
	if err != nil {
		return false, false
	}
	pins := false
	for _, r := range list.Roots {
		if r.OpenPGPFingerprint != "" {
			pins = true
			break
		}
	}
	has = len(s.keyring) > 0
	return has, pins == has
}

// Files returns the files of the set in the order of FileNames, and the keyring file after them
// when the list pins OpenPGP primaries, each with FileMode, ready for fsx.Writer.WriteSet. The data
// are copies. A zero or nil Set has no files, and neither has a set whose keyring file does not
// agree with its list (a list that pins primaries and no file, or a file and a list that pins none).
func (s *Set) Files() []fsx.NewFile {
	if !s.valid() {
		return nil
	}
	has, ok := s.hasKeyring()
	if !ok {
		return nil
	}
	names := FileNames()
	if has {
		names = append(names, KeyringFile)
	}
	out := make([]fsx.NewFile, 0, len(names))
	for _, name := range names {
		var data []byte
		switch name {
		case RootListFile:
			data = s.listJSON
		case RootListJWSFile:
			data = s.listJWS
		case CABundleFile:
			data = s.caBundle
		case KeyringFile:
			data = s.keyring
		default:
			// A name that this package has no bytes for: no file is made up for it.
			return nil
		}
		out = append(out, fsx.NewFile{Name: name, Data: slices.Clone(data), Perm: FileMode})
	}
	return out
}

// Write writes the set into finalDir (for example "trust/" followed by SetName's result) with
// w.WriteSet, and nothing else: one call, so a cut leaves no set at finalDir (record 0006, rule 41).
// It adds no deletion and no retry, and it returns the error of fsx as it is (an *fsx.Error, which
// wraps fs.ErrExist when finalDir exists). A nil or zero Set and a nil Writer are ErrParams and
// write nothing. Write does not choose finalDir.
func (s *Set) Write(w *fsx.Writer, finalDir string) error {
	if !s.valid() {
		return fail(ErrParams, "the set is empty")
	}
	if w == nil {
		return fail(ErrParams, "there is no writer")
	}
	files := s.Files()
	if files == nil {
		return fail(ErrParams, "the set has no files")
	}
	return w.WriteSet(finalDir, files)
}
