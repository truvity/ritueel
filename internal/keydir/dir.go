package keydir

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"

	"ritueel.id/ritueel/internal/fsx"
)

// TestOnlyFolder is the name of the folder that ritueel makes inside the key directory for the keys of
// a test root. The name is what marks those keys as test-only: the key files in it have no marker line.
// A key directory that holds an entry of this name is a used key directory.
const TestOnlyFolder = "test-only-keys"

// The kinds of the refusals of a [Dir], beside [ErrKeyDir] and [ErrParams].
var (
	// ErrKeyExists marks a file of that name that stands already: a file of the key directory is never
	// replaced.
	ErrKeyExists = errors.New("keydir: the file exists already")
	// ErrKeyFile marks a file of the key directory that is not of the shape of its page, that is missing,
	// or that does not read back as it was written.
	ErrKeyFile = errors.New("keydir: the file is not of the shape of the page")
)

const (
	// maxRemovalSize is the most bytes of a compact JWS.
	maxRemovalSize = 4 << 10
	// filePerm is the mode that a file of the key directory is written with.
	filePerm = 0o600
	// removalSuffix ends the name of the removal authorisation of a label.
	removalSuffix = ".removal.jws"
)

// Dir is a key directory that was checked and opened. It holds ritueel's own files of the folder, the
// removal authorisations, and says whether the folder was used before. It makes no key: a key store
// keeps its keys in a folder of its own, beside these files. A Dir is safe for concurrent use.
type Dir struct {
	path string

	mu     sync.Mutex
	w      *fsx.Writer
	closed bool
}

// Open checks the key directory with [CheckStat], opens the resolved folder that was checked with
// fsx (which refuses a link as the last element), and looks at the path again: the folder must still
// be the one that was checked. A refusal is a [*Refusal]. The caller closes the Dir.
func Open(keyDir, bundleDir string) (*Dir, error) {
	dir, err := CheckStat(os.Stat, keyDir, bundleDir)
	if err != nil {
		return nil, err
	}
	checked, err := os.Stat(dir)
	if err != nil {
		return nil, refuse(ErrKeyDir, "the key directory cannot be looked at")
	}
	w, err := fsx.Open(dir)
	if err != nil {
		if errors.Is(err, fsx.ErrLink) {
			return nil, refuse(ErrKeyDir, "the key directory is a link")
		}
		return nil, refuse(ErrKeyDir, "the key directory cannot be opened")
	}
	again, err := CheckStat(os.Stat, dir, bundleDir)
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	now, err := os.Stat(again)
	if err != nil || again != dir || !os.SameFile(checked, now) {
		_ = w.Close()
		return nil, refuse(ErrKeyDir, "the key directory is not the folder that was checked")
	}
	return &Dir{path: dir, w: w}, nil
}

// Path is the resolved path of the key directory that was checked and opened. A key store opens its own
// folder under it, by this path and never by the argument of [Open].
func (d *Dir) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Close releases the folder. A second Close does nothing.
func (d *Dir) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.w == nil {
		return nil
	}
	if err := d.w.Close(); err != nil {
		return errors.New("keydir: the key directory could not be released")
	}
	return nil
}

// begin checks that the Dir was made by [Open] and is open. The caller holds the lock.
func (d *Dir) begin() error {
	if d == nil || d.w == nil || d.w.FS == nil {
		return refuse(ErrParams, "the key directory was not made by Open")
	}
	if d.closed {
		return refuse(ErrParams, "the key directory is closed")
	}
	return nil
}

// Used says whether the key directory was used: it holds the folder [TestOnlyFolder], a removal
// authorisation, or a key file of the naming that earlier versions of ritueel used. A temporary name and
// any other name are not a use. The first `apply` refuses a used key directory. ownFolder is true for a
// caller that made the folder [TestOnlyFolder] itself and looks again: that folder is then not a use.
func (d *Dir) Used(ownFolder bool) (bool, error) {
	if d == nil {
		return false, refuse(ErrParams, "the key directory was not made by Open")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.begin(); err != nil {
		return false, err
	}
	ents, err := fsx.ReadDir(d.w.FS, ".")
	if err != nil {
		return false, refuse(ErrKeyDir, "the key directory could not be listed")
	}
	for _, e := range ents {
		name := e.Name()
		if name == TestOnlyFolder {
			if !ownFolder {
				return true, nil
			}
			continue
		}
		if fsx.CheckName(name) == nil && e.Type().IsRegular() && usedName(name) {
			return true, nil
		}
	}
	return false, nil
}

// usedName reports whether a name is that of a removal authorisation or of a key file that an earlier
// version of ritueel made in the key directory itself: <label> plus one of the suffixes below, the label
// being one upper-case letter. The two names of an encrypted file end with .age.
func usedName(name string) bool {
	if len(name) < 2 || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	rest := name[1:]
	switch rest {
	case removalSuffix, ".removal.jws.age", ".x509.key.pem", ".x509.key.age", ".openpgp.key.asc", ".openpgp.key.age":
		return true
	}
	if after, ok := strings.CutPrefix(rest, ".revocation."); ok {
		return strings.HasSuffix(after, ".asc") || strings.HasSuffix(after, ".pgp.age")
	}
	return false
}

// RemovalName is the name of the file of the removal authorisation of a label, <label>.removal.jws, or
// "" for a label that is not one upper-case letter.
func RemovalName(label string) string {
	if len(label) != 1 || label[0] < 'A' || label[0] > 'Z' {
		return ""
	}
	return label + removalSuffix
}

// SaveRemoval writes the compact JWS of the removal authorisation of a label to <label>.removal.jws in
// the key directory, with the mode 0600, and reads it back. Its content is checked by the code that
// makes and uses it, and here only its shape: three non-empty parts of Base64url text, two dots, at
// most 4 KiB. A file of that name is never replaced: it is an [ErrKeyExists]. A write that fails is
// not retried, and nothing is deleted.
func (d *Dir) SaveRemoval(label string, jws []byte) error {
	name := RemovalName(label)
	if name == "" {
		return refuse(ErrParams, "the label is not one upper-case letter A to Z")
	}
	if err := checkRemoval(jws); err != nil {
		return err
	}
	if d == nil {
		return refuse(ErrParams, "the key directory was not made by Open")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.begin(); err != nil {
		return err
	}
	ents, err := fsx.ReadDir(d.w.FS, ".")
	if err != nil {
		return refuse(ErrKeyDir, "the key directory could not be listed")
	}
	for _, e := range ents {
		if e.Name() == name {
			return refuse(ErrKeyExists, "the file %s stands there", name)
		}
	}
	if err := d.w.WriteFile(name, jws, filePerm); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return refuse(ErrKeyExists, "the file %s stands there", name)
		}
		return refuse(ErrKeyFile, "the file %s was not written whole; a temporary file whose name starts with %s may stand in the key directory", name, fsx.TempPrefix)
	}
	back, err := fsx.ReadFile(d.w.FS, name)
	if err != nil {
		return refuse(ErrKeyFile, "the file %s was written and cannot be read back", name)
	}
	if !bytes.Equal(back, jws) {
		return refuse(ErrKeyFile, "the file %s was written and does not read back as it was written", name)
	}
	return nil
}

// ReadRemoval returns the removal authorisation of a label as the file holds it. A file that is
// missing, or not of the shape that [Dir.SaveRemoval] checks, is an [ErrKeyFile].
func (d *Dir) ReadRemoval(label string) ([]byte, error) {
	name := RemovalName(label)
	if name == "" {
		return nil, refuse(ErrParams, "the label is not one upper-case letter A to Z")
	}
	if d == nil {
		return nil, refuse(ErrParams, "the key directory was not made by Open")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.begin(); err != nil {
		return nil, err
	}
	b, err := fsx.ReadFile(d.w.FS, name)
	if err != nil {
		return nil, refuse(ErrKeyFile, "the file %s cannot be read", name)
	}
	if err := checkRemoval(b); err != nil {
		return nil, err
	}
	return b, nil
}

// checkRemoval checks the compact JWS of a removal authorisation: three non-empty parts of Base64url
// text without padding, two dots, at most 4 KiB.
func checkRemoval(jws []byte) error {
	if len(jws) == 0 || len(jws) > maxRemovalSize {
		return refuse(ErrKeyFile, "the removal authorisation is empty or longer than 4 KiB")
	}
	// The strict decoder of the standard library skips a carriage return and a line feed, so a byte
	// outside the alphabet is refused before it decodes anything.
	for _, b := range jws {
		if !removalByte(b) {
			return refuse(ErrKeyFile, "the removal authorisation holds a byte that is not Base64url text or a dot")
		}
	}
	parts := bytes.Split(jws, []byte{'.'})
	if len(parts) != 3 {
		return refuse(ErrKeyFile, "the removal authorisation is not three parts and two dots")
	}
	for _, part := range parts {
		if len(part) == 0 {
			return refuse(ErrKeyFile, "a part of the removal authorisation is empty")
		}
		if _, err := base64.RawURLEncoding.Strict().DecodeString(string(part)); err != nil {
			return refuse(ErrKeyFile, "a part of the removal authorisation is not Base64url text")
		}
	}
	return nil
}

// removalByte reports whether b is a letter, a digit, a hyphen, an underscore or a dot: the alphabet of
// Base64url without padding (RFC 4648, section 5) and the separator of a compact JWS.
func removalByte(b byte) bool {
	return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '_' || b == '.'
}
