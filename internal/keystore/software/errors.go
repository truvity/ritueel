package software

import (
	"errors"
	"fmt"
)

// The errors of the package. A call returns an error that wraps one of them, and [Code] gives the
// reason code of a refusal. The text of an error holds fixed words and numbers: no key, no
// passphrase, no path and no text that came from a caller or a file (record 0002, rule 3).
var (
	// ErrParams marks a parameter of the caller that is wrong: a label, a reason, a nil or closed
	// key, a mode that is zero, an empty BundleDir, a source that does not fit the mode, a nil
	// context, a store that is closed, or a certificate that is not the key's.
	ErrParams = errors.New("software: a parameter is refused")
	// ErrKeyDir marks a key directory that is refused: inside the bundle or the repository that
	// holds it, missing, a link that cannot be resolved, or not a folder.
	ErrKeyDir = errors.New("software: the key directory is refused")
	// ErrKeyExists marks a file of that name that stands already: a key file is never replaced.
	ErrKeyExists = errors.New("software: the key file exists already")
	// ErrKeyFile marks a key file that is not exactly of the shape of the page, that is too long,
	// that is missing, or that does not match what was asked.
	ErrKeyFile = errors.New("software: the key file is not of the shape of the page")
	// ErrWrongMode marks a file of the other mode: a plain file where the store holds a
	// passphrase root, or an age file where it holds a test root. The file is not parsed.
	ErrWrongMode = errors.New("software: a key file of the other mode stands there")
	// ErrPassphrase marks a passphrase that is not acceptable. It is built with the passphrase
	// files and is not returned by this version.
	ErrPassphrase = errors.New("software: the passphrase is not acceptable")
	// ErrWrongPassphrase marks a file that did not open with the passphrase. It is built with the
	// passphrase files and is not returned by this version.
	ErrWrongPassphrase = errors.New("software: the key file did not open with this passphrase")
	// ErrNotBuilt marks a way to open a key file that is not built: the passkey way and the
	// recovery key (not written before the proof on a card), a passphrase file, a backend that is
	// not `file`.
	ErrNotBuilt = errors.New("software: this way to open a key file is not built")
)

// codes is the one table of the reason codes. The words are proposed: a script reads them.
var codes = []struct {
	err  error
	code string
}{
	{ErrKeyDir, "key-dir"},
	{ErrKeyExists, "key-exists"},
	{ErrKeyFile, "key-file"},
	{ErrWrongMode, "key-file-mode"},
	{ErrPassphrase, "passphrase"},
	{ErrWrongPassphrase, "passphrase-wrong"},
	{ErrNotBuilt, "not-built"},
}

// Code is the reason code of a refusal of this package: key-dir, key-exists, key-file,
// key-file-mode, passphrase, passphrase-wrong or not-built. It is "" for an error that wraps none
// of the sentinels that have a code, ErrParams (a fault of the caller, not a refusal) among them.
func Code(err error) string {
	if err == nil {
		return ""
	}
	for _, c := range codes {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return ""
}

// refuse returns an error that wraps kind and says why, in fixed words.
func refuse(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}
