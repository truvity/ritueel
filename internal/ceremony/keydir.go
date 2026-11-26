package ceremony

import (
	"errors"
	"fmt"

	"ritueel.id/ritueel/internal/keydir"
)

// The reason codes of a refusal of the key store or of the key directory (exit code 4). The words are
// proposed: a script reads them.
const (
	// ReasonKeyDir is a key directory that is refused: missing, not a folder, inside the bundle or the
	// repository that holds it, or a folder of the key store that its driver refuses.
	ReasonKeyDir = "key-dir"
	// ReasonKeyExists is a key directory that was used already: it holds the folder test-only-keys, a removal
	// authorisation, or a key file of the older naming; or a key that exists in the store. A key is never
	// replaced and never adopted.
	ReasonKeyExists = "key-exists"
	// ReasonKeyFile is a file of the key directory that is not of its shape, or cannot be read back.
	ReasonKeyFile = "key-file"
)

// keyDirUsedText is the text of the refusal of a used key directory, without the words about what was
// written.
const keyDirUsedText = "the key directory already holds a folder " + keydir.TestOnlyFolder + " that is not empty or not fit, a removal authorisation, or a key file, and a key is never replaced; use an empty folder"

// CheckKeyDir is every refusal about the key directory of a software root that needs no key: the
// directory must exist and be a folder, must not be the bundle folder or inside it, must not be inside
// the work tree of a repository that holds the bundle, and must not already hold a removal authorisation, a
// key file of the older naming, or the name test-only-keys unless that is an empty folder fit for the key
// driver ([keydir.Dir.Used]) (docs/reference/cli.md,
// "--key-dir"). A refusal is a [*BackendError] (exit code 4) with the reason code key-dir or key-exists. Any
// other fault, such as a key directory that cannot be listed, is an ordinary error. It makes no key and
// writes nothing; it opens the folder to look and closes it. The text of an ordinary fault is one line: the
// fault is wrapped in the text of this function, and the two are never joined by a line feed.
func CheckKeyDir(keyDir, bundleDir string) error {
	d, err := keydir.Open(keyDir, bundleDir)
	if err != nil {
		return keyDirError(err)
	}
	used, err := d.Used()
	if cerr := d.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return keyDirError(err)
	}
	if used {
		return &BackendError{Reasons: []string{ReasonKeyExists}, Msg: keyDirUsedText + "; nothing was written"}
	}
	return nil
}

// keyDirError turns a fault of the key directory into the error the command maps: a refusal that has a
// reason code is a BackendError, and any other is an ordinary error. The text of a refusal holds fixed
// words and no path.
func keyDirError(err error) error {
	if code := keyDirCode(err); code != "" {
		return &BackendError{Reasons: []string{code}, Msg: err.Error() + "; nothing was written"}
	}
	return fmt.Errorf("the key directory cannot be checked, and nothing was written: %w", err)
}

// keyDirCode is the reason code of a refusal of internal/keydir, or "" for a fault that is not a refusal
// (a fault of the caller, a nil error).
func keyDirCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, keydir.ErrKeyDir):
		return ReasonKeyDir
	case errors.Is(err, keydir.ErrKeyExists):
		return ReasonKeyExists
	case errors.Is(err, keydir.ErrKeyFile):
		return ReasonKeyFile
	}
	return ""
}

// fileError turns a fault of a file of the key directory into the error the command maps, as
// [keyDirError] does, without the words about what was written: the caller says what was written.
func fileError(err error) error {
	if code := keyDirCode(err); code != "" {
		return &BackendError{Reasons: []string{code}, Msg: err.Error()}
	}
	return err
}
