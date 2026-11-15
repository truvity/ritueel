package ceremony

import (
	"fmt"

	"ritueel.id/ritueel/internal/keystore/software"
)

// CheckKeyDir is every refusal about the key directory of a software root that needs no key: the
// directory must exist and be a folder, must not be the bundle folder or inside it, must not be inside
// the work tree of a repository that holds the bundle, and must not already hold key files
// (docs/reference/cli.md, "--key-dir"). A refusal is a [*BackendError] (exit code 4) with the reason
// code of the key store, key-dir or key-exists. Any other fault, such as a key directory that cannot be
// listed, is an ordinary error. It makes no key and writes nothing; it opens the folder to look and
// closes it. The text of an ordinary fault is one line: the fault of the key store is wrapped in the
// text of this function, and the two are never joined by a line feed.
func CheckKeyDir(keyDir, bundleDir string) error {
	s, err := software.Open(software.Config{KeyDir: keyDir, BundleDir: bundleDir, Mode: software.ModeTest})
	if err != nil {
		return keyDirError(err)
	}
	has, err := s.HasKeyFiles()
	if cerr := s.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return keyDirError(err)
	}
	if has {
		return &BackendError{
			Reasons: []string{software.Code(software.ErrKeyExists)},
			Msg:     "the key directory already holds key files, and a key file is never replaced; use an empty folder; nothing was written",
		}
	}
	return nil
}

// keyDirError turns a fault of the key store into the error the command maps: a refusal that has a
// reason code is a BackendError, and any other is an ordinary error. The text of the store holds fixed
// words and no path.
func keyDirError(err error) error {
	if code := software.Code(err); code != "" {
		return &BackendError{Reasons: []string{code}, Msg: err.Error() + "; nothing was written"}
	}
	return fmt.Errorf("the key directory cannot be checked, and nothing was written: %w", err)
}
