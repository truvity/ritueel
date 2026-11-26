package software

import (
	"errors"
	"os"

	"ritueel.id/ritueel/internal/keydir"
)

// CheckKeyDir is the check of the key directory that every key store is held to, as package
// internal/keydir states it, with the error of this package: an empty bundleDir is an [ErrParams],
// and every other refusal is an [ErrKeyDir] whose [Code] is key-dir. It reads no file. [Open]
// closes most of the gap between this check and the open of the folder (a link swapped in
// between): after fsx has opened the folder it checks the path again and refuses when the folder
// is no longer the one that was checked.
func CheckKeyDir(keyDir, bundleDir string) error {
	_, err := checkKeyDir(os.Stat, keyDir, bundleDir)
	return err
}

// checkKeyDir is CheckKeyDir with the stat function, and returns the resolved key directory that
// was checked.
func checkKeyDir(stat keydir.Stat, keyDir, bundleDir string) (string, error) {
	dir, err := keydir.CheckStat(stat, keyDir, bundleDir)
	if err != nil {
		return "", fromKeyDir(err)
	}
	return dir, nil
}

// fromKeyDir turns a refusal of internal/keydir into the error of this package, with the same
// words: [ErrParams] for a fault of the caller and [ErrKeyDir] for a refused directory.
func fromKeyDir(err error) error {
	var r *keydir.Refusal
	if !errors.As(err, &r) {
		return err
	}
	if errors.Is(r, keydir.ErrParams) {
		return refuse(ErrParams, "%s", r.Reason)
	}
	return refuse(ErrKeyDir, "%s", r.Reason)
}
