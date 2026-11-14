package software

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// statFunc is os.Stat. A test in this package replaces it to show that two spellings of one
// folder are told apart by os.SameFile and never by comparing strings.
type statFunc func(path string) (fs.FileInfo, error)

// CheckKeyDir is the refusal of record 0005 (roads not taken, "Key files inside the bundle") and
// of docs/reference/cli.md (--key-dir): it refuses a key directory that is the bundle folder or
// any folder inside it, that is inside the work tree of the repository that holds the bundle
// (the first folder at or above the bundle with a `.git` file or folder; proposed, built as the
// page of the revocation directory says), that does not exist, or that is not a folder. A key
// directory that is a parent of the bundle, or beside it, is accepted: the stick keeps `keys/<bundle>/` beside
// `bundles/<name>/`.
//
// Both paths are resolved as the operating system resolves them: a relative path is joined to the
// working folder as plain text, and every element is followed in order, so a ".." that stands
// after a link is taken from the folder that the link points to. The path is never cleaned first,
// because cleaning removes "L/.." without asking where L leads. The check then walks from the
// resolved key directory up to the root of the file system and refuses at any step that is the
// same file as the bundle folder, or as the root of any repository that encloses the bundle (the
// nearest one and every one above it), by os.SameFile. A string prefix is never the test, so
// another spelling, a link, a bind mount of the same folder and a file system that ignores case
// cannot get past it. An empty bundleDir is an [ErrParams]; every other refusal is an
// [ErrKeyDir]. The error says no path.
//
// This function resolves links on purpose, because a link into the bundle is the case that it
// must catch. It reads no file. [Open] closes most of the gap between this check and the open of
// the folder (a link swapped in between): after fsx has opened the folder it checks the path
// again and refuses when the folder is no longer the one that was checked. A swap that is made
// and undone between the two looks cannot be seen, and the holder's folder is the rest.
func CheckKeyDir(keyDir, bundleDir string) error {
	_, err := checkKeyDir(os.Stat, keyDir, bundleDir)
	return err
}

// checkKeyDir is CheckKeyDir with the stat function, and returns the resolved key directory that
// was checked.
func checkKeyDir(stat statFunc, keyDir, bundleDir string) (string, error) {
	if bundleDir == "" {
		return "", refuse(ErrParams, "the bundle folder is empty")
	}
	if keyDir == "" {
		return "", refuse(ErrKeyDir, "the key directory is empty")
	}
	bundle, err := resolve(bundleDir)
	if err != nil {
		return "", refuse(ErrKeyDir, "the bundle folder %s", why(err))
	}
	key, err := resolve(keyDir)
	if err != nil {
		return "", refuse(ErrKeyDir, "the key directory %s", why(err))
	}
	keyInfo, err := stat(key)
	if err != nil {
		return "", refuse(ErrKeyDir, "the key directory %s", why(err))
	}
	if !keyInfo.IsDir() {
		return "", refuse(ErrKeyDir, "the key directory is not a folder")
	}
	bundleInfo, err := stat(bundle)
	if err != nil {
		return "", refuse(ErrKeyDir, "the bundle folder %s", why(err))
	}
	if !bundleInfo.IsDir() {
		return "", refuse(ErrKeyDir, "the bundle folder is not a folder")
	}
	inside, err := within(stat, key, bundleInfo)
	if err != nil {
		return "", refuse(ErrKeyDir, "the key directory cannot be compared with the bundle folder")
	}
	if inside {
		return "", refuse(ErrKeyDir, "the key directory is the bundle folder or inside it")
	}
	inRepo, err := inRepository(stat, key, bundle)
	if err != nil {
		return "", refuse(ErrKeyDir, "the key directory cannot be compared with the repository of the bundle")
	}
	if inRepo {
		return "", refuse(ErrKeyDir, "the key directory is inside the work tree of the repository that holds the bundle")
	}
	return key, nil
}

// resolve makes a path absolute and follows every link in it, element by element, in order, as
// the operating system does. It does not clean the path first: filepath.Abs and filepath.Join
// clean a path, and the cleaning of "L/../b" gives "b" whatever L is, where the system gives the
// folder beside the target of L. A relative path is joined to the working folder as text.
func resolve(path string) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = wd + string(os.PathSeparator) + path
	}
	return filepath.EvalSymlinks(abs)
}

// why says in fixed words why a path could not be used. It never repeats the text of the error,
// which holds the path.
func why(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "does not exist"
	case errors.Is(err, fs.ErrPermission):
		return "cannot be read"
	}
	return "cannot be resolved"
}

// within reports whether dir, or any folder above it up to the root of the file system, is the
// same file as target.
func within(stat statFunc, dir string, target fs.FileInfo) (bool, error) {
	for cur := dir; ; {
		info, err := stat(cur)
		if err != nil {
			return false, err
		}
		if os.SameFile(info, target) {
			return true, nil
		}
		up := filepath.Dir(cur)
		if up == cur {
			return false, nil
		}
		cur = up
	}
}

// inRepository is the one place of the rule that a key directory is not inside the work tree of
// the repository that holds the bundle (proposed; the rule of the revocation directory, applied
// here): one answer to the open question changes this function and nothing else. The folder
// that holds the `.git` entry is the root of the work tree, and it is refused too.
func inRepository(stat statFunc, key, bundle string) (bool, error) {
	// Every enclosing work tree counts: a repository inside a repository (a bundle kept in a
	// nested clone or a submodule) must not hide the outer one.
	for cur := bundle; ; {
		work, ok := repositoryRoot(cur)
		if !ok {
			return false, nil
		}
		info, err := stat(work)
		if err != nil {
			return false, err
		}
		inside, err := within(stat, key, info)
		if err != nil || inside {
			return inside, err
		}
		up := filepath.Dir(work)
		if up == work {
			return false, nil
		}
		cur = up
	}
}

// repositoryRoot returns the first folder at or above dir that holds a `.git` file or folder (a
// worktree has a file). It looks at the name only and reads nothing.
func repositoryRoot(dir string) (string, bool) {
	for cur := dir; ; {
		if _, err := os.Lstat(filepath.Join(cur, ".git")); err == nil {
			return cur, true
		}
		up := filepath.Dir(cur)
		if up == cur {
			return "", false
		}
		cur = up
	}
}
