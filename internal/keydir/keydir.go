package keydir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Stat is os.Stat. Production code passes os.Stat. A test replaces it to show that two spellings
// of one folder are told apart by os.SameFile and never by comparing strings; any other function
// is for tests only, because a stat that lies skips every rule.
type Stat func(path string) (fs.FileInfo, error)

// The kinds of a [Refusal].
var (
	// ErrKeyDir marks a key directory that is refused: empty, inside the bundle or the repository
	// that holds it, missing, a link that cannot be resolved, or not a folder; also a bundle
	// folder that is missing, cannot be resolved or is not a folder, and a folder that cannot be
	// compared with the bundle folder or with the repository of the bundle.
	ErrKeyDir = errors.New("keydir: the key directory is refused")
	// ErrParams marks a parameter of the caller that is wrong: an empty bundle folder. It is a
	// fault of the caller, not a refusal of a key directory.
	ErrParams = errors.New("keydir: a parameter is refused")
)

// Refusal is the error of [Check] and [CheckStat]. Kind is [ErrKeyDir] or [ErrParams], and an
// error that is a Refusal satisfies errors.Is for its Kind. Reason says why in fixed words: it
// holds no path and no text that came from the caller or from the file system. The refusals of
// this package always have a Kind; the Error method is safe for one built by hand without it.
type Refusal struct {
	Kind   error
	Reason string
}

// Error gives the kind and the reason, or a fixed text and the reason when there is no kind.
func (r *Refusal) Error() string {
	if r.Kind == nil {
		return "keydir: the key directory is refused: " + r.Reason
	}
	return r.Kind.Error() + ": " + r.Reason
}

// Unwrap gives the kind.
func (r *Refusal) Unwrap() error { return r.Kind }

func refuse(kind error, format string, args ...any) error {
	return &Refusal{Kind: kind, Reason: fmt.Sprintf(format, args...)}
}

// Check is the refusal of record 0005 (roads not taken, "Key files inside the bundle") and of
// docs/reference/cli.md (--key-dir): it refuses a key directory that is the bundle folder or
// any folder inside it, that is inside the work tree of the repository that holds the bundle
// (the first folder at or above the bundle with a `.git` file or folder; proposed, built as the
// page of the revocation directory says), that is empty, that does not exist, or that is not a
// folder; it also refuses when the bundle folder does not exist, cannot be resolved or is not a
// folder, and when the key directory cannot be compared with the bundle folder or with the
// repository of the bundle. A key directory that is a parent of the bundle, or beside it, is
// accepted unless a rule above refuses it: the stick keeps `keys/<bundle>/` beside
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
// must catch. It reads no file. A store that opens the folder after the check closes most of the
// gap between the check and the open (a link swapped in between): once the folder is open it
// checks the path again with [CheckStat] and refuses when the folder is no longer the one that
// was checked. A swap that is made and undone between the two looks cannot be seen, and the
// holder's folder is the rest.
//
// Check gives only the verdict, and is for a caller that opens nothing. A store that opens the
// folder uses [CheckStat], opens the resolved path that it returns and never its own argument,
// and checks again after the open.
func Check(keyDir, bundleDir string) error {
	_, err := CheckStat(os.Stat, keyDir, bundleDir)
	return err
}

// CheckStat is [Check] with the stat function, and returns the resolved key directory that was
// checked. Production code passes os.Stat; another function is for tests only, because a stat
// that lies skips every rule. A store opens the resolved path that CheckStat returns, never its
// own argument, and checks again after it has opened the folder.
func CheckStat(stat Stat, keyDir, bundleDir string) (string, error) {
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
func within(stat Stat, dir string, target fs.FileInfo) (bool, error) {
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
func inRepository(stat Stat, key, bundle string) (bool, error) {
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
// worktree has a file). It looks at the name only and reads nothing. It uses os.Lstat and not the
// stat function of the check: the [Stat] seam does not cover it.
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
