package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/wanted"
)

// The modes of what [Create] makes, less the umask of the process.
const (
	folderMode fs.FileMode = 0o755
	fileMode   fs.FileMode = 0o644
)

// CreateError is the error of [Create]. It says what the call had already made when it stopped, so that the
// caller can tell a person which folder to remove. Create deletes nothing and does not retry.
type CreateError struct {
	// Dir is the folder that was asked for, as the caller gave it.
	Dir string
	// Made is true when the folder itself exists because of this call, also when the flush of its parent failed
	// after the make. When it is false nothing was written.
	Made bool
	// Written lists what exists inside the folder after the stop, as paths relative to it: a folder ends
	// with "/". A folder or a file is listed when its make or its rename succeeded, also when the flush that
	// follows it failed. It holds no ritueel.yaml unless every other file was written first. The temporary
	// names (".rt-" and a random part) that a cut leaves in a folder are not listed: a name that fsx drew is not
	// one of the bundle's, and Create deletes nothing, so the person removes the folder as a whole.
	Written []string
	// Err is the cause.
	Err error

	// whole is true when the bundle is whole on disk (every folder and file is listed) and only the last flush
	// failed, so that the bundle may not survive a power cut.
	whole bool
}

// Error says that the folder was not made, or that it was made in part, and why.
func (e *CreateError) Error() string {
	if e == nil {
		return "bundle: no error"
	}
	state := "the folder was not made"
	if e.Made {
		state = writtenText(e.Written)
	}
	if e.whole {
		state = "the bundle is whole on disk but was not flushed: it may not survive a power cut"
	}
	return fmt.Sprintf("bundle: cannot make the bundle %s: %s: %v", jsonset.EscapeExact(e.Dir), state, e.Err)
}

// writtenText says how many things the stopped call made inside the folder and names each one, as the paths of
// [CreateError.Written] through the exact escape of a name from a file system: "1 thing was", "N things were".
func writtenText(written []string) string {
	count := fmt.Sprintf("%d things were", len(written))
	if len(written) == 1 {
		count = "1 thing was"
	}
	text := "the folder was made and " + count + " written in it"
	if len(written) == 0 {
		return text
	}
	names := make([]string, len(written))
	for i, w := range written {
		names[i] = jsonset.EscapeExact(w)
	}
	return text + " (" + strings.Join(names, ", ") + ")"
}

// Unwrap returns the cause.
func (e *CreateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Create makes the new bundle folder dir and the starter wanted files in it, and returns the files in the
// order they were written. Nothing is created above the parent of dir: the parent must exist, and a link as
// the last element of the parent is refused. The last element of dir must pass [fsx.CheckName]: a bundle is
// named by its folder, and the name goes into the names of its objects. dir must hold no ".." element.
//
// The folder is made by a make that fails when anything holds the name (record 0006, rule 42): a file, a
// folder (an empty one too), a link, a leftover. Create never writes into an existing folder. Then it makes
// want/ and want/roots/, writes each root file, and writes ritueel.yaml last; each file has mode 0644 and each
// folder 0755, less the umask. The folders seen/, sealed/, roots/, requests/, history/, trust/ and drills/ are
// not made: the code that writes into each makes it. The first error of the writer stops it for good, and
// the error is a [*CreateError] that lists what was made.
//
// A folder above dir that holds a name ritueel.yaml refuses it: a bundle is not made inside a bundle. The
// folders above dir are looked at by name and not by listing them, so a folder that can be passed but not
// listed is looked at too. A folder that cannot be examined stops the call with an error that names it, and
// so does a parent whose links cannot be followed (the folders above it are then not known): nothing is
// written, because a check that cannot run is not a pass. The starter files are made and read back before
// any write ([Starter]); an error there writes nothing.
func Create(dir string, opt StarterOptions) ([]wanted.File, error) {
	parent, last, err := splitDir(dir)
	if err != nil {
		return nil, &CreateError{Dir: dir, Err: err}
	}
	files, err := Starter(opt)
	if err != nil {
		return nil, &CreateError{Dir: dir, Err: err}
	}
	parentFS, err := fsx.OpenFS(parent)
	if err != nil {
		return nil, &CreateError{Dir: dir, Err: fmt.Errorf("the parent folder cannot be opened: %w", err)}
	}
	w := &fsx.Writer{FS: parentFS}
	defer func() { _ = w.Close() }()
	above, err := bundleAbove(parent)
	if err != nil {
		return nil, &CreateError{Dir: dir, Err: err}
	}
	if above != "" {
		return nil, &CreateError{Dir: dir, Err: fmt.Errorf("the folder %s holds %s: a bundle is not made inside a bundle", jsonset.EscapeExact(above), wanted.SettingsPath)}
	}
	if err := create(w, dir, last, files); err != nil {
		return nil, err
	}
	return files, nil
}

// bundleAbove returns the nearest folder from parent up to the root of the file system that holds a name
// ritueel.yaml (of any kind: a file, a folder, a link, a pipe), or "" when none does. parent is made absolute,
// and its links are followed, so that the folders above it are the ones on the disk. An error is a path that
// cannot be made absolute, a path whose links cannot be followed (a link that leads to itself, a link to
// nothing, a folder that cannot be passed), or a folder that cannot be examined ([holdsSettings]): the
// answer is then not known, and it is not "none". The folders of a path that was not resolved are never
// looked at, because they may not be the ones on the disk.
func bundleAbove(parent string) (string, error) {
	abs, err := filepath.Abs(parent)
	if err != nil {
		return "", fmt.Errorf("the parent folder cannot be made absolute: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err // the cause without the path: the text names the parent, made absolute, by its escape
		}
		return "", fmt.Errorf("the parent folder %s cannot be resolved: %w", jsonset.EscapeExact(abs), err)
	}
	abs = real
	for p := abs; ; p = filepath.Dir(p) {
		held, err := holdsSettings(p)
		if err != nil {
			return "", err
		}
		if held {
			return p, nil
		}
		if filepath.Dir(p) == p {
			return "", nil
		}
	}
}

// holdsSettings tells whether the folder p holds the name ritueel.yaml. It looks at the name itself with a
// call that follows no link and does not open the folder, so a folder that can be passed but not listed is
// looked at too. A name that exists, of any kind (a file, a folder, a link, a link to nothing, a pipe), holds
// the name; only "does not exist" is absent. Any other error means that the folder cannot be examined: it is
// returned with the name of the folder, and it is never taken for "absent".
func holdsSettings(p string) (bool, error) {
	_, err := os.Lstat(filepath.Join(p, wanted.SettingsPath))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	// The cause is the error of the system without the path, which the text names by its escape.
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return false, fmt.Errorf("the folder %s cannot be examined for %s: %w", jsonset.EscapeExact(p), wanted.SettingsPath, err)
}

// create makes the folder last in the root of w and writes the files into it. It is the part of Create that a
// test drives with a file system of its own.
func create(w *fsx.Writer, dir, last string, files []wanted.File) error {
	e := &CreateError{Dir: dir}
	total := 2 + len(files) // the two folders and the files
	fail := func(err error) error {
		e.Err = err
		e.whole = e.Made && len(e.Written) == total
		return e
	}
	if err := w.Mkdir(last, folderMode); err != nil {
		// The make is followed by a flush of the parent. A fault at the flush leaves the folder on disk, so
		// the person is told to remove it: only a fault before the flush means that nothing was made.
		e.Made = existsAfter(err)
		return fail(err)
	}
	e.Made = true
	for _, d := range []string{"want", wanted.RootsDir} {
		err := w.Mkdir(last+"/"+d, folderMode)
		if existsAfter(err) {
			e.Written = append(e.Written, d+"/")
		}
		if err != nil {
			return fail(err)
		}
	}
	for _, f := range files {
		err := w.WriteFile(last+"/"+f.Path, f.Data, fileMode)
		if existsAfter(err) {
			e.Written = append(e.Written, f.Path)
		}
		if err != nil {
			return fail(err)
		}
	}
	return nil
}

// existsAfter tells whether what a make or a write was asked for exists after it returned err: it does when it
// succeeded, and when only the flush that follows the make or the rename failed (Step sync-dir). A fault at
// any earlier step leaves the name unmade.
func existsAfter(err error) bool {
	if err == nil {
		return true
	}
	var fe *fsx.Error
	return errors.As(err, &fe) && fe.Step == fsx.StepSyncDir
}

// splitDir splits dir into its parent and its last element, and checks the last element and that there is no
// ".." element. The parent of a single name is ".".
func splitDir(dir string) (parent, last string, err error) {
	if dir == "" {
		return "", "", errors.New("the folder name is empty")
	}
	for _, el := range strings.Split(dir, "/") {
		if el == ".." {
			return "", "", errors.New("the path has a \"..\" element")
		}
	}
	clean := filepath.Clean(dir)
	parent, last = filepath.Split(clean)
	if parent == "" {
		parent = "."
	}
	if err := fsx.CheckName(last); err != nil {
		return "", "", fmt.Errorf("the last element of the path is not a name of a bundle: %w", err)
	}
	return parent, last, nil
}
