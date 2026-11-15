package wanted

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
)

// yamlSuffix ends the name of every wanted root file and delegation file.
const yamlSuffix = ".yaml"

// ListRootNames lists want/roots once and returns the names (without ".yaml") of the root files, in
// the order of the names. It reads no file: only the names are judged, so that a caller can refuse a
// folder of more files than it can use before it reads any of them. The folder is listed once,
// through package fsx, which follows no link and stops at [fsx.MaxDirEntries] names; at most
// [MaxFiles] names are accepted, and more is an error. A folder that does not exist gives no name.
// Each name must be NAME.yaml with a NAME that passes [ValidName], and each entry must be a regular
// file: a name of another form, a link, a folder and a FIFO are errors that name the path, escaped.
// An error returns no name.
func ListRootNames(fsys fsx.FS) ([]string, error) {
	return listNames(fsys, RootsDir, ValidName)
}

// LoadRoots reads the root files of the given names, with [LoadRoot], and returns the roots in the
// order of the names. The first file that fails its check is an error that names the path, escaped,
// and no root is returned: a list of some of the files is never returned. The caller bounds the
// number of names (see [ListRootNames]); every file that is named is read and kept.
func LoadRoots(fsys fsx.FS, names []string) ([]*Root, error) {
	roots := make([]*Root, 0, len(names))
	for _, name := range names {
		r, err := LoadRoot(fsys, name)
		if err != nil {
			return nil, err
		}
		roots = append(roots, r)
	}
	return roots, nil
}

// ListRoots reads every want/roots/NAME.yaml of the bundle that fsys is the root of, with
// [LoadRoot], and returns the roots in the order of their names. The names are listed and judged
// first, as [ListRootNames] does, and no file is read when the folder holds more than [MaxFiles]
// names or an entry that is not a root file. A folder that does not exist is an empty list. A file
// that fails its own check is an error that names the path, escaped. An error returns no root: a
// list of some of the files is never returned.
func ListRoots(fsys fsx.FS) ([]*Root, error) {
	names, err := ListRootNames(fsys)
	if err != nil {
		return nil, err
	}
	return LoadRoots(fsys, names)
}

// ListDelegations reads every want/delegations/NAME.yaml with [LoadDelegation] and the settings of
// the bundle, which it needs, and returns the delegations in the order of their names. It lists,
// bounds and refuses as [ListRoots] does, and a delegation whose root file is missing or fails its
// check is an error. A Settings that is not [Settings.Valid] is an error.
func ListDelegations(fsys fsx.FS, s *Settings) ([]*Delegation, error) {
	names, err := listDelegationNames(fsys, s)
	if err != nil {
		return nil, err
	}
	out := make([]*Delegation, 0, len(names))
	for _, name := range names {
		d, err := LoadDelegation(fsys, name, s)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// CheckDelegations reads and checks every delegation file as [ListDelegations] does, and keeps none
// of them: each file is dropped when it has been checked, so the memory it holds is that of one file
// and not of up to [MaxFiles] files. The names are listed and judged before the first file is read.
// It returns the first fault, which names the path, escaped, and nil when every file passes.
func CheckDelegations(fsys fsx.FS, s *Settings) error {
	names, err := listDelegationNames(fsys, s)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, err := LoadDelegation(fsys, name, s); err != nil {
			return err
		}
	}
	return nil
}

// listDelegationNames lists the names of the delegation files, once, and reads none of them. A
// Settings that is not [Settings.Valid] is an error.
func listDelegationNames(fsys fsx.FS, s *Settings) ([]string, error) {
	if !s.Valid() {
		return nil, errorf(DelegationsDir, 0, "the settings of the bundle are needed to read the delegations, and these were not made by the reader")
	}
	return listNames(fsys, DelegationsDir, func(name string) error {
		if why := delegationNameProblem(name); why != "" {
			return errors.New(why)
		}
		return nil
	})
}

// listNames lists dir once and returns the names (without ".yaml") of its entries, in the order of
// the entries' names. A folder that does not exist gives none. Every entry must be a regular file
// called NAME.yaml with a NAME that valid accepts.
func listNames(fsys fsx.FS, dir string, valid func(string) error) ([]string, error) {
	if fsys == nil {
		return nil, errorf(dir, 0, "there is no folder to read it from")
	}
	ents, err := fsx.ReadDir(fsys, dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		e := errorf(dir, 0, "the folder cannot be listed: "+listFault(err))
		e.cause = err
		return nil, e
	}
	if len(ents) > MaxFiles {
		return nil, errorf(dir, 0, fmt.Sprintf("the folder holds more than %d files", MaxFiles))
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		entry := dir + "/" + e.Name()
		stem, ok := strings.CutSuffix(e.Name(), yamlSuffix)
		if !ok {
			return nil, errorf(entry, 0, "the name is not NAME"+yamlSuffix)
		}
		if err := valid(stem); err != nil {
			return nil, errorf(entry, 0, err.Error())
		}
		if !e.Type().IsRegular() {
			return nil, errorf(entry, 0, "it is not a regular file (a folder, a link or another kind of entry is not read)")
		}
		names = append(names, stem)
	}
	slices.Sort(names)
	return names, nil
}

// listFault is the short text for the error of a listing: fixed words for the faults that are told
// apart.
func listFault(err error) string {
	switch {
	case errors.Is(err, fsx.ErrLink):
		return "a link is not followed"
	case errors.Is(err, fsx.ErrTooMany):
		return "it holds too many names"
	}
	return "the system refused to list it"
}
