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

// ListRoots reads every want/roots/NAME.yaml of the bundle that fsys is the root of, with
// [LoadRoot], and returns the roots in the order of their names. The folder is listed once, through
// package fsx, which follows no link and stops at [fsx.MaxDirEntries] names; at most [MaxFiles]
// names are accepted, and more is an error. A folder that does not exist is an empty list. Each name
// must be NAME.yaml with a NAME that passes [ValidName], and each entry must be a regular file: a
// name of another form, a link, a folder, a FIFO and a file that fails its own check are errors
// that name the path, escaped. An error returns no root: a list of some of the files is never
// returned.
func ListRoots(fsys fsx.FS) ([]*Root, error) {
	names, err := listNames(fsys, RootsDir, ValidName)
	if err != nil {
		return nil, err
	}
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

// ListDelegations reads every want/delegations/NAME.yaml with [LoadDelegation] and the settings of
// the bundle, which it needs, and returns the delegations in the order of their names. It lists,
// bounds and refuses as [ListRoots] does, and a delegation whose root file is missing or fails its
// check is an error. A Settings that is not [Settings.Valid] is an error.
func ListDelegations(fsys fsx.FS, s *Settings) ([]*Delegation, error) {
	if !s.Valid() {
		return nil, errorf(DelegationsDir, 0, "the settings of the bundle are needed to read the delegations, and these were not made by the reader")
	}
	names, err := listNames(fsys, DelegationsDir, func(name string) error {
		if why := delegationNameProblem(name); why != "" {
			return errors.New(why)
		}
		return nil
	})
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
