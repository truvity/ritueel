package answer

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
)

// LoadAnswer reads `<stem>.result.json`, `<stem>.cert.pem` and `<stem>.bound.pgp` in the folder dir of root,
// as [handoff.LoadRequest] reads a request: by [fsx.ReadFile], which walks the path from the open folder root one
// element at a time and opens each element without following a link, never waits on a pipe, and reads only a
// regular file. A file that is not there has no entry: the floor's answer is one file, `<stem>.cert.pem`, and has
// no result file, and an answer with no result file is judged malformed by the full contract, not here. dir is
// relative to root, with "/" as the separator; "." is root itself. A file of any other name is not read.
//
// When none of the three files is there (a folder that does not exist, a stem with a typing mistake, an empty
// folder), nothing came back, so there is nothing to judge: that is the problem of the caller and not a verdict,
// and LoadAnswer returns an error that wraps [ErrLoad]. One file there is an [Answer], as it is, whatever the
// others lack. An Answer made by hand with no file is not LoadAnswer's: [Checker.Check] judges it, and it is
// malformed.
//
// A file longer than [MaxFileSize] is not an error of the caller: the answer is refused, because the contract
// refuses a file that large before it reads it, and the refusal is the verdict's (malformed). So a file of up to
// [fsx.MaxReadSize] bytes is returned cut to MaxFileSize+1 bytes, which is more than the limit, and
// [Checker.Check] refuses it. A file longer than fsx.MaxReadSize is read in no part by fsx, and is given the same
// answer: it is returned as MaxFileSize+1 bytes of zeros.
//
// A stem that [handoff.ValidStem] refuses, a folder that is not a path, a link anywhere on the way to a file, a
// file that is not a regular file, a file that cannot be read and the absence of all three files are an error
// that wraps [ErrLoad]; so is a nil root.
func LoadAnswer(root fsx.FS, dir, stem string) (*Answer, error) {
	if root == nil {
		return nil, fmt.Errorf("%w: no root folder", ErrLoad)
	}
	if !handoff.ValidStem(stem) {
		return nil, fmt.Errorf("%w: the stem is not 1 to 63 lower-case letters, digits and hyphens that start with a letter or a digit", ErrLoad)
	}
	if !fs.ValidPath(dir) {
		return nil, fmt.Errorf("%w: the folder is not a path inside the root", ErrLoad)
	}
	a := &Answer{Stem: stem, Files: map[string][]byte{}}
	for _, suffix := range answerSuffixes {
		data, err := fsx.ReadFile(root, path.Join(dir, stem+"."+suffix))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, fsx.ErrTooLarge):
			// A file over the read limit of fsx is read in no part; it is given the same answer as a file just
			// over MaxFileSize: MaxFileSize+1 bytes of nothing, which Check refuses as malformed.
			data = make([]byte, MaxFileSize+1)
		case err != nil:
			return nil, fmt.Errorf("%w: %s.%s: %w", ErrLoad, stem, suffix, err)
		}
		if len(data) > MaxFileSize+1 {
			data = slices.Clone(data[:MaxFileSize+1])
		}
		a.Files[suffix] = data
	}
	if len(a.Files) == 0 {
		return nil, fmt.Errorf("%w: none of %s.%s, %s.%s and %s.%s is in the folder", ErrLoad, stem, FileResult, stem, FileCert, stem, FileBound)
	}
	return a, nil
}
