package history

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"syscall"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// How a file stands when a check looks at it.
type stand uint8

const (
	// standOK is a regular file that was read.
	standOK stand = iota
	// standMissing is a name that does not exist (or whose folder on the way is a file, so that
	// the name cannot exist).
	standMissing
	// standNotFile is a name that exists and is not a regular file of at most
	// fsx.MaxReadSize: a folder, a symbolic link, a FIFO, a device, a file that is too long.
	standNotFile
)

// fileState is what a read of one path found.
type fileState struct {
	kind stand
	// digest is the digest of the bytes, for standOK of a digest read ([reader.digest]).
	digest string
	// why says what a standNotFile is, in a few fixed words.
	why string
	// anchor is, for the root list of a trust set that was read, what it says of its anchor. It
	// is kept from the read of the digest, so that the list is read once.
	anchor *anchorOf
}

// reader reads the files of one bundle for one check. Every read goes through fsx, so no
// symbolic link is followed, only a regular file of at most fsx.MaxReadSize is read, and a FIFO
// is not waited on. It keeps the two limits that bound a whole run, [MaxReadBytes] and
// [MaxFileReads], and the cache that reads a listed path once.
type reader struct {
	ctx       context.Context
	fsys      fsx.FS
	left      int64
	total     int64
	fileReads int
	cache     map[[sha256.Size]byte]fileState
}

func newReader(ctx context.Context, fsys fsx.FS, lim limits) *reader {
	return &reader{ctx: ctx, fsys: fsys, left: lim.readBytes, total: lim.readBytes, fileReads: lim.fileReads, cache: map[[sha256.Size]byte]fileState{}}
}

// read reads the file at path (relative to the bundle). It returns its bytes when the file is
// there and plain. A file that is not there, or is there and is not the file, is a state and not
// an error. Any other failure (a permission, an input or output error, the context, a limit) is
// an error and ends the check: it is "cannot read", never a finding.
func (r *reader) read(path string) ([]byte, fileState, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, fileState{}, err
	}
	data, err := fsx.ReadFile(r.fsys, path)
	switch {
	case err == nil:
		r.left -= int64(len(data))
		if r.left < 0 {
			return nil, fileState{}, fmt.Errorf("%w: more than %d bytes of files were read", ErrTooMuch, r.total)
		}
		return data, fileState{kind: standOK}, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return nil, fileState{kind: standMissing}, nil
	case errors.Is(err, fsx.ErrLink):
		return nil, fileState{kind: standNotFile, why: "it is a symbolic link"}, nil
	case errors.Is(err, fsx.ErrNotRegular):
		return nil, fileState{kind: standNotFile, why: "it is not a regular file"}, nil
	case errors.Is(err, fsx.ErrTooLarge):
		return nil, fileState{kind: standNotFile, why: "it is longer than 8 MiB"}, nil
	}
	return nil, fileState{}, err
}

// digest returns how the file at path stands and, for a file that is there, the digest of its
// bytes. A path is read at most once in a run: the answer is kept, so a record that lists the same
// path three thousand times, or many records that list it, cost one read. The cache keeps the
// hash of the path and not the path, so that its memory does not grow with the length of the
// paths a hostile record lists.
func (r *reader) digest(path string) (fileState, error) {
	key := sha256.Sum256([]byte(path))
	if st, ok := r.cache[key]; ok {
		return st, nil
	}
	if len(r.cache) >= r.fileReads {
		return fileState{}, fmt.Errorf("%w: more than %d different files are listed", ErrTooMuch, r.fileReads)
	}
	data, st, err := r.read(path)
	if err != nil {
		return fileState{}, err
	}
	if st.kind == standOK {
		st.digest = files.Digest(data)
		if isRootList(path) {
			st.anchor = parseAnchor(data)
		}
	}
	r.cache[key] = st
	return st, nil
}

// isRootList reports whether path is trust/<set>/root-list.json.
func isRootList(path string) bool {
	name, ok := trustSetOf(path)
	return ok && path == "trust/"+name+"/root-list.json"
}

// cached returns what a digest read of path found, when there was one.
func (r *reader) cached(path string) (fileState, bool) {
	st, ok := r.cache[sha256.Sum256([]byte(path))]
	return st, ok
}

// isListed reports whether a record listed path: a path is in the cache exactly when a record
// of a kind that was read listed it.
func (r *reader) isListed(path string) bool {
	_, ok := r.cache[sha256.Sum256([]byte(path))]
	return ok
}
