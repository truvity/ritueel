package ceremony

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/wanted"
)

// The kinds of fault of a [FolderError]. A caller tells them apart with errors.Is.
var (
	// ErrOutOfOrder is a call that the state of the folder does not allow, or a call on a nil or
	// zero [Folder]. Nothing was written.
	ErrOutOfOrder = errors.New("the call is out of order for the state of the ceremony folder")
	// ErrInvalidInput is an argument that the folder refuses before it writes: a name, a plan, a
	// copy, an attempt, a line, a transcript, or the input of a record. Nothing was written.
	ErrInvalidInput = errors.New("the ceremony folder refuses the input")
	// ErrDiskMismatch is a file or a folder on disk that is not what the folder holds or wrote: a
	// plan that another run wrote, a copy that changed, a file that is not whole.
	ErrDiskMismatch = errors.New("the ceremony folder on disk is not what it should be")
	// ErrFolderStopped is the fault of a write that failed, and of every call after it. The
	// folder never retries and deletes nothing; the files that exist stay.
	ErrFolderStopped = errors.New("a write of the ceremony folder failed; the folder is stopped")
)

// maxCauseText is the most bytes of the text of a cause that an error of this package keeps.
const maxCauseText = 300

// FolderError is the error of the ceremony folder, of a journal that it made and of the record.
// Its text is made once, when the error is made, in printable ASCII: the text of the cause goes
// through jsonset.Escape and is cut, and no method of the cause is called again. The kind
// (ErrOutOfOrder, ErrInvalidInput, ErrDiskMismatch, ErrFolderStopped, fs.ErrExist) and the cause
// stay reachable with errors.Is and errors.As.
type FolderError struct {
	// Op is the step: "write-plan", "adopt", "start", "end", "transcript", "record", "births.jsonl"
	// or "signatures.jsonl".
	Op string
	// Reason is one line of printable ASCII that says what is wrong.
	Reason string
	// Err holds the kind and the cause.
	Err error
}

// Error says the step and the reason.
func (e *FolderError) Error() string {
	if e == nil {
		return "ceremony folder: no error"
	}
	return "ceremony folder: " + e.Op + ": " + e.Reason
}

// Unwrap returns the kind and the cause.
func (e *FolderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// causeText is the text of an error for another error: printable ASCII, cut, taken once, and
// safe against a method that panics.
func causeText(err error) (text string) {
	if err == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			text = "(the text of the error could not be read)"
		}
	}()
	s := jsonset.Escape(err.Error())
	if len(s) > maxCauseText {
		s = s[:maxCauseText] + "..."
	}
	return s
}

// newError makes a FolderError. kind and cause may be nil. The reason is the formatted text with
// the text of the cause after it; the arguments are the caller's to escape.
func newError(op string, kind, cause error, format string, args ...any) *FolderError {
	reason := fmt.Sprintf(format, args...)
	if t := causeText(cause); t != "" {
		reason += ": " + t
	}
	var inner error
	switch {
	case kind != nil && cause != nil:
		inner = errors.Join(kind, cause)
	case kind != nil:
		inner = kind
	default:
		inner = cause
	}
	return &FolderError{Op: op, Reason: reason, Err: inner}
}

// folderState is where a folder is in its order. The zero value is a Folder that NewFolder did not
// make.
type folderState uint8

const (
	stateNew folderState = iota + 1
	statePlanned
	stateStarted
	stateEnded
	stateTranscribed
	stateRecorded
)

func (s folderState) String() string {
	switch s {
	case stateNew:
		return "new"
	case statePlanned:
		return "planned"
	case stateStarted:
		return "started"
	case stateEnded:
		return "ended"
	case stateTranscribed:
		return "transcribed"
	case stateRecorded:
		return "recorded"
	}
	return "not made by NewFolder"
}

const (
	historyDir = "history"
	// dirMode and fileMode are the modes of the folders and files of a ceremony folder: those of
	// bundle.Create. The journals (0600) and the temporary folders of fsx are not changed.
	dirMode  fs.FileMode = 0o755
	fileMode fs.FileMode = 0o644
	// maxCopies is the most copies of wanted files that a plan lists: the files of want/roots and
	// want/delegations that a listing keeps, and ritueel.yaml and one more.
	maxCopies = wanted.MaxFiles + 2
	// maxWantedEntries is the most entries that Adopt looks at in wanted/, folders and files.
	maxWantedEntries = 4 * maxCopies
)

// Folder is one ceremony folder, history/<name>/, and the order in which it is written. It owns a
// state: new, planned, started, ended (the journals are closed), transcribed, recorded. A call out
// of order is an error and writes nothing. The first write that fails stops the folder: every
// later call returns an error that satisfies [ErrFolderStopped] and fsx.ErrStopped, nothing is
// retried and nothing is deleted. The zero value, a nil Folder and a Folder that is copied are
// unusable; make one with [NewFolder] and use it through its pointer. A Folder is safe for use by
// several goroutines: a call holds its lock from its first check to its last write.
type Folder struct {
	mu     sync.Mutex
	w      *fsx.Writer
	name   string
	state  folderState
	broken *FolderError

	plan    []byte
	planSHA string
	parsed  *files.Plan
	trace   *fileTrace
}

// NewFolder makes the handle of the ceremony folder history/<name>/ in the bundle that w writes
// into. The name comes from the caller and is checked with fsx.CheckName (a plain name: no space,
// no "..", no temporary prefix). It touches no disk.
func NewFolder(w *fsx.Writer, name string) (*Folder, error) {
	if w == nil {
		return nil, newError("new-folder", ErrInvalidInput, nil, "there is no writer")
	}
	if err := fsx.CheckName(name); err != nil {
		return nil, newError("new-folder", ErrInvalidInput, err, "the name of a ceremony folder is not a plain name")
	}
	return &Folder{w: w, name: name, state: stateNew}, nil
}

// begin is the check at the start of every method: the Folder is made, it is not stopped, and it
// is in the state that the method needs. It returns the error to give back, or nil.
func (f *Folder) begin(op string, want folderState) error {
	if f == nil || f.state == 0 || f.w == nil {
		return newError(op, ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	if f.broken != nil {
		return &FolderError{
			Op:     op,
			Reason: "an earlier write failed (" + f.broken.Op + "): " + f.broken.Reason,
			Err:    errors.Join(ErrFolderStopped, fsx.ErrStopped, f.broken),
		}
	}
	if f.state != want {
		return newError(op, ErrOutOfOrder, nil, "the folder is %s, and this call needs it %s", f.state, want)
	}
	return nil
}

// stop marks the folder stopped after a failed write and returns the error of the call.
func (f *Folder) stop(op string, cause error, format string, args ...any) error {
	e := newError(op, ErrFolderStopped, cause, format, args...)
	f.broken = e
	return e
}

func (f *Folder) dir() string { return historyDir + "/" + f.name }

// checkPlan judges the bytes of a plan: the strict reader of files, the canonical form, the
// ceremony the folder names, and at least one wanted file (a plan always uses ritueel.yaml).
func (f *Folder) checkPlan(op string, plan []byte) (*files.Plan, error) {
	if len(plan) == 0 || len(plan) > strictjson.DefaultMaxBytes {
		return nil, newError(op, ErrInvalidInput, nil, "the plan is empty or longer than %d bytes", strictjson.DefaultMaxBytes)
	}
	p, err := files.ReadPlan(plan)
	if err != nil {
		return nil, newError(op, ErrInvalidInput, err, "the plan is refused by its reader")
	}
	ok, err := canonjson.IsCanonical(plan)
	if err != nil || !ok {
		return nil, newError(op, ErrInvalidInput, err, "the plan is not in the canonical form of RFC 8785")
	}
	if p.Ceremony != f.name {
		return nil, newError(op, ErrInvalidInput, nil, "the plan is of the ceremony %s, and the folder is %s", jsonset.Quote(p.Ceremony), jsonset.Quote(f.name))
	}
	if len(p.Wanted) == 0 || len(p.Wanted) > maxCopies {
		return nil, newError(op, ErrInvalidInput, nil, "the plan lists %d wanted files; it must list from 1 to %d", len(p.Wanted), maxCopies)
	}
	return p, nil
}

// checkTree refuses wanted paths that cannot all be written as files of one tree: a path twice, a
// path that is a folder of another, two paths that differ only in case (a stick compares names
// without case).
func checkTree(op string, paths []string) error {
	seen := make(map[string]string, len(paths)*2)
	note := func(p string, isFile bool) error {
		key := strings.ToLower(p)
		if old, dup := seen[key]; dup && (old != p || isFile) {
			return newError(op, ErrInvalidInput, nil, "the wanted paths %s and %s meet on one name", jsonset.Quote(old), jsonset.Quote(p))
		}
		seen[key] = p
		return nil
	}
	isFile := make(map[string]bool, len(paths))
	for _, p := range paths {
		isFile[strings.ToLower(p)] = true
	}
	for _, p := range paths {
		if err := note(p, true); err != nil {
			return err
		}
	}
	for _, p := range paths {
		for i := 0; i < len(p); i++ {
			if p[i] != '/' {
				continue
			}
			if isFile[strings.ToLower(p[:i])] {
				return newError(op, ErrInvalidInput, nil, "the wanted path %s is a file and also a folder of %s", jsonset.Quote(p[:i]), jsonset.Quote(p))
			}
			if err := note(p[:i], false); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCopies compares the copies with the list of the plan: the same paths, the same digests of
// the bytes (taken here, never from the SHA256 field of a copy), at most fsx.MaxReadSize bytes each.
func checkCopies(op string, p *files.Plan, copies []wanted.File) (map[string][]byte, error) {
	if len(copies) != len(p.Wanted) {
		return nil, newError(op, ErrInvalidInput, nil, "the plan lists %d wanted files and %d copies were given", len(p.Wanted), len(copies))
	}
	data := make(map[string][]byte, len(copies))
	for _, c := range copies {
		if err := files.CheckPath(c.Path); err != nil {
			return nil, newError(op, ErrInvalidInput, nil, "the path %s of a copy %s", jsonset.Quote(c.Path), err)
		}
		if len(c.Data) > fsx.MaxReadSize {
			return nil, newError(op, ErrInvalidInput, nil, "the copy %s is longer than %d bytes", jsonset.Quote(c.Path), fsx.MaxReadSize)
		}
		if _, dup := data[c.Path]; dup {
			return nil, newError(op, ErrInvalidInput, nil, "the copy %s is given twice", jsonset.Quote(c.Path))
		}
		if c.SHA256 != "" && c.SHA256 != files.Digest(c.Data) {
			return nil, newError(op, ErrInvalidInput, nil, "the digest of the copy %s is not the digest of its bytes", jsonset.Quote(c.Path))
		}
		data[c.Path] = c.Data
	}
	paths := make([]string, 0, len(p.Wanted))
	for _, w := range p.Wanted {
		d, ok := data[w.Path]
		if !ok {
			return nil, newError(op, ErrInvalidInput, nil, "the plan lists %s and no copy of it was given", jsonset.Quote(w.Path))
		}
		if files.Digest(d) != w.SHA256 {
			return nil, newError(op, ErrInvalidInput, nil, "the copy %s does not have the digest that the plan lists", jsonset.Quote(w.Path))
		}
		paths = append(paths, w.Path)
	}
	if err := checkTree(op, paths); err != nil {
		return nil, err
	}
	return data, nil
}

// listOptional lists the folder at path. A folder that does not exist is (nil, false, nil).
func (f *Folder) listOptional(path string) ([]fs.DirEntry, bool, error) {
	ents, err := fsx.ReadDir(f.w.FS, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return ents, true, nil
}

// makeMu is the one lock of the package for the step that decides whether a ceremony folder may
// be made: it is held from the read of history/ to the Mkdir of the ceremony folder, so that two
// Folders on one writer cannot both see history/ absent, or both see a name free.
var makeMu sync.Mutex

// makeFolders reads history/ and makes the ceremony folder, under [makeMu]. The read comes first:
// history/ is made only when the read shows that it is absent, and a ceremony folder whose name
// exists (compared without case, as a stick compares it) is refused with an error that wraps
// fs.ErrExist and with no Mkdir call, so the writer is not stopped and the folder of the other is
// untouched. The lock is released when a call panics, and nothing under it takes the lock again.
func (f *Folder) makeFolders(op string) error {
	makeMu.Lock()
	defer makeMu.Unlock()
	ents, haveHistory, err := f.listOptional(historyDir)
	if err != nil {
		return newError(op, nil, err, "the folder history/ cannot be listed")
	}
	for _, e := range ents {
		if strings.EqualFold(e.Name(), f.name) {
			return newError(op, fs.ErrExist, nil, "the ceremony folder exists already")
		}
	}
	if !haveHistory {
		if err := f.w.Mkdir(historyDir, dirMode); err != nil {
			return f.stop(op, err, "history/ could not be made")
		}
	}
	if err := f.w.Mkdir(f.dir(), dirMode); err != nil {
		return f.stop(op, err, "the ceremony folder could not be made")
	}
	return nil
}

// ownCopies makes the copies of the caller's list that the call works on: the list, and the bytes
// of each copy, so that a caller that changes its bytes during the call changes nothing. The bytes
// of all the copies together are at most [maxFolderBytes], the limit that [Folder.Record] reads in
// all; a list over it is refused before any byte is copied.
func ownCopies(op string, copies []wanted.File) ([]wanted.File, error) {
	own := slices.Clone(copies)
	total := 0
	for _, c := range own {
		total += len(c.Data)
		if total > maxFolderBytes {
			return nil, newError(op, ErrInvalidInput, nil, "the copies are more than %d bytes in all", maxFolderBytes)
		}
	}
	for i := range own {
		own[i].Data = slices.Clone(own[i].Data)
	}
	return own, nil
}

// WritePlan makes the ceremony folder and writes plan.json and the copies of the wanted files
// under wanted/, in this order: history/ when it is absent (it is read first: an existing one is
// not made again), history/<name>/, plan.json, wanted/ with the folders of the paths of the copies,
// and each copy, in the order of the plan's wanted list. plan is the canonical plan of the
// ceremony the folder names; copies are exactly the files that the plan lists, with the digests
// it lists, and their bytes together are at most the bytes that [Folder.Record] reads in all. The
// call takes its own copy of the plan and of every copy at its top, so a caller that changes its
// bytes during the call changes nothing. A ceremony folder that exists is refused with an error
// that wraps fs.ErrExist before anything is made, so the writer is not stopped by a name that is
// taken; the read of history/ and the Mkdir of the ceremony folder are made under one lock of the
// package, so two Folders on one writer do not stop each other. After a failed write the folder is
// stopped.
func (f *Folder) WritePlan(plan []byte, copies []wanted.File) error {
	if f == nil {
		return newError("write-plan", ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const op = "write-plan"
	if err := f.begin(op, stateNew); err != nil {
		return err
	}
	own := slices.Clone(plan)
	ownCopyList, err := ownCopies(op, copies)
	if err != nil {
		return err
	}
	p, err := f.checkPlan(op, own)
	if err != nil {
		return err
	}
	data, err := checkCopies(op, p, ownCopyList)
	if err != nil {
		return err
	}
	if err := f.makeFolders(op); err != nil {
		return err
	}
	if err := f.w.WriteFile(f.dir()+"/"+files.PlanFile, own, fileMode); err != nil {
		return f.stop(op, err, "plan.json could not be written")
	}
	if err := f.verifyFile(op, files.PlanFile, own); err != nil {
		return err
	}
	if err := f.w.Mkdir(f.dir()+"/"+files.WantedDir, dirMode); err != nil {
		return f.stop(op, err, "wanted/ could not be made")
	}
	made := map[string]bool{}
	for _, w := range p.Wanted {
		elems := strings.Split(w.Path, "/")
		for i := 1; i < len(elems); i++ {
			d := strings.Join(elems[:i], "/")
			if made[d] {
				continue
			}
			made[d] = true
			if err := f.w.Mkdir(f.dir()+"/"+files.WantedDir+"/"+d, dirMode); err != nil {
				return f.stop(op, err, "a folder of wanted/ could not be made")
			}
		}
		if err := f.w.WriteFile(f.dir()+"/"+files.WantedDir+"/"+w.Path, data[w.Path], fileMode); err != nil {
			return f.stop(op, err, "a copy of a wanted file could not be written")
		}
	}
	f.plan, f.planSHA, f.parsed = own, files.Digest(own), p
	f.state = statePlanned
	return nil
}

// verifyFile reads the file name of the ceremony folder back and compares it with what was
// written. A file that is not what was written stops the folder: the write is done and cannot be
// undone.
func (f *Folder) verifyFile(op, name string, want []byte) error {
	got, err := fsx.ReadFile(f.w.FS, f.dir()+"/"+name)
	if err != nil {
		return f.stop(op, err, "%s could not be read back", name)
	}
	if !bytes.Equal(got, want) {
		return f.stop(op, ErrDiskMismatch, "%s is not what was written", name)
	}
	return nil
}

// Adopt takes a ceremony folder that [Folder.WritePlan] made in an earlier run (apply PLAN): it
// reads plan.json and the copies back and compares them with plan and with the list of the plan,
// and writes nothing. The folder must hold plan.json and wanted/ and nothing else, and wanted/
// must hold exactly the files that the plan lists, with the digests it lists, in the folders of
// their paths: an entry of any kind that the plan does not list, an empty folder too, is refused.
// A mismatch is an error that satisfies [ErrDiskMismatch] and leaves the folder unadopted.
//
// Adopt returns the copies that it read and compared, in the order of the plan's wanted list: the
// caller goes on with these bytes and reads no copy a second time. The plan bytes are the
// caller's already. The copies share nothing with the Folder, and their bytes together are at most
// the bytes that [Folder.Record] reads in all.
func (f *Folder) Adopt(plan []byte) ([]wanted.File, error) {
	if f == nil {
		return nil, newError("adopt", ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const op = "adopt"
	if err := f.begin(op, stateNew); err != nil {
		return nil, err
	}
	own := slices.Clone(plan)
	p, err := f.checkPlan(op, own)
	if err != nil {
		return nil, err
	}
	copies, err := f.checkPlannedFolder(op, p, own)
	if err != nil {
		return nil, err
	}
	f.plan, f.planSHA, f.parsed = own, files.Digest(own), p
	f.state = statePlanned
	return copies, nil
}

// checkPlannedFolder is the read of Adopt: the top of the folder, plan.json, and the tree wanted/.
// It returns the copies it read, each once, in the order of the plan.
func (f *Folder) checkPlannedFolder(op string, p *files.Plan, plan []byte) ([]wanted.File, error) {
	top, ok, err := f.listOptional(f.dir())
	if err != nil {
		return nil, newError(op, nil, err, "the ceremony folder cannot be listed")
	}
	if !ok {
		return nil, newError(op, ErrDiskMismatch, nil, "the ceremony folder does not exist")
	}
	var havePlan, haveWanted bool
	for _, e := range top {
		switch {
		case e.Name() == files.PlanFile && e.Type().IsRegular():
			havePlan = true
		case e.Name() == files.WantedDir && e.IsDir():
			haveWanted = true
		default:
			return nil, newError(op, ErrDiskMismatch, nil, "the ceremony folder holds an entry that a planned folder does not: %s", jsonset.EscapeExact(e.Name()))
		}
	}
	if !havePlan || !haveWanted {
		return nil, newError(op, ErrDiskMismatch, nil, "the ceremony folder lacks plan.json or wanted/")
	}
	onDisk, err := fsx.ReadFile(f.w.FS, f.dir()+"/"+files.PlanFile)
	if err != nil {
		return nil, newError(op, nil, err, "plan.json cannot be read")
	}
	if !bytes.Equal(onDisk, plan) {
		return nil, newError(op, ErrDiskMismatch, nil, "plan.json on disk is not the plan that was given")
	}
	listed := make(map[string]string, len(p.Wanted))
	folders := map[string]bool{}
	paths := make([]string, 0, len(p.Wanted))
	for _, w := range p.Wanted {
		if _, dup := listed[w.Path]; dup {
			return nil, newError(op, ErrInvalidInput, nil, "the plan lists %s twice", jsonset.Quote(w.Path))
		}
		listed[w.Path] = w.SHA256
		paths = append(paths, w.Path)
		for i := 0; i < len(w.Path); i++ {
			if w.Path[i] == '/' {
				folders[w.Path[:i]] = true
			}
		}
	}
	if err := checkTree(op, paths); err != nil {
		return nil, err
	}
	found, dirs, err := f.walkWanted(op)
	if err != nil {
		return nil, err
	}
	for _, d := range dirs {
		if !folders[d] {
			return nil, newError(op, ErrDiskMismatch, nil, "wanted/ holds a folder that no path of the plan is in: %s", jsonset.EscapeExact(d))
		}
	}
	if len(found) != len(listed) {
		return nil, newError(op, ErrDiskMismatch, nil, "wanted/ holds %d files and the plan lists %d", len(found), len(listed))
	}
	for _, path := range found {
		if _, ok := listed[path]; !ok {
			return nil, newError(op, ErrDiskMismatch, nil, "wanted/ holds a file that the plan does not list: %s", jsonset.EscapeExact(path))
		}
	}
	copies := make([]wanted.File, 0, len(p.Wanted))
	total := 0
	for _, w := range p.Wanted {
		b, err := fsx.ReadFile(f.w.FS, f.dir()+"/"+files.WantedDir+"/"+w.Path)
		if err != nil {
			return nil, newError(op, nil, err, "a copy cannot be read")
		}
		total += len(b)
		if total > maxFolderBytes {
			return nil, newError(op, ErrDiskMismatch, nil, "the copies are more than %d bytes in all", maxFolderBytes)
		}
		d := files.Digest(b)
		if d != w.SHA256 {
			return nil, newError(op, ErrDiskMismatch, nil, "the copy %s does not have the digest that the plan lists", jsonset.Quote(w.Path))
		}
		copies = append(copies, wanted.File{Path: w.Path, Data: b, SHA256: d})
	}
	return copies, nil
}

// walkWanted lists wanted/ and every folder under it, at most [files.MaxPathElements] deep and
// [maxWantedEntries] entries in all, and returns the paths of the regular files and of the
// folders, relative to wanted/. An entry that is not a folder or a regular file, a name that
// fsx.CheckName refuses and a temporary name are errors.
func (f *Folder) walkWanted(op string) (found, dirs []string, err error) {
	visited := 0
	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		path := f.dir() + "/" + files.WantedDir
		if rel != "" {
			path += "/" + rel
		}
		ents, err := fsx.ReadDir(f.w.FS, path)
		if err != nil {
			return newError(op, nil, err, "wanted/ cannot be listed")
		}
		for _, e := range ents {
			visited++
			if visited > maxWantedEntries {
				return newError(op, ErrDiskMismatch, nil, "wanted/ holds more than %d entries", maxWantedEntries)
			}
			if err := fsx.CheckName(e.Name()); err != nil {
				return newError(op, ErrDiskMismatch, nil, "wanted/ holds a name that is not a plain name: %s", jsonset.EscapeExact(e.Name()))
			}
			child := e.Name()
			if rel != "" {
				child = rel + "/" + child
			}
			switch {
			case e.IsDir():
				if depth+1 >= files.MaxPathElements {
					return newError(op, ErrDiskMismatch, nil, "wanted/ is deeper than %d elements", files.MaxPathElements)
				}
				dirs = append(dirs, child)
				if err := walk(child, depth+1); err != nil {
					return err
				}
			case e.Type().IsRegular():
				found = append(found, child)
			default:
				return newError(op, ErrDiskMismatch, nil, "wanted/ holds an entry that is not a file or a folder: %s", jsonset.EscapeExact(child))
			}
		}
		return nil
	}
	if err := walk("", 0); err != nil {
		return nil, nil, err
	}
	return found, dirs, nil
}

// Start writes attempt.json and then creates the two journals, births.jsonl and signatures.jsonl,
// empty; all before the first key is born (record 0005, rule 10). a is the attempt: its ceremony is
// the folder's, its plan digest is the digest of the plan that the folder holds, and a version of 0
// is taken as 1. It returns the [Trace] that writes the two journals. An error returns no Trace;
// a failed write stops the folder.
func (f *Folder) Start(a files.Attempt) (Trace, error) {
	if f == nil {
		return nil, newError("start", ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const op = "start"
	if err := f.begin(op, statePlanned); err != nil {
		return nil, err
	}
	if a.Version == 0 {
		a.Version = files.FormatVersion
	}
	if a.Ceremony != f.name {
		return nil, newError(op, ErrInvalidInput, nil, "the attempt is of the ceremony %s, and the folder is %s", jsonset.Quote(a.Ceremony), jsonset.Quote(f.name))
	}
	if a.PlanSHA256 != f.planSHA {
		return nil, newError(op, ErrInvalidInput, nil, "the attempt names another plan than the plan of the folder")
	}
	b, err := a.Canonical()
	if err != nil {
		return nil, newError(op, ErrInvalidInput, err, "the attempt cannot be written")
	}
	back, err := files.ReadAttempt(b)
	if err != nil {
		return nil, newError(op, ErrInvalidInput, err, "the attempt is refused by its reader")
	}
	if *back != a {
		return nil, newError(op, ErrInvalidInput, nil, "the attempt is not what its reader reads")
	}
	if err := f.w.WriteFile(f.dir()+"/"+files.AttemptFile, b, fileMode); err != nil {
		return nil, f.stop(op, err, "attempt.json could not be written")
	}
	if err := f.verifyFile(op, files.AttemptFile, b); err != nil {
		return nil, err
	}
	births, err := f.w.CreateJournal(f.dir() + "/" + files.BirthsFile)
	if err != nil {
		return nil, f.stop(op, err, "births.jsonl could not be created")
	}
	sigs, err := f.w.CreateJournal(f.dir() + "/" + files.SignaturesFile)
	if err != nil {
		_ = births.Close()
		return nil, f.stop(op, err, "signatures.jsonl could not be created")
	}
	f.trace = newFileTrace(births, sigs)
	f.state = stateStarted
	return f.trace, nil
}

// End closes the two journals. After it no line is written. A failed close stops the folder.
func (f *Folder) End() error {
	if f == nil {
		return newError("end", ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const op = "end"
	if err := f.begin(op, stateStarted); err != nil {
		return err
	}
	if err := f.trace.close(); err != nil {
		return f.stop(op, err, "a journal could not be closed")
	}
	f.state = stateEnded
	return nil
}

// WriteTranscript writes transcript.txt after [Folder.End]. b is the text of [Console.Transcript];
// it must pass the rules of the page: UTF-8, LF line endings, no terminal control sequence, and
// the limits of the transcript.
func (f *Folder) WriteTranscript(b []byte) error {
	if f == nil {
		return newError("transcript", ErrOutOfOrder, nil, "the folder was not made by NewFolder")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const op = "transcript"
	if err := f.begin(op, stateEnded); err != nil {
		return err
	}
	if len(b) == 0 {
		return newError(op, ErrInvalidInput, nil, "the transcript is empty; a ceremony prints at least its plan")
	}
	own := slices.Clone(b)
	if err := checkTranscript(own); err != nil {
		return newError(op, ErrInvalidInput, err, "the transcript breaks the rules of the page")
	}
	if err := f.w.WriteFile(f.dir()+"/"+files.TranscriptFile, own, fileMode); err != nil {
		return f.stop(op, err, "transcript.txt could not be written")
	}
	f.state = stateTranscribed
	return nil
}
