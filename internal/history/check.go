package history

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strconv"
	"strings"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// The limits of a check. Every loop of the package runs over a list that one of them bounds, and
// every read is bounded by one of them or by the limits of fsx and strictjson.
const (
	// MaxFindingsPerCode is the most findings of one code that a report keeps: 1,000. A record of
	// 256 KiB can list three thousand files, and a bundle has up to 65,536 records, so what a
	// hostile bundle could make a report hold is bounded by this and not by the bundle. The
	// findings that are left out are counted in [Report.Omitted]; a code is never left out. A
	// command that prints the findings must also print that count, or a person reads the
	// thousand lines as the whole list.
	MaxFindingsPerCode = 1000
	// MaxFileReads is the most different files whose digest a run computes for the files that
	// records list: 131,072. A run that meets more stops with [ErrTooMuch]. An honest bundle has
	// about ten files for each ceremony, so this is thousands of ceremonies.
	MaxFileReads = 1 << 17
	// MaxReadBytes is the most bytes of files a run reads in all: 1 GiB. A run that reads more
	// stops with [ErrTooMuch]. Each file is at most fsx.MaxReadSize (8 MiB), each record at most
	// strictjson.DefaultMaxBytes (256 KiB), and the folders hold at most fsx.MaxDirEntries
	// (65,536) names each, so this limit is what bounds the time of a run on a hostile bundle.
	// An honest history of a thousand ceremonies is far below it.
	MaxReadBytes = 1 << 30
	// MaxWalkEntries is the most names a run looks at in all when it lists folders of the bundle:
	// 131,072. It counts the names of the root folder, of history/, of trust/ and of each
	// ceremony folder, and the names of the walk of the files inside the trust sets and inside the
	// folders of copies. A run that meets more stops with [ErrTooMuch].
	MaxWalkEntries = 1 << 17
	// MaxNamesShown is the most names a detail lists, for a fork: 8.
	MaxNamesShown = 8
	// MaxRootEntries is the most entries of the member roots that a run keeps from all the root
	// lists together, for the finding root-returns: 262,144. A run that meets more stops with
	// [ErrTooMuch]. An honest bundle has a few entries in each of a few lists. One list holds at
	// most [MaxRootsPerList] entries, because a label is one letter of A to Z.
	MaxRootEntries = 1 << 18
	// MaxRootsPerList is the most entries of roots that one root list may have for this check
	// to read it: 26, the letters A to Z of the labels. A list with more is not read, and is
	// anchor-unknown.
	MaxRootsPerList = 26
	// MaxSetPlaces is the most places at which the trust sets of a bundle stand, all sets together,
	// for the finding root-returns: 131,072. A set that records list stands at one place for each
	// different record before a record that lists it, and is judged at each, so the work and the
	// memory of the finding grow with this number and not with the number of sets. A run that meets
	// more stops with [ErrTooMuch]. It is counted when a record notes a new place of a set, before
	// the chain is walked. In a bundle that follows the rules each set stands at one place, so
	// this limit is far away.
	MaxSetPlaces = 1 << 17
	// MaxStateBytes is the most bytes of root lists that [Inspect] keeps while it walks, so that the
	// State holds the bytes that were judged: 64 MiB. A root list that can be read is at most
	// strictjson.DefaultMaxBytes (256 KiB) and an honest one is a few kilobytes. Bytes that do not
	// fit are not kept, and a bundle whose newest root list is one of them has no State: Inspect
	// ends with [ErrTooMuch].
	MaxStateBytes = 64 << 20
)

// ErrNotBundle is returned when the folder has no history/ and has no ritueel.yaml: it is not a
// bundle. A folder with a ritueel.yaml and no history/ is a
// bundle with no ceremony yet, and the report has no record.
var ErrNotBundle = errors.New("the folder has no history folder and no ritueel.yaml: it is not a bundle")

// ErrTooMuch is returned when a run would read more than [MaxReadBytes] bytes or list more than
// [MaxFileReads] different files, look at more than [MaxWalkEntries] names, keep more than
// [MaxRootEntries] entries of roots, or note more than [MaxSetPlaces] places of trust sets. The
// check is not done, and is never a clean one.
var ErrTooMuch = errors.New("the bundle holds more than a check reads")

func errTooManyNames(limit int) error {
	return fmt.Errorf("%w: more than %d names were looked at in the folders of the bundle", ErrTooMuch, limit)
}

// count adds n names that were listed to the number looked at in this run, and ends the run with
// [ErrTooMuch] when it is over the limit. The names of history/, of trust/, of each ceremony
// folder and of the walk of the trust sets and the folders of copies all count here, so that one
// run has one bound on names.
func (ck *checker) count(n int) error {
	ck.walked += n
	if ck.walked > ck.walkLimit {
		return errTooManyNames(ck.walkLimit)
	}
	return nil
}

// Roles of a listed file, as the detail of a finding names them.
const (
	roleTranscript = "the transcript"
	roleWanted     = "a wanted copy"
	roleArtifact   = "an artifact"
	rolePlan       = "the plan"
	roleAttempt    = "the attempt it closes"
	roleOwnAttempt = "its attempt"
	roleBirths     = "its birth journal"
	roleSigns      = "its journal of signatures"
)

// recInfo is what the walk keeps of one record after it was checked: no list of its files.
type recInfo struct {
	folder  string // the name of the ceremony folder
	digest  string // of record.json as stored; "" when the file could not be read
	parsed  bool   // ReadRecord succeeded, so prev below is known
	hasPrev bool
	prev    string
}

// anchorWant is what the records that list a trust set say its root list must anchor: the record
// before the ceremony that wrote the set. For a record of a ceremony that is its own, that is the
// prev_record_sha256 of the record that lists the set (empty for the first record). For a closing
// record that lists a leftover set, the ceremony that wrote the set is the closed one, so it is
// the last_record_sha256 of that ceremony's plan: closes names the ceremony and attempt the
// digest of its attempt, and the plan is found through them. When two records list the set and
// differ, conflict is set.
//
// by is the record before each record that lists the set ("" for none). It is what places the set
// for [checker.rootReturns]: a set stands at the place of each record that lists it, whatever
// kind of record that is, and not at the end that a plan names (a plan is a file that the writer
// of a closing record can make).
type anchorWant struct {
	key      string // what the lister says: its prev, or "closes <ceremony> <attempt digest>"
	prev     string
	closes   string
	attempt  string
	conflict bool
	by       map[string]struct{}
}

// closedPlan is what a closing record's closed ceremony says: the end its plan named, or why the
// plan cannot be read.
type closedPlan struct {
	last string
	why  string
}

// wrongEntry is a known name of a ceremony folder that is not the kind of entry it should be. It is
// said at the end, and only if no record lists the path: a listed path has its own finding.
type wrongEntry struct {
	path, kind string
	code       Code
}

// checker is one run of [Check].
type checker struct {
	ctx  context.Context
	fsys fsx.FS
	rd   *reader
	col  *collector

	rootLists []setList // the trust sets that have a root-list.json, as the anchor check read them

	records    int
	recs       []recInfo
	byDigest   map[string]int      // digest of a record file -> the first index in recs that has it
	candidates []string            // ceremony folders with an attempt.json and no record.json
	closed     map[string]struct{} // ceremony folders that a closing record names in closes.ceremony
	setNames   []string            // the trust sets, in order of name
	sets       map[string]bool
	listed     map[string]*anchorWant // trust sets that a record lists
	closedPlan map[string]closedPlan  // closed ceremony -> its plan's end, read once
	lowest     int64                  // the lowest trust number of the sets; -1 when none; see lowestSet
	lowestDone bool
	unfinished map[string]string // trust sets of an unfinished ceremony -> the end its plan names
	onChain    map[string]bool   // digests of the records on the chain
	forked     map[string]bool   // digests of records that two or more records name: the places of a fork
	depth      map[string]int    // digest of a record on the chain -> the number of records before it
	ends       []string
	wantedDirs []string // ceremony folders that have a record that was read and a wanted/ folder
	wrong      []wrongEntry
	walked     int
	walkLimit  int
	places     int // the places of trust sets noted so far: see noteListed
	placeLimit int
}

// Check walks the history of the bundle at fsys and reports what it finds: the chain of the
// ceremony records, the files they list, the trust sets, the anchors of the root lists, and what
// the check did not expect. It reads only: it calls fsx.ReadFile and fsx.ReadDir and no other
// method of fsys, and it never reads the clock. An error means the check could not be done (a
// read failed, a limit was met, the context ended, the folder is not a bundle), and is never a
// finding.
func Check(ctx context.Context, fsys fsx.FS) (*Report, error) {
	return check(ctx, fsys, limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode})
}

// limits are the limits of a run that a test can lower: the constants above are what [Check]
// passes. A walkEntries of 0 is [MaxWalkEntries], a rootEntries of 0 is [MaxRootEntries] and a
// setPlaces of 0 is [MaxSetPlaces].
type limits struct {
	readBytes   int64
	fileReads   int
	perCode     int
	walkEntries int
	rootEntries int
	setPlaces   int
}

// check is one run of [Check]: the walk of [runCheck], and the report of what it collected.
func check(ctx context.Context, fsys fsx.FS, lim limits) (*Report, error) {
	ck, err := runCheck(ctx, fsys, lim, false)
	if err != nil {
		return nil, err
	}
	return ck.report(), nil
}

// report is what the walk found, as [Check] returns it.
func (ck *checker) report() *Report {
	return &Report{Records: ck.records, Ends: ck.ends, Findings: ck.col.sorted(), Omitted: ck.col.omitted}
}

// runCheck is the one walk of the bundle that [Check] and [Inspect] share. It returns the checker
// with everything the walk collected, and no second walk is made from it. With keep set, the walk
// keeps the bytes of the root lists that it read and could read (at most [MaxStateBytes] in all),
// so that [Inspect] can return the bytes that were judged and not a second read of them.
func runCheck(ctx context.Context, fsys fsx.FS, lim limits, keep bool) (*checker, error) {
	if fsys == nil {
		return nil, fsx.ErrNoRoot
	}
	ck := &checker{
		ctx:        ctx,
		fsys:       fsys,
		rd:         newReader(ctx, fsys, lim),
		col:        newCollector(lim.perCode),
		byDigest:   map[string]int{},
		sets:       map[string]bool{},
		listed:     map[string]*anchorWant{},
		closedPlan: map[string]closedPlan{},
		unfinished: map[string]string{},
		onChain:    map[string]bool{},
		forked:     map[string]bool{},
		depth:      map[string]int{},
		walkLimit:  lim.walkEntries,
		placeLimit: lim.setPlaces,
	}
	if ck.walkLimit == 0 {
		ck.walkLimit = MaxWalkEntries
	}
	if ck.placeLimit == 0 {
		ck.placeLimit = MaxSetPlaces
	}
	if keep {
		ck.rd.keep, ck.rd.keepLeft = true, MaxStateBytes
	}
	if err := ck.run(); err != nil {
		return nil, err
	}
	return ck, nil
}

func (ck *checker) run() error {
	hist, found, err := ck.readDirOptional("history")
	if err != nil {
		return err
	}
	if !found {
		ok, err := ck.hasManifest()
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotBundle
		}
	}
	trust, _, err := ck.readDirOptional("trust")
	if err != nil {
		return err
	}
	ck.trustSets(trust)
	for _, e := range hist {
		if err := ck.ctx.Err(); err != nil {
			return err
		}
		name := e.Name()
		if !ck.plainName("history", name) {
			continue
		}
		if !e.IsDir() {
			ck.notAFolder("history", name, e, "a ceremony folder")
			continue
		}
		if err := ck.ceremony(name); err != nil {
			return err
		}
	}
	ck.chain()
	if err := ck.trust(); err != nil {
		return err
	}
	if err := ck.anchors(); err != nil {
		return err
	}
	ck.trustSequence()
	if err := ck.rootReturns(); err != nil {
		return err
	}
	if err := ck.unlistedFiles(); err != nil {
		return err
	}
	ck.flushWrong()
	return nil
}

// notAFolder says that the entry name of dir is not a folder where a folder belongs: a plain
// file is a notice, and anything else (a link, a FIFO, a socket, a device) is [codeOddEntry].
func (ck *checker) notAFolder(dir, name string, e fs.DirEntry, what string) {
	path := dir + "/" + name
	if e.Type().IsRegular() {
		ck.col.add(UnexpectedFile, path, "it is a file, and "+what+" is expected")
		return
	}
	ck.col.add(codeOddEntry, path, "it is "+kindOf(e)+", where "+what+" belongs")
}

// readDirOptional lists a folder of the bundle; found is false when it does not exist. A link, a
// file in its place, a folder of more than fsx.MaxDirEntries names, or a failed read is an error.
func (ck *checker) readDirOptional(path string) (ents []fs.DirEntry, found bool, err error) {
	if err := ck.ctx.Err(); err != nil {
		return nil, false, err
	}
	ents, err = fsx.ReadDir(ck.fsys, path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := ck.count(len(ents)); err != nil {
		return nil, false, err
	}
	return ents, true, nil
}

// hasManifest reports whether the root of the bundle holds ritueel.yaml as a regular file.
func (ck *checker) hasManifest() (bool, error) {
	ents, _, err := ck.readDirOptional(".")
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if e.Name() == "ritueel.yaml" && e.Type().IsRegular() {
			return true, nil
		}
	}
	return false, nil
}

// plainName decides whether a name from the list of dir is one to look at. A leftover temporary
// name is skipped, and said (record 0006, rule 45). A name that breaks record 0006, rule 38, is
// not entered or read, and is a finding (record 0006, rule 46). The name is data from the stick,
// so the path of the finding holds it written with escapes, a backslash doubled
// (jsonset.EscapeExact), and never as it is.
func (ck *checker) plainName(dir, name string) bool {
	return ck.plainNameIn(dir, name, UnexpectedFile, "a leftover temporary name; it is skipped (record 0006, rule 45)")
}

// plainNameIn is plainName with the code and the detail that a leftover temporary name gets in
// the folder, which differ inside a trust set.
func (ck *checker) plainNameIn(dir, name string, tempCode Code, tempDetail string) bool {
	switch {
	case hasTempPrefix(name):
		ck.col.add(tempCode, jsonset.EscapeExact(dir+"/"+name), tempDetail)
		return false
	case fsx.CheckName(name) != nil:
		ck.col.add(UnexpectedName, jsonset.EscapeExact(dir+"/"+name), "the name breaks the rule for names (record 0006, rule 38)")
		return false
	}
	return true
}

// hasTempPrefix reports whether name starts with fsx.TempPrefix, compared without case. Only the
// ASCII letters fold: the prefix is ASCII, and a name with another character is refused by the
// rule for names anyway.
func hasTempPrefix(name string) bool {
	if len(name) < len(fsx.TempPrefix) {
		return false
	}
	for i := 0; i < len(fsx.TempPrefix); i++ {
		c := name[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != fsx.TempPrefix[i] {
			return false
		}
	}
	return true
}

// kindOf says what an entry of a list is, in a few fixed words.
func kindOf(e fs.DirEntry) string {
	switch t := e.Type(); {
	case t.IsDir():
		return "a folder"
	case t&fs.ModeSymlink != 0:
		return "a symbolic link"
	case t.IsRegular():
		return "a file"
	}
	return "neither a file nor a folder"
}

// trustSets lists the trust sets: the folders of trust/ with a plain name.
func (ck *checker) trustSets(ents []fs.DirEntry) {
	for _, e := range ents {
		name := e.Name()
		if !ck.plainName("trust", name) {
			continue
		}
		if !e.IsDir() {
			ck.notAFolder("trust", name, e, "a trust set (a folder)")
			continue
		}
		ck.sets[name] = true
		ck.setNames = append(ck.setNames, name)
	}
}

// ceremony looks at one ceremony folder: the names in it, then its record, if it has one.
func (ck *checker) ceremony(folder string) error {
	dir := "history/" + folder
	ents, err := fsx.ReadDir(ck.fsys, dir)
	if err != nil {
		return err
	}
	if err := ck.count(len(ents)); err != nil {
		return err
	}
	var hasRecord, hasAttempt, hasWanted bool
	for _, e := range ents {
		name := e.Name()
		if !ck.plainName(dir, name) {
			continue
		}
		switch name {
		case files.RecordFile:
			hasRecord = true // its type is the record's business: a record that is not a file is record-invalid
		case files.AttemptFile, files.PlanFile, files.TranscriptFile, files.BirthsFile, files.SignaturesFile:
			hasAttempt = hasAttempt || name == files.AttemptFile
			if !e.Type().IsRegular() {
				code := UnexpectedFile
				if name == files.AttemptFile || name == files.BirthsFile || name == files.SignaturesFile {
					code = codeOddFile
				}
				ck.wrong = append(ck.wrong, wrongEntry{path: dir + "/" + name, kind: kindOf(e), code: code})
			}
		case files.WantedDir:
			hasWanted = e.IsDir()
			if !hasWanted {
				ck.col.add(UnexpectedFile, dir+"/"+name, "it is "+kindOf(e)+", and a folder is expected")
			}
		default:
			ck.col.add(UnexpectedFile, dir+"/"+name, "a ceremony folder does not hold a name like this")
		}
	}
	switch {
	case hasRecord:
		if err := ck.record(folder); err != nil {
			return err
		}
		if hasWanted && ck.recs[len(ck.recs)-1].parsed {
			ck.wantedDirs = append(ck.wantedDirs, folder)
		}
	case hasAttempt:
		ck.candidates = append(ck.candidates, folder)
	}
	return nil
}

// record reads and checks the record.json of one ceremony folder, and the files it lists.
func (ck *checker) record(folder string) error {
	ck.records++
	path := "history/" + folder + "/" + files.RecordFile
	data, st, err := ck.rd.read(path)
	if err != nil {
		return err
	}
	info := recInfo{folder: folder}
	switch st.kind {
	case standMissing:
		return fmt.Errorf("%s was listed and is gone: the bundle changed while it was read", path)
	case standNotFile:
		ck.col.add(RecordInvalid, path, "the record cannot be read: "+st.why)
		ck.recs = append(ck.recs, info)
		return nil
	}
	info.digest = files.Digest(data)
	if _, ok := ck.byDigest[info.digest]; !ok {
		ck.byDigest[info.digest] = len(ck.recs)
	}
	rec, err := files.ReadRecord(data)
	var ve *files.VersionError
	switch {
	case errors.As(err, &ve):
		ck.col.add(RecordVersionUnknown, path, "version "+strconv.FormatInt(ve.Version, 10)+" is not known")
	case err != nil:
		ck.col.add(RecordInvalid, path, err.Error())
	}
	if ve == nil {
		// A document that breaks the strict rules has no canonical form: record-invalid says so.
		if ok, cerr := canonjson.IsCanonical(data); cerr == nil && !ok {
			ck.col.add(RecordNotCanonical, path, "the bytes are not the canonical form of RFC 8785 (record 0006, rule 8)")
		}
	}
	if err == nil && recordCeremonyMustMatchFolder && rec.Ceremony != folder {
		ck.col.add(RecordInvalid, path, "the ceremony member is "+rec.Ceremony+", and the name of the folder is "+folder)
	}
	if err == nil {
		info.parsed = true
		info.hasPrev = rec.PrevRecordSHA256 != ""
		info.prev = rec.PrevRecordSHA256
	}
	ck.recs = append(ck.recs, info)
	if err != nil {
		return nil
	}
	return ck.listedFiles(&info, rec)
}

// listedFiles checks every file that a record lists, and notes the trust sets it lists. It keeps
// nothing of the record's lists.
func (ck *checker) listedFiles(info *recInfo, rec *files.Record) error {
	folder := info.folder
	seen := map[[sha256.Size]byte]struct{}{}
	expect := func(role, path, want string) error {
		return ck.expect(seen, folder, role, path, want)
	}
	if err := expect(roleTranscript, "history/"+folder+"/"+files.TranscriptFile, rec.TranscriptSHA256); err != nil {
		return err
	}
	// The attempt and the journals are checked when the record names their digests.
	for _, f := range []struct{ role, name, digest string }{
		{roleOwnAttempt, files.AttemptFile, rec.AttemptSHA256},
		{roleBirths, files.BirthsFile, rec.BirthsSHA256},
		{roleSigns, files.SignaturesFile, rec.SignaturesSHA256},
	} {
		if f.digest == "" {
			continue
		}
		if err := expect(f.role, "history/"+folder+"/"+f.name, f.digest); err != nil {
			return err
		}
	}
	if rec.Command == files.CommandClose && rec.Closes != nil {
		if ck.closed == nil {
			ck.closed = map[string]struct{}{}
		}
		ck.closed[rec.Closes.Ceremony] = struct{}{}
	}
	for _, w := range rec.Wanted {
		if err := expect(roleWanted, "history/"+folder+"/"+files.WantedDir+"/"+w.Path, w.SHA256); err != nil {
			return err
		}
	}
	for _, a := range rec.Artifacts {
		if err := expect(roleArtifact, a.Path, a.SHA256); err != nil {
			return err
		}
		if name, ok := trustSetOf(a.Path); ok && ck.sets[name] {
			if err := ck.noteListed(name, info.prev, rec); err != nil {
				return err
			}
		}
	}
	if rec.Command == files.CommandApply {
		return expect(rolePlan, "history/"+folder+"/"+files.PlanFile, rec.PlanSHA256)
	}
	// The attempt that a closing record resolves is in the folder of the ceremony it names.
	return expect(roleAttempt, "history/"+rec.Closes.Ceremony+"/"+files.AttemptFile, rec.Closes.AttemptSHA256)
}

// noteListed notes that the record rec, whose predecessor is prev, lists a file of the trust set
// name. Each different prev is one place of the set, and it is counted when it is new, so that the
// notes are bounded by [MaxSetPlaces] and not by the number of records. The run ends with
// [ErrTooMuch] when the limit is passed.
func (ck *checker) noteListed(name, prev string, rec *files.Record) error {
	want := &anchorWant{key: prev, prev: prev}
	if rec.Command == files.CommandClose {
		want = &anchorWant{
			key:     "closes " + rec.Closes.Ceremony + " " + rec.Closes.AttemptSHA256,
			closes:  rec.Closes.Ceremony,
			attempt: rec.Closes.AttemptSHA256,
		}
	}
	w := ck.listed[name]
	switch {
	case w == nil:
		w = want
		ck.listed[name] = w
	case w.key != want.key:
		w.conflict = true
	}
	if w.by == nil {
		w.by = map[string]struct{}{}
	}
	if _, seen := w.by[prev]; !seen {
		ck.places++
		if ck.places > ck.placeLimit {
			return fmt.Errorf("%w: the trust sets stand at more than %d places in the chain of records (MaxSetPlaces)", ErrTooMuch, ck.placeLimit)
		}
		w.by[prev] = struct{}{}
	}
	return nil
}

// trustSetOf returns the name of the trust set that a path of a record is a file of: the path
// begins trust/<name>/ and has a file below it.
func trustSetOf(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "trust/")
	if !ok {
		return "", false
	}
	name, tail, ok := strings.Cut(rest, "/")
	return name, ok && name != "" && tail != ""
}

// expect checks one listed file against the digest the record gives. The same role, path and
// digest in one record is checked once.
func (ck *checker) expect(seen map[[sha256.Size]byte]struct{}, folder, role, path, want string) error {
	key := sha256.Sum256([]byte(role + "\x00" + path + "\x00" + want))
	if _, dup := seen[key]; dup {
		return nil
	}
	seen[key] = struct{}{}
	st, err := ck.rd.digest(path)
	if err != nil {
		return err
	}
	by := "listed by " + folder + " as " + role
	switch {
	case st.kind == standMissing:
		ck.col.add(FileMissing, path, by)
	case st.kind == standNotFile:
		ck.col.add(FileDigest, path, by+": "+st.why)
	case st.digest != want:
		code := FileDigest
		if role == roleTranscript {
			code = TranscriptDigest
		}
		ck.col.add(code, path, by+": expected "+want[:16]+", found "+st.digest[:16])
	}
	return nil
}

// chain finds the chain, the forks, the records off the chain and the ends of the history from
// what the walk kept.
func (ck *checker) chain() {
	children := map[string][]int{} // the digest of a record -> the records that name it
	roots := 0
	for i, r := range ck.recs {
		switch {
		case !r.parsed:
		case r.hasPrev:
			children[r.prev] = append(children[r.prev], i)
		default:
			roots++
		}
	}
	// Mark what is on the chain: from the one record without a predecessor, down the names. A
	// digest is visited once, so a loop (which a hash makes impossible) cannot hold the walk.
	if roots == 1 {
		for _, r := range ck.recs {
			if r.parsed && !r.hasPrev {
				ck.walk(children, r.digest)
			}
		}
	}
	for _, r := range ck.recs {
		path := "history/" + r.folder
		switch {
		case !r.parsed:
			ck.col.add(RecordOffChain, path, "the record could not be read, so it is not on the chain")
		case !r.hasPrev:
			if roots > 1 {
				ck.col.add(ChainBroken, path, "it has no prev_record_sha256, and so does another record: only the first has none (record 0006, rule 8)")
			}
		default:
			if _, ok := ck.byDigest[r.prev]; !ok {
				ck.col.add(ChainBroken, path, "prev_record_sha256 "+r.prev[:16]+" is not the digest of a record")
			} else if !ck.onChain[r.digest] {
				ck.col.add(RecordOffChain, path, "the record before it is not on the chain")
			}
		}
	}
	for _, prev := range slices.Sorted(maps.Keys(children)) {
		kids := children[prev]
		if len(kids) >= 2 {
			ck.forked[prev] = true
		}
		first, ok := ck.byDigest[prev]
		if len(kids) < 2 || !ok {
			continue // a missing predecessor is chain-broken for each record that names it
		}
		names := make([]string, 0, MaxNamesShown+1)
		for _, k := range kids {
			if len(names) == MaxNamesShown {
				names = append(names, "...")
				break
			}
			names = append(names, ck.recs[k].folder)
		}
		ck.col.add(Fork, "history/"+ck.recs[first].folder,
			strconv.Itoa(len(kids))+" records name it: "+strings.Join(names, ", ")+" (record 0006, rule 35)")
	}
	for d := range ck.byDigest {
		if len(children[d]) == 0 {
			ck.ends = append(ck.ends, d)
		}
	}
	slices.Sort(ck.ends)
}

// walk marks the digest from and every digest below it, as on the chain, and keeps how many records
// are before each: the place of a record in the chain, which orders the root lists
// ([checker.rootReturns]). Two records that name the same predecessor have the same depth.
func (ck *checker) walk(children map[string][]int, from string) {
	type step struct {
		digest string
		depth  int
	}
	stack := []step{{from, 0}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if ck.onChain[s.digest] {
			continue
		}
		ck.onChain[s.digest] = true
		ck.depth[s.digest] = s.depth
		for _, i := range children[s.digest] {
			stack = append(stack, step{ck.recs[i].digest, s.depth + 1})
		}
	}
}

// trust looks at each trust set that no record lists: an unfinished ceremony if an open attempt
// is linked to it, else a sign that the newest record was removed (record 0006, rule 34).
func (ck *checker) trust() error {
	var open map[int64][]string
	var end string
	for _, name := range ck.setNames {
		if ck.listed[name] != nil {
			continue
		}
		if open == nil {
			var err error
			if open, end, err = ck.openAttempts(); err != nil {
				return err
			}
		}
		path := "trust/" + name
		n, ok := trustNumber(name)
		if !ok || n < 1 {
			ck.col.add(TrustSetUnlisted, path, "no record lists it, and its name has no trust number")
			continue
		}
		cands := open[n]
		if len(cands) == 0 {
			ck.col.add(TrustSetUnlisted, path, "no record lists it, and no open attempt that belongs to this history has its trust sequence "+strconv.FormatInt(n, 10))
			continue
		}
		names := cands
		if len(names) > 3 {
			names = append(slices.Clone(names[:3]), "...")
		}
		ck.unfinished[name] = end
		ck.col.add(UnfinishedCeremony, path, "an attempt of "+strings.Join(names, ", ")+" is open (record 0006, rule 34); the end of the history shown is the end before this ceremony")
	}
	return nil
}

// trustNumber returns the number a trust set's name begins with: the decimal digits before the
// first hyphen, written with no leading zero (the spelling is Proposed on the bundle page). A name
// that begins 0- has the number 0 here, which is a number that is read and is no trust number: the
// trust numbers are 1 and up (the sequence of a root list is at least 1), and the callers that
// judge a name by its number ask for [trustNumberFrom1].
func trustNumber(name string) (int64, bool) {
	digits, _, found := strings.Cut(name, "-")
	if !found || digits == "" || len(digits) > 15 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != digits {
		return 0, false
	}
	return n, true
}

// trustNumberFrom1 is [trustNumber] for a name whose number is a trust number: 1 and up. A number of
// 0 is read by [trustNumber] and is no trust number.
func trustNumberFrom1(name string) (int64, bool) {
	n, ok := trustNumber(name)
	return n, ok && n >= 1
}

// openAttempts links each open attempt to the trust sequence of its plan, and returns the
// ceremony folders for each sequence and the end of the history that the plans must name. An
// attempt is open when its ceremony folder has no record.json. (A ceremony that a closing record
// closes cannot link either: the closing record is then the end, and a plan made before it
// cannot name it.) It is linked when:
//   - it and its plan are readable, the plan's digest is the attempt's plan_sha256, and both
//     name the folder as their ceremony; and
//   - the plan belongs to this history: when the history has no record, the plan has no
//     last_record_sha256 (it is the first ceremony); when it has records, the plan's
//     last_record_sha256 is the digest of the one end of the chain, because a ceremony is planned
//     against the end that stands then. A plan that does not meet this cannot be told from one
//     that someone put there, and the trust set is then reported as unlisted.
//
// An attempt that does not link is left out. Each file is read once here.
func (ck *checker) openAttempts() (map[int64][]string, string, error) {
	out := map[int64][]string{}
	end := ""
	if ck.records > 0 {
		if len(ck.ends) != 1 {
			return out, "", nil // a history with two ends, or none that can be read, has no end to plan against
		}
		end = ck.ends[0]
	}
	for _, folder := range ck.candidates {
		dir := "history/" + folder + "/"
		abytes, st, err := ck.rd.read(dir + files.AttemptFile)
		if err != nil {
			return nil, "", err
		}
		if st.kind != standOK {
			continue
		}
		a, err := files.ReadAttempt(abytes)
		if err != nil || a.Ceremony != folder {
			continue
		}
		pbytes, st, err := ck.rd.read(dir + files.PlanFile)
		if err != nil {
			return nil, "", err
		}
		if st.kind != standOK || files.Digest(pbytes) != a.PlanSHA256 {
			continue
		}
		p, err := files.ReadPlan(pbytes)
		if err != nil || p.Ceremony != folder || p.LastRecordSHA256 != end {
			continue
		}
		out[*p.TrustSequence] = append(out[*p.TrustSequence], folder)
	}
	return out, end, nil
}

// anchorOf is what a root list says about its anchor and its keys, read once.
type anchorOf struct {
	present bool
	value   string
	problem string // the list cannot be read
	// sequence is the member sequence, when the list has it as an integer.
	sequence    int64
	hasSequence bool
	// keys are the entries of roots that name a pin or a fingerprint, in the order of the file.
	keys []rootKey
	// raw is the bytes of the list that were parsed, kept only when the run keeps them (see
	// [Inspect]) and only for a list that can be read.
	raw []byte
}

// rootKey is one entry of the member roots, in the one form this check compares: the bytes of the
// pin and of the fingerprint, so that the case of the hexadecimal digits never matters. An entry
// with no pin and a fingerprint is a key too (hasPin is false): it is known by its fingerprint.
type rootKey struct {
	pin    [32]byte
	hasPin bool
	fp     [20]byte
	hasFP  bool
	label  string // as the file has it, cut short; it is shown only escaped
}

// maxLabelShown is the most bytes of a label that are kept; a label is one letter on the page.
const maxLabelShown = 16

// rootList is what this check reads of root-list.json: the anchor, the sequence and the entries
// of roots. The rest of the list (its signature, version and unknown members) belongs to the
// root list's own check.
type rootList struct {
	LastRecordSHA256 *string     `json:"last_record_sha256"`
	Sequence         *int64      `json:"sequence"`
	Roots            []rootEntry `json:"roots"`
}

type rootEntry struct {
	Label       *string `json:"label"`
	Pin         *string `json:"x509_spki_sha256"`
	Fingerprint *string `json:"openpgp_fingerprint"`
}

// parseAnchor reads the anchor and the keys of the bytes of a root list. The entries of roots are
// read in the most lenient way this check has, so that a list that the reader of root lists
// refuses (a pin in capitals, with a 0x prefix or with separators, an entry with a fingerprint and
// no pin, a label that is not a letter, no sequence) hides no key: see [hexForm]. An entry with a
// pin or a fingerprint that is there and cannot be read, and an entry with neither member, make
// the whole list a list that cannot be read (the finding anchor-unknown), because what it holds is
// not known; a host refuses such a list too. The entries of a list that can be read count against
// the limit of the run ([MaxRootEntries]), those of a list that cannot be read do not: an error is
// [ErrTooMuch].
func (r *reader) parseAnchor(data []byte) (*anchorOf, error) {
	var list rootList
	if err := strictjson.Unmarshal(data, &list, strictjson.Options{AllowUnknown: true}); err != nil {
		return &anchorOf{problem: "the root list cannot be read: " + err.Error()}, nil
	}
	if len(list.Roots) > MaxRootsPerList {
		return &anchorOf{problem: "the root list cannot be read: it has more than " + strconv.Itoa(MaxRootsPerList) + " entries of roots, and a label is one letter of A to Z"}, nil
	}
	a := &anchorOf{}
	if list.LastRecordSHA256 != nil {
		a.present, a.value = true, *list.LastRecordSHA256
	}
	if list.Sequence != nil {
		a.sequence, a.hasSequence = *list.Sequence, true
	}
	for i, e := range list.Roots {
		k, ok := keyOf(e)
		if !ok {
			return &anchorOf{problem: "the root list cannot be read: entry " + strconv.Itoa(i) + " of roots has a pin or an OpenPGP fingerprint that is not hexadecimal digits of the right length"}, nil
		}
		if !k.hasPin && !k.hasFP {
			return &anchorOf{problem: "the root list cannot be read: entry " + strconv.Itoa(i) + " of roots has neither a pin nor an OpenPGP fingerprint"}, nil
		}
		a.keys = append(a.keys, k)
	}
	// The entries of a list that can be read are kept; a list that cannot be read keeps none, and
	// counts none.
	if r.entriesLeft -= len(a.keys); r.entriesLeft < 0 {
		return nil, fmt.Errorf("%w: more than %d entries of roots were kept from the root lists", ErrTooMuch, r.entryLimit)
	}
	// The bytes are kept while the budget lasts; a list whose bytes are not kept is still judged.
	if r.keep && int64(len(data)) <= r.keepLeft {
		r.keepLeft -= int64(len(data))
		a.raw = data
	}
	return a, nil
}

// hexForm reads s as the n bytes that its hexadecimal digits stand for, in the most lenient way
// this check has: digits of either case, white space around the text, a 0x prefix, and the
// separators space, colon and hyphen between digits are accepted and dropped. Every list that
// the reader of root lists takes is read the same way; the forms that only this check takes are
// all read as the key the writer meant, so that none of them hides a key from the later lists.
func hexForm(s string, n int) (b []byte, ok bool) {
	s = strings.Trim(s, " \t\r\n")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if strings.ContainsAny(s, " :-") {
		s = strings.NewReplacer(" ", "", ":", "", "-", "").Replace(s)
	}
	if len(s) != 2*n {
		return nil, false
	}
	b = make([]byte, n)
	if _, err := hex.Decode(b, []byte(s)); err != nil {
		return nil, false
	}
	return b, true
}

// keyOf turns an entry of roots into a rootKey. ok is false when the entry has a pin or a
// fingerprint that is there and cannot be read. An entry with neither member gives a key that
// holds nothing: the caller refuses the list.
func keyOf(e rootEntry) (k rootKey, ok bool) {
	if e.Pin != nil {
		b, good := hexForm(*e.Pin, len(k.pin))
		if !good {
			return k, false
		}
		copy(k.pin[:], b)
		k.hasPin = true
	}
	if e.Fingerprint != nil {
		b, good := hexForm(*e.Fingerprint, len(k.fp))
		if !good {
			return k, false
		}
		copy(k.fp[:], b)
		k.hasFP = true
	}
	if e.Label != nil {
		k.label = cut(*e.Label, maxLabelShown)
	}
	return k, true
}

// anchors checks the last_record_sha256 of the root list of each trust set that has one. It is
// the digest of the record before the ceremony that wrote the set: the prev_record_sha256 of the
// record that lists the set, or, for a set of an unfinished ceremony, the end its plan names; and
// it is absent exactly when that ceremony is the first. It is also the digest of a record on the
// chain. A list that cannot be read is the same finding. A set that nothing explains (no record
// lists it, no open attempt) is reported as unlisted already; a list without an anchor in it is
// a second finding unless it is in the set with the lowest trust number (see [checker.judgeAnchor]).
func (ck *checker) anchors() error {
	for _, name := range ck.setNames {
		path := "trust/" + name + "/root-list.json"
		var anchor *anchorOf
		st, cached := ck.rd.cached(path)
		if !cached {
			data, rst, err := ck.rd.read(path)
			if err != nil {
				return err
			}
			st = rst
			if st.kind == standOK {
				if st.anchor, err = ck.rd.parseAnchor(data); err != nil {
					return err
				}
			}
		}
		switch st.kind {
		case standMissing:
			continue // a personal bundle's set has no root list (record 0006, rule 12)
		case standNotFile:
			ck.col.add(AnchorUnknown, path, "the root list cannot be read: "+st.why)
			ck.rootLists = append(ck.rootLists, setList{set: name})
			continue
		}
		anchor = st.anchor
		if anchor.problem != "" {
			ck.col.add(AnchorUnknown, path, anchor.problem)
			ck.rootLists = append(ck.rootLists, setList{set: name})
			continue
		}
		ck.rootLists = append(ck.rootLists, setList{set: name, read: anchor})
		// The range of a sequence is judged here: it is an integer of at least 1 (root-list page). A
		// sequence that the strict reader of JSON does not accept (outside plus or minus 2^53-1, so
		// also the lowest 64-bit number) makes the list one that cannot be read, as for every other
		// integer outside that range: it is anchor-unknown with that detail and the bundle fails, and
		// its keys are not read, because no lenient reader of the file is added.
		if anchor.hasSequence && anchor.sequence < 1 {
			// The keys of the list are read all the same (it is in rootLists above), so that the list
			// hides no key from the later lists.
			ck.col.add(AnchorUnknown, path, "the root list has a sequence of "+strconv.FormatInt(anchor.sequence, 10)+", and a sequence is an integer of at least 1; its keys are still read")
		}
		why, err := ck.judgeAnchor(name, anchor)
		if err != nil {
			return err
		}
		if why != "" {
			ck.col.add(AnchorUnknown, path, why)
		}
	}
	return nil
}

// judgeAnchor says what is wrong with the anchor of the root list of the set name, or "". An
// error is a read that failed.
func (ck *checker) judgeAnchor(name string, a *anchorOf) (string, error) {
	if a.present && !files.IsDigest(a.value) {
		return "last_record_sha256 is not a SHA-256 digest", nil
	}
	want, known, why, err := ck.anchorWanted(name)
	if err != nil || why != "" {
		return why, err
	}
	switch {
	case !known && !a.present:
		// The set is unlisted, and says so. A list without an anchor is right only in the first
		// list, so it is a second fact unless the set has the lowest trust number of all: then it
		// can be the first, whose record was removed or whose ceremony did not finish, and the
		// first finding says all there is to say.
		if n, ok := trustNumberFrom1(name); ok && n == ck.lowestSet() {
			return "", nil
		}
		return "the root list has no last_record_sha256, and the set is not the first one", nil
	case known && want == "" && a.present:
		// Reached for a set that a closing record lists, whose closed ceremony was the first: its
		// plan names no end, and a list that anchors a record cannot be honest. (For an ordinary
		// first record the anchor cannot be on the chain, and the last case says it.)
		return "last_record_sha256 is there, and the ceremony that wrote the set has no record before it", nil
	case known && want != "" && !a.present:
		return "the root list has no last_record_sha256, and the ceremony that wrote the set has a record before it (" + want[:16] + ")", nil
	case known && want != "" && a.value != want:
		return "last_record_sha256 " + a.value[:16] + " is not the record before the ceremony that wrote the set (" + want[:16] + ")", nil
	case a.present && !ck.onChain[a.value]:
		// Also the case of a first list that has an anchor: no record can come before the first.
		return "last_record_sha256 " + a.value[:16] + " is not the digest of a record on the chain", nil
	}
	return "", nil
}

// anchorWanted is the record that the root list of the set name must anchor, as the records say
// it and not as the list says it: "" is none (the ceremony that wrote the set is the first). known
// is false when nothing says it (no record lists the set and no open attempt belongs to it), and
// why is a reason when the records that list the set do not give one answer. An error is a read
// that failed. This is only the anchor that a list must have; the place of a list in the chain is
// the place of the records that list its set ([checker.placingsOf]).
func (ck *checker) anchorWanted(name string) (want string, known bool, why string, err error) {
	if w := ck.listed[name]; w != nil {
		switch {
		case w.conflict:
			return "", false, "the records that list the set differ in the record before them, so the anchor cannot be told", nil
		case w.closes != "":
			cp, err := ck.planOfClosed(w.closes, w.attempt)
			if err != nil {
				return "", false, "", err
			}
			if cp.why != "" {
				return "", false, "a closing record lists the set, and the plan of the ceremony it closed cannot be read (" + cp.why + "), so the anchor cannot be checked", nil
			}
			return cp.last, true, "", nil
		}
		return w.prev, true, "", nil
	}
	if end, ok := ck.unfinished[name]; ok {
		return end, true, "", nil
	}
	return "", false, "", nil
}

// planOfClosed finds the plan of the ceremony c that a closing record closes, and returns the end
// that plan named (empty for a first ceremony). The plan is the one whose digest the attempt
// names, and the attempt is the one whose digest the closing record names. When any of that does
// not hold, or a file cannot be read as it should be, the plan is not found and why says so: the
// anchor of the set is then not accepted, because nothing it could be compared with is known.
func (ck *checker) planOfClosed(c, attemptDigest string) (closedPlan, error) {
	if cp, ok := ck.closedPlan[c]; ok {
		return cp, nil
	}
	cp, err := ck.readPlanOfClosed(c, attemptDigest)
	if err != nil {
		return closedPlan{}, err
	}
	ck.closedPlan[c] = cp
	return cp, nil
}

func (ck *checker) readPlanOfClosed(c, attemptDigest string) (closedPlan, error) {
	dir := "history/" + c + "/"
	abytes, st, err := ck.rd.read(dir + files.AttemptFile)
	if err != nil {
		return closedPlan{}, err
	}
	if st.kind != standOK {
		return closedPlan{why: "its attempt is not there as a file"}, nil
	}
	if files.Digest(abytes) != attemptDigest {
		return closedPlan{why: "its attempt is not the one the closing record names"}, nil
	}
	a, aerr := files.ReadAttempt(abytes)
	if aerr != nil || a.Ceremony != c {
		return closedPlan{why: "its attempt cannot be read"}, nil
	}
	pbytes, st, err := ck.rd.read(dir + files.PlanFile)
	if err != nil {
		return closedPlan{}, err
	}
	if st.kind != standOK {
		return closedPlan{why: "its plan is not there as a file"}, nil
	}
	if files.Digest(pbytes) != a.PlanSHA256 {
		return closedPlan{why: "its plan is not the one its attempt names"}, nil
	}
	p, perr := files.ReadPlan(pbytes)
	if perr != nil || p.Ceremony != c {
		return closedPlan{why: "its plan cannot be read"}, nil
	}
	return closedPlan{last: p.LastRecordSHA256}, nil
}

// lowestSet returns the lowest trust number among the trust sets, or -1 when none has a number.
// It is worked out once.
func (ck *checker) lowestSet() int64 {
	if ck.lowestDone {
		return ck.lowest
	}
	ck.lowestDone = true
	ck.lowest = -1
	for _, name := range ck.setNames {
		if n, ok := trustNumberFrom1(name); ok && (ck.lowest < 0 || n < ck.lowest) {
			ck.lowest = n
		}
	}
	return ck.lowest
}

// flushWrong says each known name of a ceremony folder that is not the kind of entry it should be
// and that no record lists. A listed path has its own finding, so it is not said twice.
func (ck *checker) flushWrong() {
	for _, w := range ck.wrong {
		if !ck.rd.isListed(w.path) {
			ck.col.add(w.code, w.path, "it is "+w.kind+", and a file is expected")
		}
	}
}
