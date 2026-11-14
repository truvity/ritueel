package history

import (
	"context"
	"crypto/sha256"
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
)

// ErrNotBundle is returned when the folder has no history/ and has no ritueel.yaml: it is not a
// bundle. A folder with a ritueel.yaml and no history/ is a
// bundle with no ceremony yet, and the report has no record.
var ErrNotBundle = errors.New("the folder has no history folder and no ritueel.yaml: it is not a bundle")

// ErrTooMuch is returned when a run would read more than [MaxReadBytes] bytes or list more than
// [MaxFileReads] different files, or look at more than [MaxWalkEntries] names. The check is not
// done, and is never a clean one.
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
type anchorWant struct {
	key      string // what the lister says: its prev, or "closes <ceremony> <attempt digest>"
	prev     string
	closes   string
	attempt  string
	conflict bool
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

	records    int
	recs       []recInfo
	byDigest   map[string]int // digest of a record file -> the first index in recs that has it
	candidates []string       // ceremony folders with an attempt.json and no record.json
	setNames   []string       // the trust sets, in order of name
	sets       map[string]bool
	listed     map[string]*anchorWant // trust sets that a record lists
	closedPlan map[string]closedPlan  // closed ceremony -> its plan's end, read once
	lowest     int64                  // the lowest trust number of the sets; -1 when none; see lowestSet
	lowestDone bool
	unfinished map[string]string // trust sets of an unfinished ceremony -> the end its plan names
	onChain    map[string]bool   // digests of the records on the chain
	ends       []string
	wantedDirs []string // ceremony folders that have a record that was read and a wanted/ folder
	wrong      []wrongEntry
	walked     int
	walkLimit  int
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
// passes. A walkEntries of 0 is [MaxWalkEntries].
type limits struct {
	readBytes   int64
	fileReads   int
	perCode     int
	walkEntries int
}

func check(ctx context.Context, fsys fsx.FS, lim limits) (*Report, error) {
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
		walkLimit:  lim.walkEntries,
	}
	if ck.walkLimit == 0 {
		ck.walkLimit = MaxWalkEntries
	}
	if err := ck.run(); err != nil {
		return nil, err
	}
	return &Report{Records: ck.records, Ends: ck.ends, Findings: ck.col.sorted(), Omitted: ck.col.omitted}, nil
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
// name is skipped, and said (record 0006, rule 45). A name that breaks rule 38 is not entered or
// read, and is a finding (rule 46). The name is data from the stick, so the path of the finding
// holds it written with escapes, a backslash doubled (jsonset.EscapeExact), and never as it is.
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
			ck.noteListed(name, info.prev, rec)
		}
	}
	if rec.Command == files.CommandApply {
		return expect(rolePlan, "history/"+folder+"/"+files.PlanFile, rec.PlanSHA256)
	}
	// The attempt that a closing record resolves is in the folder of the ceremony it names.
	return expect(roleAttempt, "history/"+rec.Closes.Ceremony+"/"+files.AttemptFile, rec.Closes.AttemptSHA256)
}

// noteListed notes that the record rec, whose predecessor is prev, lists a file of the trust set
// name.
func (ck *checker) noteListed(name, prev string, rec *files.Record) {
	want := &anchorWant{key: prev, prev: prev}
	if rec.Command == files.CommandClose {
		want = &anchorWant{
			key:     "closes " + rec.Closes.Ceremony + " " + rec.Closes.AttemptSHA256,
			closes:  rec.Closes.Ceremony,
			attempt: rec.Closes.AttemptSHA256,
		}
	}
	switch w := ck.listed[name]; {
	case w == nil:
		ck.listed[name] = want
	case w.key != want.key:
		w.conflict = true
	}
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

// walk marks the digest from and every digest below it, as on the chain.
func (ck *checker) walk(children map[string][]int, from string) {
	stack := []string{from}
	for len(stack) > 0 {
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if ck.onChain[d] {
			continue
		}
		ck.onChain[d] = true
		for _, i := range children[d] {
			stack = append(stack, ck.recs[i].digest)
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
		if !ok {
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
// first hyphen, written with no leading zero (the spelling is Proposed on the bundle page).
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

// anchorOf is what a root list says about its anchor, read once.
type anchorOf struct {
	present bool
	value   string
	problem string // the list cannot be read
}

// rootList is the one member of root-list.json that this check reads. The rest of the list
// (its signature, version and unknown members) belongs to the root list's own check.
type rootList struct {
	LastRecordSHA256 *string `json:"last_record_sha256"`
}

// parseAnchor reads the anchor of the bytes of a root list.
func parseAnchor(data []byte) *anchorOf {
	var list rootList
	if err := strictjson.Unmarshal(data, &list, strictjson.Options{AllowUnknown: true}); err != nil {
		return &anchorOf{problem: "the root list cannot be read: " + err.Error()}
	}
	if list.LastRecordSHA256 == nil {
		return &anchorOf{}
	}
	return &anchorOf{present: true, value: *list.LastRecordSHA256}
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
				st.anchor = parseAnchor(data)
			}
		}
		switch st.kind {
		case standMissing:
			continue // a personal bundle's set has no root list (record 0006, rule 12)
		case standNotFile:
			ck.col.add(AnchorUnknown, path, "the root list cannot be read: "+st.why)
			continue
		}
		anchor = st.anchor
		if anchor.problem != "" {
			ck.col.add(AnchorUnknown, path, anchor.problem)
			continue
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
	want, known := "", false
	if w := ck.listed[name]; w != nil {
		switch {
		case w.conflict:
			return "the records that list the set differ in the record before them, so the anchor cannot be told", nil
		case w.closes != "":
			cp, err := ck.planOfClosed(w.closes, w.attempt)
			if err != nil {
				return "", err
			}
			if cp.why != "" {
				return "a closing record lists the set, and the plan of the ceremony it closed cannot be read (" + cp.why + "), so the anchor cannot be checked", nil
			}
			want, known = cp.last, true
		default:
			want, known = w.prev, true
		}
	} else if end, ok := ck.unfinished[name]; ok {
		want, known = end, true
	}
	switch {
	case !known && !a.present:
		// The set is unlisted, and says so. A list without an anchor is right only in the first
		// list, so it is a second fact unless the set has the lowest trust number of all: then it
		// can be the first, whose record was removed or whose ceremony did not finish, and the
		// first finding says all there is to say.
		if n, ok := trustNumber(name); ok && n == ck.lowestSet() {
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
		if n, ok := trustNumber(name); ok && (ck.lowest < 0 || n < ck.lowest) {
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
