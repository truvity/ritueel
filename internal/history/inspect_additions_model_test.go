//go:build linux || darwin

package history

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// A second reader of the four additions, written from the files and not from the walk: it reads
// each record.json of the bundle with encoding/json and the digest with crypto/sha256, and says what
// Inspection.Unfinished, State.Chain, State.Unlisted and State.NewestListed must be. It is for every
// bundle that a test builds, and for the fuzz targets.

// addPlain says that the walk looks at a name: it passes the rule for names and is no leftover
// temporary name.
func addPlain(name string) bool { return fsx.CheckName(name) == nil && !hasTempPrefix(name) }

// addRecord is what the model reads of one record.json.
type addRecord struct {
	folder, digest, prev, command, outcome string
	closes                                 string
	artifacts                              []string
	ok                                     bool
}

// addRecords reads the record.json file of each ceremony folder of the bundle.
func addRecords(m *mnode) (recs []addRecord, attempts, folders []string) {
	h := m.get("history")
	if h == nil || h.kind != "dir" {
		return nil, nil, nil
	}
	for name, f := range h.kids {
		if f.kind != "dir" || !addPlain(name) {
			continue
		}
		folders = append(folders, name)
		_, hasAttempt := f.kids["attempt.json"]
		rec, hasRecord := f.kids["record.json"]
		if hasAttempt && !hasRecord {
			attempts = append(attempts, name)
		}
		if !hasRecord || rec.kind != "file" {
			continue
		}
		sum := sha256.Sum256(rec.data)
		r := addRecord{folder: name, digest: hex.EncodeToString(sum[:])}
		var v struct {
			Command   string `json:"command"`
			Outcome   string `json:"outcome"`
			Prev      string `json:"prev_record_sha256"`
			Closes    *struct{ Ceremony string }
			Artifacts []struct{ Path string }
		}
		if err := json.Unmarshal(rec.data, &v); err == nil {
			r.ok = true
			r.command, r.outcome, r.prev = v.Command, v.Outcome, v.Prev
			if v.Closes != nil && v.Command == "close" {
				r.closes = v.Closes.Ceremony
			}
			for _, a := range v.Artifacts {
				r.artifacts = append(r.artifacts, a.Path)
			}
		}
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].folder < recs[j].folder })
	slices.Sort(attempts)
	slices.Sort(folders)
	return recs, attempts, folders
}

// addNumber is the number that the digits before the first hyphen of a set name give.
func addNumber(name string) (int64, bool) {
	digits, _, found := strings.Cut(name, "-")
	n, err := strconv.ParseInt(digits, 10, 64)
	if !found || err != nil || n < 0 || strconv.FormatInt(n, 10) != digits || len(digits) > 15 {
		return 0, false
	}
	return n, true
}

// checkAdditions holds an Inspection of the bundle m to what the files say.
func checkAdditions(t testing.TB, m *mnode, in *Inspection) {
	t.Helper()
	recs, attempts, _ := addRecords(m)
	closed := map[string]bool{}
	for _, r := range recs {
		if r.closes != "" {
			closed[r.closes] = true
		}
	}
	var open []string
	for _, a := range attempts {
		if !closed[a] {
			open = append(open, a)
		}
	}
	if !slices.IsSorted(in.Unfinished) {
		t.Fatalf("Inspection.Unfinished %v is not in the order of the names", in.Unfinished)
	}
	for i, u := range in.Unfinished {
		if i > 0 && in.Unfinished[i-1] == u {
			t.Fatalf("Inspection.Unfinished names %s twice", u)
		}
		if !slices.Contains(attempts, u) {
			t.Fatalf("Inspection.Unfinished names %s, which has no attempt.json or has a record.json", u)
		}
	}
	// A closing record that the walk could not read closes nothing, so the walk can show more than
	// the model; it never shows less. With a clean report every record was read, and the two agree.
	for _, o := range open {
		if !slices.Contains(in.Unfinished, o) {
			t.Fatalf("the ceremony %s holds an attempt, no record and no closing record names it, and Inspection.Unfinished %v leaves it out", o, in.Unfinished)
		}
	}
	if in.Report.Clean() && !slices.Equal(in.Unfinished, open) && (len(open) != 0 || len(in.Unfinished) != 0) {
		t.Fatalf("a clean report: Unfinished %v, the files say %v", in.Unfinished, open)
	}
	if in.State == nil {
		return
	}
	st := in.State
	if !slices.Equal(st.Unfinished, in.Unfinished) && (len(st.Unfinished) != 0 || len(in.Unfinished) != 0) {
		t.Fatalf("State.Unfinished %v differs from Inspection.Unfinished %v", st.Unfinished, in.Unfinished)
	}
	// Chain: every record once, one line, each naming the one before it.
	if len(st.Chain) != st.Records || len(st.Chain) != len(recs) {
		t.Fatalf("Chain has %d entries, Records %d, the files hold %d records", len(st.Chain), st.Records, len(recs))
	}
	byFolder := map[string]addRecord{}
	for _, r := range recs {
		byFolder[r.folder] = r
	}
	for i, c := range st.Chain {
		r, ok := byFolder[c.Folder]
		if !ok {
			t.Fatalf("Chain[%d] names the folder %q, which holds no record", i, c.Folder)
		}
		delete(byFolder, c.Folder)
		if c.SHA256 != r.digest {
			t.Fatalf("Chain[%d].SHA256 = %s, the file has %s", i, c.SHA256, r.digest)
		}
		if c.Command != r.command || c.Outcome != r.outcome {
			t.Fatalf("Chain[%d] has %q %q, the file has %q %q", i, c.Command, c.Outcome, r.command, r.outcome)
		}
		wantPrev := ""
		if i > 0 {
			wantPrev = st.Chain[i-1].SHA256
		}
		if r.prev != wantPrev {
			t.Fatalf("Chain[%d] (%s) names %q before it, the chain has %q", i, c.Folder, r.prev, wantPrev)
		}
	}
	if n := len(st.Chain); n > 0 && st.Chain[n-1].SHA256 != st.End {
		t.Fatalf("the last of Chain is %s, End is %s", st.Chain[n-1].SHA256, st.End)
	}
	if len(st.Chain) == 0 && st.End != "" {
		t.Fatalf("End %q with an empty chain", st.End)
	}
	// Unlisted and NewestListed from the artifacts of the records.
	listed := map[string]bool{}
	for _, r := range recs {
		for _, p := range r.artifacts {
			if rest, ok := strings.CutPrefix(p, "trust/"); ok {
				if name, _, found := strings.Cut(rest, "/"); found {
					listed[name] = true
				}
			}
		}
	}
	var unlisted []string
	if tr := m.get("trust"); tr != nil && tr.kind == "dir" {
		for name, s := range tr.kids {
			if s.kind == "dir" && addPlain(name) && !listed[name] {
				unlisted = append(unlisted, name)
			}
		}
	}
	slices.Sort(unlisted)
	if got := unlistedNames(st); !slices.Equal(got, unlisted) && (len(got) != 0 || len(unlisted) != 0) {
		t.Fatalf("Unlisted %v, the files say %v", got, unlisted)
	}
	inLists := map[string]bool{}
	for _, l := range st.Lists {
		inLists[l.Name] = true
	}
	for _, s := range st.Unlisted {
		n, ok := addNumber(s.Name)
		if !ok || n != s.Number {
			t.Fatalf("Unlisted %s has the number %d, the digits say %d (%v)", s.Name, s.Number, n, ok)
		}
		file := m.get("trust/" + s.Name + "/root-list.json")
		switch {
		case file == nil || file.kind != "file":
			if s.ListJSON != nil || inLists[s.Name] {
				t.Fatalf("Unlisted %s has no root list file, and has bytes %q or a place in Lists", s.Name, s.ListJSON)
			}
		case s.ListJSON != nil:
			if !bytes.Equal(s.ListJSON, file.data) {
				t.Fatalf("Unlisted %s: ListJSON is not the file", s.Name)
			}
			if !inLists[s.Name] {
				t.Fatalf("Unlisted %s has a root list and is not in Lists", s.Name)
			}
		}
	}
	var newest *string
	for i := len(st.Lists) - 1; i >= 0; i-- {
		if listed[st.Lists[i].Name] {
			newest = &st.Lists[i].Name
			break
		}
	}
	switch {
	case newest == nil && st.NewestListed != nil:
		t.Fatalf("NewestListed %s, and no list of the State is listed by a record", st.NewestListed.Name)
	case newest != nil && st.NewestListed == nil:
		t.Fatalf("NewestListed is nil, and %s is listed by a record", *newest)
	case newest != nil:
		nl := st.NewestListed
		if nl.Name != *newest {
			t.Fatalf("NewestListed %s, the last listed list is %s", nl.Name, *newest)
		}
		if n, ok := addNumber(nl.Name); !ok || n != nl.Number {
			t.Fatalf("NewestListed %s has the number %d, the digits say %d (%v)", nl.Name, nl.Number, n, ok)
		}
		if file := m.get("trust/" + nl.Name + "/root-list.json"); file == nil || !bytes.Equal(file.data, nl.ListJSON) {
			t.Fatalf("NewestListed %s: ListJSON is not the file", nl.Name)
		}
		if slices.Contains(unlisted, nl.Name) {
			t.Fatalf("NewestListed %s is a set that no record lists", nl.Name)
		}
	}
	// What stands after the newest listed list is unlisted.
	after := false
	for _, l := range st.Lists {
		if after && listed[l.Name] {
			t.Fatalf("%s is listed by a record and stands after NewestListed", l.Name)
		}
		if newest != nil && l.Name == *newest {
			after = true
		}
	}
	if st.Newest != nil && st.NewestListed != nil && st.Newest.Name != st.NewestListed.Name && !slices.Contains(unlisted, st.Newest.Name) {
		t.Fatalf("Newest %s is not NewestListed %s and is no unlisted set", st.Newest.Name, st.NewestListed.Name)
	}
}

// loadForModel reads a bundle from disk into memory with every kind of entry that the walk meets: a
// link and any other entry that is no file or folder are nodes of their own kind. Only the files
// that the model reads are read (record.json, root-list.json, and files up to 1 MiB), so a sparse
// file of any size costs nothing.
func loadForModel(t testing.TB, dir string) *mnode {
	t.Helper()
	root := newMem()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			root.put(rel, &mnode{kind: "link"})
		case d.IsDir():
			root.put(rel, &mnode{kind: "dir", kids: map[string]*mnode{}})
		case d.Type().IsRegular():
			n := &mnode{kind: "file"}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if base := d.Name(); base == "record.json" || base == "root-list.json" || info.Size() <= 1<<20 {
				if n.data, err = os.ReadFile(p); err != nil {
					return err
				}
			}
			root.put(rel, n)
		default:
			root.put(rel, &mnode{kind: "fifo"})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}
