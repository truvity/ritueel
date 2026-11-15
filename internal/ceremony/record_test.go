package ceremony_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// transcribed makes a flow that stands before Record, with its artifacts written.
func transcribed(t *testing.T, edit func(*spec)) *flow {
	t.Helper()
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	if edit != nil {
		edit(s)
	}
	fl := newFlow(t, b, s)
	fl.must("artifacts")
	return fl
}

func noRecord(t *testing.T, fl *flow) {
	t.Helper()
	if _, err := os.Lstat(fl.b.path("history", fl.s.name, "record.json")); !os.IsNotExist(err) {
		t.Errorf("record.json exists: %v", err)
	}
}

// Record reads the files back: a transcript that was changed between its write and the record has
// the digest of the new bytes in the record, because the record says what is on the disk.
func TestRecordTakesTheDigestOfWhatIsOnTheDisk(t *testing.T) {
	fl := transcribed(t, nil)
	changed := []byte("another text, line one\nline two\n")
	if err := os.WriteFile(fl.b.path("history", name1, "transcript.txt"), changed, 0o644); err != nil {
		t.Fatal(err)
	}
	fl.must("record")
	r, err := files.ReadRecord(fl.out)
	if err != nil {
		t.Fatal(err)
	}
	if r.TranscriptSHA256 != sum(changed) {
		t.Errorf("transcript_sha256 = %s, want the digest of the bytes on the disk %s", r.TranscriptSHA256, sum(changed))
	}
	if rep := fl.b.check(); !rep.Clean() {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// An artifact is read as it is on the disk when Record runs, and its digest is of those bytes.
func TestRecordTakesTheDigestOfAnArtifactOnTheDisk(t *testing.T) {
	fl := transcribed(t, nil)
	text := []byte("changed after it was written")
	if err := os.WriteFile(fl.b.path("roots", "A", "root.json"), text, 0o644); err != nil {
		t.Fatal(err)
	}
	fl.must("record")
	r, _ := files.ReadRecord(fl.out)
	for _, a := range r.Artifacts {
		if a.Path == "roots/A/root.json" && a.SHA256 != sum(text) {
			t.Errorf("the digest of roots/A/root.json is %s, want %s", a.SHA256, sum(text))
		}
	}
}

// What the attempt and the plan name, the copies and the transcript must still be when Record runs.
func TestRecordRefusesFilesThatChangedSinceTheAttempt(t *testing.T) {
	d := []string{"history", name1}
	cases := map[string]func(t *testing.T, fl *flow){
		"plan.json changed": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "plan.json")...), "{}")
		},
		"plan.json with one byte changed": func(t *testing.T, fl *flow) {
			p := fl.b.path(append(d, "plan.json")...)
			data := fl.b.read(append(d, "plan.json")...)
			data[len(data)-2] ^= 1
			mustWrite(t, p, string(data))
		},
		"plan.json removed": func(t *testing.T, fl *flow) {
			if err := os.Remove(fl.b.path(append(d, "plan.json")...)); err != nil {
				t.Fatal(err)
			}
		},
		"attempt.json changed": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "attempt.json")...), `{"ceremony":"`+name1+`","plan_sha256":"`+rep('1')+`","version":1}`)
		},
		"attempt.json of another ceremony": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "attempt.json")...), `{"ceremony":"`+name2+`","plan_sha256":"`+sum(fl.s.plan(t))+`","version":1}`)
		},
		"attempt.json that is not canonical": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "attempt.json")...), `{"version": 1, "ceremony":"`+name1+`","plan_sha256":"`+sum(fl.s.plan(t))+`"}`)
		},
		"attempt.json that is not an attempt": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "attempt.json")...), "[]")
		},
		"a copy changed": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "wanted", "ritueel.yaml")...), "version: 2\n")
		},
		"a copy removed": func(t *testing.T, fl *flow) {
			if err := os.Remove(fl.b.path(append(d, "wanted", "want", "roots", "x509.yaml")...)); err != nil {
				t.Fatal(err)
			}
		},
		"the transcript removed": func(t *testing.T, fl *flow) {
			if err := os.Remove(fl.b.path(append(d, "transcript.txt")...)); err != nil {
				t.Fatal(err)
			}
		},
		"the transcript with an escape character": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "transcript.txt")...), "line\x1b[2J\n")
		},
		"the transcript with a carriage return": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "transcript.txt")...), "line\r\n")
		},
		"the transcript with no line feed at its end": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "transcript.txt")...), "line")
		},
		"the transcript that is empty": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "transcript.txt")...), "")
		},
		"the transcript that is not UTF-8": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "transcript.txt")...), "a\xff\n")
		},
		"the transcript over 1 MiB": func(t *testing.T, fl *flow) {
			mustWrite(t, fl.b.path(append(d, "transcript.txt")...), strings.Repeat(strings.Repeat("a", 1000)+"\n", 1100))
		},
		"a journal removed": func(t *testing.T, fl *flow) {
			if err := os.Remove(fl.b.path(append(d, "births.jsonl")...)); err != nil {
				t.Fatal(err)
			}
		},
		"plan.json that is a link": func(t *testing.T, fl *flow) {
			p := fl.b.path(append(d, "plan.json")...)
			orig := fl.b.read(append(d, "plan.json")...)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, fl.b.path("plan-elsewhere.json"), string(orig))
			mustLink(t, fl.b.path("plan-elsewhere.json"), p)
		},
		"a copy that is a folder": func(t *testing.T, fl *flow) {
			p := fl.b.path(append(d, "wanted", "ritueel.yaml")...)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, p)
		},
		"the transcript that is a pipe": func(t *testing.T, fl *flow) {
			p := fl.b.path(append(d, "transcript.txt")...)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	// The reason that these refusals give: the file is compared with what the folder holds and
	// not only judged by the readers that come after.
	reasons := map[string]string{
		"plan.json with one byte changed": "not the plan of the folder",
		"plan.json changed":               "not the plan of the folder",
		"a copy changed":                  "digest that the plan lists",
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			mutate(t, fl)
			before := tree(t, fl.b.dir)
			mark := fl.b.r.mark()
			out, err := fl.f.Record(fl.recordIn())
			if err == nil {
				t.Fatalf("a record was written: %s", out)
			}
			if want := reasons[name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Errorf("the reason is %q, want one that holds %q", err, want)
			}
			if out != nil {
				t.Error("Record returned bytes with its error")
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("a refusal stopped the folder")
			}
			if got := fl.b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused record reached the file system: %v", got)
			}
			sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
			noRecord(t, fl)
		})
	}
}

// recordIn is the input that the flow gives to Record.
func (fl *flow) recordIn() ceremony.RecordIn {
	s := fl.s
	return ceremony.RecordIn{
		Command: files.CommandApply, Outcome: files.OutcomeCompleted, PrevRecordSHA256: s.last,
		StartedAt: ts, FinishedAt: "2026-11-14T10:05:00Z",
		Artifacts: s.artifactPaths(),
	}
}

// Each refusal of the input is of kind ErrInvalidInput, writes nothing, and leaves the folder in
// the state in which the right call still works.
func TestRecordRefusesABadInput(t *testing.T) {
	cases := []struct {
		name string
		edit func(in *ceremony.RecordIn)
	}{
		{"a zero input", func(in *ceremony.RecordIn) { *in = ceremony.RecordIn{} }},
		{"no command", func(in *ceremony.RecordIn) { in.Command = "" }},
		{"the command close", func(in *ceremony.RecordIn) { in.Command = files.CommandClose }},
		{"an unknown command", func(in *ceremony.RecordIn) { in.Command = "revoke" }},
		{"no outcome", func(in *ceremony.RecordIn) { in.Outcome = "" }},
		{"the outcome declined", func(in *ceremony.RecordIn) { in.Outcome = files.OutcomeDeclined }},
		{"the outcome closed", func(in *ceremony.RecordIn) { in.Outcome = files.OutcomeClosed }},
		{"a previous record that is not a digest", func(in *ceremony.RecordIn) { in.PrevRecordSHA256 = "abc" }},
		{"a previous record in capitals", func(in *ceremony.RecordIn) { in.PrevRecordSHA256 = strings.ToUpper(rep('a')) }},
		{"a previous record that the plan does not name", func(in *ceremony.RecordIn) { in.PrevRecordSHA256 = rep('a') }},
		{"a start time with a fraction", func(in *ceremony.RecordIn) { in.StartedAt = "2026-11-14T10:00:00.5Z" }},
		{"a finish time with an offset", func(in *ceremony.RecordIn) { in.FinishedAt = "2026-11-14T10:00:00+01:00" }},
		{"a start time that is not a time", func(in *ceremony.RecordIn) { in.StartedAt = "yesterday" }},
		{"a place that is not one of the two words", func(in *ceremony.RecordIn) { in.RanOn = "laptop" }},
		{"a place in capitals", func(in *ceremony.RecordIn) { in.RanOn = "Workstation" }},
		{"a confirmation by a stranger", func(in *ceremony.RecordIn) { in.Confirmation = &files.Confirmation{By: "someone"} }},
		{"a confirmation at a bad time", func(in *ceremony.RecordIn) { in.Confirmation = &files.Confirmation{By: "typed", At: "now"} }},
		{"an artifact over the limit", func(in *ceremony.RecordIn) {
			in.Artifacts = make([]string, 1001)
			for i := range in.Artifacts {
				in.Artifacts[i] = fmt.Sprintf("roots/r%d.json", i)
			}
		}},
		{"an artifact path that is empty", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "") }},
		{"an absolute artifact path", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "/etc/passwd") }},
		{"an artifact path with ..", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "roots/../../x") }},
		{"an artifact path outside the bundle", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "../keys/A.x509.key.pem") }},
		{"an artifact path with a backslash", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, `roots\A\root.json`) }},
		{"an artifact path with an escape character", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "roots/\x1b[2J") }},
		{"an artifact path of 13 elements", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, pathOf(13)) }},
		{"an artifact path that is a temporary name", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "roots/.rt-abcdefghij") }},
		{"an artifact under history/", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "history/"+name1+"/plan.json") }},
		{"an artifact under History/", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "History/x") }},
		{"the plan of another ceremony as an artifact", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, "history/"+name2+"/plan.json") }},
		{"an artifact twice", func(in *ceremony.RecordIn) { in.Artifacts = append(in.Artifacts, in.Artifacts[0]) }},
	}
	// The reason that each refusal gives: the input is judged by this check, and not only by the
	// reader of the record that comes after it.
	reasons := map[string]string{
		"a zero input": "completed apply only", "no command": "completed apply only", "the command close": "completed apply only",
		"an unknown command": "completed apply only", "no outcome": "completed apply only",
		"the outcome declined": "completed apply only", "the outcome closed": "completed apply only",
		"a previous record that is not a digest": "prev_record_sha256", "a previous record in capitals": "prev_record_sha256",
		"a previous record that the plan does not name": "another record",
		"a start time with a fraction":                  "started_at is not a time", "a finish time with an offset": "finished_at is not a time", "a start time that is not a time": "started_at is not a time",
		"a place that is not one of the two words": "ran_on", "a place in capitals": "ran_on",
		"an artifact over the limit": "1001 artifacts", "an artifact path that is empty": "artifact path",
		"an absolute artifact path": "artifact path", "an artifact under history/": "history/",
		"an artifact twice": "twice",
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, nil)
			in := fl.recordIn()
			c.edit(&in)
			before := tree(t, fl.b.dir)
			mark := fl.b.r.mark()
			out, err := fl.f.Record(in)
			if out != nil {
				t.Error("Record returned bytes with its error")
			}
			wantKind(t, err, ceremony.ErrInvalidInput)
			if want := reasons[c.name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Errorf("the reason is %q, want one that holds %q", err, want)
			}
			if got := fl.b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused input reached the file system: %v", got)
			}
			sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
			noRecord(t, fl)
			// Nothing is stopped: the right input is recorded.
			if _, err := fl.f.Record(fl.recordIn()); err != nil {
				t.Errorf("the record after a refused input: %v", err)
			}
		})
	}
}

// A first ceremony has no record before it, and a later one names exactly the end that its plan
// named.
func TestRecordChainsOnTheEndThatThePlanNamed(t *testing.T) {
	t.Run("a first ceremony that names a record before it", func(t *testing.T) {
		fl := transcribed(t, nil)
		in := fl.recordIn()
		in.PrevRecordSHA256 = rep('a')
		_, err := fl.f.Record(in)
		wantKind(t, err, ceremony.ErrInvalidInput)
	})
	t.Run("a second ceremony that names none", func(t *testing.T) {
		fl := transcribed(t, func(s *spec) { s.last = rep('c') })
		in := fl.recordIn()
		in.PrevRecordSHA256 = ""
		_, err := fl.f.Record(in)
		wantKind(t, err, ceremony.ErrInvalidInput)
	})
	t.Run("a second ceremony that names another end", func(t *testing.T) {
		fl := transcribed(t, func(s *spec) { s.last = rep('c') })
		in := fl.recordIn()
		in.PrevRecordSHA256 = rep('d')
		_, err := fl.f.Record(in)
		wantKind(t, err, ceremony.ErrInvalidInput)
	})
	t.Run("a second ceremony that names the end", func(t *testing.T) {
		fl := transcribed(t, func(s *spec) { s.last = rep('c') })
		in := fl.recordIn()
		in.PrevRecordSHA256 = rep('c')
		out, err := fl.f.Record(in)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := files.ReadRecord(out)
		if r.PrevRecordSHA256 != rep('c') {
			t.Errorf("prev_record_sha256 = %q", r.PrevRecordSHA256)
		}
	})
}

// A plan that answers requests is not recorded by this version.
func TestRecordRefusesAPlanThatAnswersRequests(t *testing.T) {
	fl := transcribed(t, func(s *spec) {
		s.edit = func(m map[string]any) {
			m["requests"] = []any{map[string]any{"stem": "a", "type": "x509", "request_sha256": rep('1'), "proof_sha256": rep('2'), "store": "software", "key": rep('3')}}
		}
	})
	_, err := fl.f.Record(fl.recordIn())
	wantKind(t, err, ceremony.ErrInvalidInput)
	noRecord(t, fl)
}

// An artifact that is not there, is not a file, or is too long: an error and no record.json, and
// the folder goes on once the file is put right.
func TestRecordRefusesAnArtifactThatIsNotAFile(t *testing.T) {
	cases := map[string]func(t *testing.T, fl *flow, p string){
		"missing": func(t *testing.T, fl *flow, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, fl *flow, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, p)
		},
		"a link": func(t *testing.T, fl *flow, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, fl.b.path("elsewhere.json"), "{}")
			mustLink(t, fl.b.path("elsewhere.json"), p)
		},
		"a dangling link": func(t *testing.T, fl *flow, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustLink(t, "nowhere", p)
		},
		"a pipe": func(t *testing.T, fl *flow, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"longer than 8 MiB": func(t *testing.T, fl *flow, p string) {
			if err := os.Truncate(p, fsx.MaxReadSize+1); err != nil {
				t.Fatal(err)
			}
		},
		"a folder above it that is a link": func(t *testing.T, fl *flow, p string) {
			dir := filepath.Dir(p)
			moved := dir + "-moved"
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			mustLink(t, moved, dir)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			p := fl.b.path("roots", "A", "root.json")
			mutate(t, fl, p)
			before := tree(t, fl.b.dir)
			out, err := fl.f.Record(fl.recordIn())
			if err == nil || out != nil {
				t.Fatalf("Record = %q, %v", out, err)
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("a refusal stopped the folder")
			}
			sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
			noRecord(t, fl)
		})
	}
	// A file of exactly 8 MiB is read and listed.
	t.Run("exactly 8 MiB", func(t *testing.T) {
		fl := transcribed(t, nil)
		if err := os.Truncate(fl.b.path("roots", "A", "root.json"), fsx.MaxReadSize); err != nil {
			t.Fatal(err)
		}
		if _, err := fl.f.Record(fl.recordIn()); err != nil {
			t.Fatalf("an artifact of 8 MiB: %v", err)
		}
	})
}

// The artifacts are listed in path order, whatever order the caller gave them.
func TestRecordListsArtifactsInPathOrder(t *testing.T) {
	fl := transcribed(t, nil)
	for _, p := range []string{"zzz/last.json", "aaa/first.json", "roots/B/root.json", "Mixed/case.json"} {
		mustWrite(t, fl.b.path(filepath.FromSlash(p)), "x "+p)
	}
	in := fl.recordIn()
	in.Artifacts = []string{"zzz/last.json", "trust/1-00000001/root-list.json", "roots/B/root.json", "aaa/first.json", "roots/A/root.json", "Mixed/case.json"}
	given := append([]string(nil), in.Artifacts...)
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(in.Artifacts, "|") != strings.Join(given, "|") {
		t.Error("Record changed the list of the caller")
	}
	r, _ := files.ReadRecord(out)
	var got []string
	for _, a := range r.Artifacts {
		got = append(got, a.Path)
		if a.SHA256 != sum(fl.b.read(filepath.FromSlash(a.Path))) {
			t.Errorf("the digest of %s is not the digest of the file", a.Path)
		}
	}
	want := []string{"Mixed/case.json", "aaa/first.json", "roots/A/root.json", "roots/B/root.json", "trust/1-00000001/root-list.json", "zzz/last.json"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("artifacts in the order %v, want %v", got, want)
	}
}

// A ceremony with no artifact lists an empty list, which the record always has.
func TestRecordWithNoArtifactsHasTheMemberAsAnEmptyList(t *testing.T) {
	fl := transcribed(t, nil)
	in := fl.recordIn()
	in.Artifacts = nil
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"artifacts":[]`)) {
		t.Errorf("the record has no empty list of artifacts: %s", out)
	}
	if _, err := files.ReadRecord(out); err != nil {
		t.Error(err)
	}
}

// The members that the caller does not give are left out, never written as empty.
func TestRecordLeavesOutWhatTheCallerDidNotGive(t *testing.T) {
	fl := transcribed(t, nil)
	in := fl.recordIn()
	in.StartedAt, in.FinishedAt = "", ""
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatal(err)
	}
	r, err := files.ReadRecord(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"started_at", "finished_at", "root\"", "confirmation", "ran_on", "limit_shown", "advisory_review", "declined", "closes", "revocations", "requests", "slot_map_version", "warnings", "backend"} {
		if bytes.Contains(out, []byte(`"`+strings.TrimSuffix(name, `"`)+`"`)) && name != "root\"" {
			t.Errorf("the record holds the member %s that nobody gave", name)
		}
	}
	if r.Root != nil || r.Confirmation != nil || r.RanOn != "" || r.LimitShown {
		t.Errorf("members the caller did not give: %+v", r)
	}
	if strings.Contains(string(out), `"root":`) {
		t.Error("the record holds root that nobody gave")
	}
}

// The files of a record that are too many bytes in all are refused before the record is built.
func TestRecordRefusesMoreThan256MiBOfFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("reads 256 MiB of zeros")
	}
	build := func(n int) *flow {
		fl := transcribed(t, nil)
		in := make([]string, 0, n+2)
		in = append(in, fl.s.artifactPaths()...)
		for i := 0; i < n; i++ {
			p := fmt.Sprintf("big/f%02d.bin", i)
			full := fl.b.path(filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := os.Create(full)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(fsx.MaxReadSize); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			in = append(in, p)
		}
		fl.in = func(ri *ceremony.RecordIn) { ri.Artifacts = in }
		return fl
	}
	ok := build(30)
	if err := ok.run(""); err != nil {
		t.Fatalf("30 files of 8 MiB (240 MiB): %v", err)
	}
	over := build(32)
	err := over.run("")
	if err == nil {
		t.Fatal("32 files of 8 MiB (256 MiB and the others) were recorded")
	}
	wantKind(t, errors.Unwrap(err), ceremony.ErrInvalidInput)
	noRecord(t, over)
}

// RecordIn.Root and Confirmation are written as the caller gave them.
func TestRecordCopiesTheRootAndTheConfirmation(t *testing.T) {
	fl := transcribed(t, nil)
	in := fl.recordIn()
	in.Root = &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), Test: true}
	in.Confirmation = &files.Confirmation{By: "typed", At: ts}
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := files.ReadRecord(out)
	if r.Root == nil || r.Root.X509 != rep('a') || r.Confirmation == nil || r.Confirmation.By != "typed" {
		t.Errorf("root and confirmation: %+v %+v", r.Root, r.Confirmation)
	}
}

// The plan's own signatures, one for each line of the journal, in the order of n, of the same
// kind, and with the same key when the plan names one.
func TestRecordJoinsThePlanAndTheJournalOfSignatures(t *testing.T) {
	cases := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"a plan signature with another n", func(m map[string]any) { m["signatures"].([]any)[1].(map[string]any)["n"] = 5 }},
		{"a plan signature with no n", func(m map[string]any) { delete(m["signatures"].([]any)[0].(map[string]any), "n") }},
		{"a plan signature of another kind", func(m map[string]any) { m["signatures"].([]any)[0].(map[string]any)["kind"] = "root-list" }},
		{"a plan signature that names another key", func(m map[string]any) { m["signatures"].([]any)[2].(map[string]any)["key"] = rep('9') }},
		{"a plan signature that is not an object", func(m map[string]any) { m["signatures"].([]any)[1] = "x" }},
		{"a plan with a signature too many", func(m map[string]any) {
			m["signatures"] = append(m["signatures"].([]any), map[string]any{"n": 4, "kind": "root-list"})
		}},
		{"a plan with a signature too few", func(m map[string]any) { m["signatures"] = m["signatures"].([]any)[:2] }},
		{"a plan with no signatures", func(m map[string]any) { delete(m, "signatures") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, func(s *spec) { s.edit = c.edit })
			_, err := fl.f.Record(fl.recordIn())
			if err == nil {
				t.Fatal("a record was written for a plan that its journal does not follow")
			}
			wantKind(t, err, ceremony.ErrDiskMismatch)
			noRecord(t, fl)
		})
	}
}

// With the key named by the plan the journal's key fills nothing and must agree; a derived
// signature takes its key from the journal.
func TestRecordTakesTheKeyOfADerivedSignatureFromTheJournal(t *testing.T) {
	fl := transcribed(t, nil)
	out, err := fl.f.Record(fl.recordIn())
	if err != nil {
		t.Fatal(err)
	}
	r, _ := files.ReadRecord(out)
	for i, raw := range r.Signatures {
		m := raw.(map[string]any)
		if m["key"] != fl.s.pin {
			t.Errorf("signature %d has the key %v, want %s", i+1, m["key"], fl.s.pin)
		}
	}
}

// The folder that Record could not finish stays "transcribed": after the artifact is made, the
// same Record works.
func TestRecordAfterAMissingArtifactWorksOnceItIsThere(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("transcript")
	if _, err := fl.f.Record(fl.recordIn()); err == nil {
		t.Fatal("a record for artifacts that are not there")
	}
	noRecord(t, fl)
	fl.must("")
	if rep := b.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
}

func TestWriteTranscriptRefusesATextThatBreaksTheRules(t *testing.T) {
	long := strings.Repeat("a", 1025) + "\n"
	cases := map[string][]byte{
		"nothing":           nil,
		"an empty text":     {},
		"no line feed":      []byte("line"),
		"a carriage return": []byte("line\r\n"),
		"a tab":             []byte("a\tb\n"),
		"an escape":         []byte("\x1b[31mred\x1b[0m\n"),
		"a null":            []byte("a\x00b\n"),
		"a delete":          []byte("a\x7fb\n"),
		"a control of the range U+0080 to U+009F": []byte("a\u0085b\n"),
		"a right-to-left mark":                    []byte("a\u202eb\n"),
		"a zero-width space":                      []byte("a\u200bb\n"),
		"a byte order mark":                       []byte("\ufeffline\n"),
		"a line separator":                        []byte("a\u2028b\n"),
		"a paragraph separator":                   []byte("a\u2029b\n"),
		"not UTF-8":                               []byte("a\xffb\n"),
		"a line over 1,024 bytes":                 []byte(long),
		"4,097 lines":                             []byte(strings.Repeat("a\n", 4097)),
		"over 1 MiB":                              []byte(strings.Repeat(strings.Repeat("a", 1023)+"\n", 1025)),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			fl := newFlow(t, b, newSpec(name1, 1, ""))
			fl.must("end")
			before := tree(t, b.dir)
			mark := b.r.mark()
			keep := append([]byte(nil), text...)
			err := fl.f.WriteTranscript(text)
			wantKind(t, err, ceremony.ErrInvalidInput)
			if len(text) == 0 && !strings.Contains(err.Error(), "prints at least") {
				t.Errorf("an empty text is refused for another reason: %v", err)
			}
			if !bytes.Equal(keep, text) {
				t.Error("WriteTranscript changed the caller's bytes")
			}
			if got := b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused transcript reached the file system: %v", got)
			}
			sameTree(t, "WriteTranscript", before, tree(t, b.dir))
			// Not stopped: a good text is written next.
			if err := fl.f.WriteTranscript([]byte("a good line\n")); err != nil {
				t.Errorf("the transcript after a refused one: %v", err)
			}
		})
	}
}

func TestWriteTranscriptWritesTheBytesAsTheyAre(t *testing.T) {
	text := []byte("line one\nline two with caf\\u00e9\n" + strings.Repeat("b", 1024) + "\n")
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("end")
	if err := fl.f.WriteTranscript(text); err != nil {
		t.Fatal(err)
	}
	if got := b.read("history", name1, "transcript.txt"); !bytes.Equal(got, text) {
		t.Errorf("transcript.txt is %q", got)
	}
	// The text is copied: a change of the caller's bytes later does not matter to the record.
	for i := range text {
		text[i] = 'z'
	}
	fl.skipTo("artifacts")
	fl.must("")
	r, _ := files.ReadRecord(fl.out)
	if r.TranscriptSHA256 != sum(b.read("history", name1, "transcript.txt")) {
		t.Error("the transcript digest is not that of the file")
	}
}

// 4,096 lines of 1,024 bytes are the most a transcript may be; 1 MiB is the most in bytes.
func TestWriteTranscriptTakesTheLimitsExactly(t *testing.T) {
	cases := map[string]string{
		"4,096 lines":                   strings.Repeat("a\n", 4096),
		"a line of exactly 1,024 bytes": strings.Repeat("a", 1024) + "\n",
		"exactly 1 MiB":                 strings.Repeat(strings.Repeat("a", 1023)+"\n", 1024),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			fl := newFlow(t, b, newSpec(name1, 1, ""))
			fl.must("end")
			if err := fl.f.WriteTranscript([]byte(text)); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		})
	}
}

// Two artifacts whose names differ only in case are one name on a stick that compares names
// without case (bundle page, "How a file is written"): the record refuses them, whether they sit
// next to each other in path order or not.
func TestRecordTakesExactly1000Artifacts(t *testing.T) {
	fl := transcribed(t, nil)
	in := fl.recordIn()
	for i := len(in.Artifacts); i < 1000; i++ {
		p := fmt.Sprintf("many/f%04d.json", i)
		mustWrite(t, fl.b.path(filepath.FromSlash(p)), p)
		in.Artifacts = append(in.Artifacts, p)
	}
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatalf("1,000 artifacts: %v", err)
	}
	r, _ := files.ReadRecord(out)
	if len(r.Artifacts) != 1000 {
		t.Errorf("%d artifacts", len(r.Artifacts))
	}
}

func TestRecordRefusesTwoArtifactsThatDifferOnlyInCase(t *testing.T) {
	cases := map[string][]string{
		"next to each other": {"roots/A/root.json", "ROOTS/A/ROOT.JSON"},
		"far apart":          {"Roots/A/root.json", "Sets/x.json", "roots/A/root.json"},
		"one in a folder":    {"x/Y.json", "Zeta.json", "x/y.json"},
	}
	for name, paths := range cases {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			for _, p := range paths {
				mustWrite(t, fl.b.path(filepath.FromSlash(p)), "x "+p)
			}
			in := fl.recordIn()
			in.Artifacts = paths
			_, err := fl.f.Record(in)
			wantKind(t, err, ceremony.ErrInvalidInput)
			noRecord(t, fl)
		})
	}
}

// The two fingerprints of the root in a record are the forms of the page's "Common rules": 64
// lower-case digits for an X.509 key, 40 for an OpenPGP key. The reader of a record does not judge
// them, so the writer is the only guard.
func TestRecordRefusesARootWhoseFingerprintIsNotOfTheFormOfThePage(t *testing.T) {
	good := func() *files.PlanRoot {
		return &files.PlanRoot{Label: "A", Store: "software", X509: rep('a'), OpenPGP: strings.Repeat("b", 40), Test: true}
	}
	cases := []struct {
		name string
		edit func(r *files.PlanRoot)
		ok   bool
	}{
		{"both fingerprints", func(r *files.PlanRoot) {}, true},
		{"only the X.509 key", func(r *files.PlanRoot) { r.OpenPGP = "" }, true},
		{"only the OpenPGP key", func(r *files.PlanRoot) { r.X509 = "" }, true},
		{"an X.509 fingerprint that is not hexadecimal", func(r *files.PlanRoot) { r.X509 = strings.Repeat("z", 64) }, false},
		{"an X.509 fingerprint of 63 digits", func(r *files.PlanRoot) { r.X509 = rep('a')[:63] }, false},
		{"an X.509 fingerprint in capitals", func(r *files.PlanRoot) { r.X509 = strings.ToUpper(rep('a')) }, false},
		{"an X.509 fingerprint of text with an escape", func(r *files.PlanRoot) { r.X509 = "\x1b[31m" }, false},
		{"an OpenPGP fingerprint of 64 digits", func(r *files.PlanRoot) { r.OpenPGP = rep('b') }, false},
		{"an OpenPGP fingerprint of 39 digits", func(r *files.PlanRoot) { r.OpenPGP = strings.Repeat("b", 39) }, false},
		{"an OpenPGP fingerprint in capitals", func(r *files.PlanRoot) { r.OpenPGP = strings.Repeat("B", 40) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, nil)
			in := fl.recordIn()
			in.Root = good()
			c.edit(in.Root)
			out, err := fl.f.Record(in)
			if c.ok {
				if err != nil {
					t.Fatalf("a good root is refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a record with a root that breaks the form of the page was written: %s", out)
			}
			wantKind(t, err, ceremony.ErrInvalidInput)
			noRecord(t, fl)
		})
	}
}

// A name that is judged by the case of letters is judged before any artifact is read: the paths
// of these lists do not exist on the disk, and the refusal is still the one of the case.
func TestRecordRefusesCaseClashesWhereverTheyStand(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{"two letters of two elements", []string{"a/B", "A/b"}, "case"},
		{"another path between them in byte order", []string{"x/Y.json", "x/Z.json", "X/Q.json", "x/y.json"}, "case"},
		{"the first and the last of a long list", []string{"Roots/A/root.json", "b/1", "c/2", "d/3", "e/4", "f/5", "g/6", "roots/A/root.json"}, "case"},
		{"in the order that the caller gave", []string{"roots/a.json", "other/z.json", "ROOTS/A.JSON"}, "case"},
		{"in the given order and reversed", []string{"ROOTS/A.JSON", "other/z.json", "roots/a.json"}, "case"},
		{"a name twice with others between", []string{"q", "m", "qQ", "q"}, "twice"},
		{"the very same path twice", []string{"roots/A/root.json", "other/z.json", "roots/A/root.json"}, "twice"},
		{"the pair that makes the 1,000th artifact", func() []string {
			p := make([]string, 0, 1000)
			for i := 0; i < 998; i++ {
				p = append(p, fmt.Sprintf("many/f%04d.json", i))
			}
			return append(p, "zz/Last.json", "zz/last.json")
		}(), "case"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, nil)
			in := fl.recordIn()
			in.Artifacts = c.paths
			before := tree(t, fl.b.dir)
			mark := fl.b.r.mark()
			out, err := fl.f.Record(in)
			if out != nil {
				t.Error("Record returned bytes with its error")
			}
			wantKind(t, err, ceremony.ErrInvalidInput)
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the reason is %q, want one that holds %q", err, c.want)
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("a refusal stopped the folder")
			}
			if got := fl.b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused record reached the file system: %v", got)
			}
			sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
			noRecord(t, fl)
			// The folder is not stopped: the right list is recorded.
			if _, err := fl.f.Record(fl.recordIn()); err != nil {
				t.Errorf("the record after a refused list: %v", err)
			}
		})
	}
	t.Run("a letter that is not ASCII and lowers to one", func(t *testing.T) {
		fl := transcribed(t, nil)
		in := fl.recordIn()
		in.Artifacts = []string{"roots/\u212a.json", "roots/k.json"}
		_, err := fl.f.Record(in)
		wantKind(t, err, ceremony.ErrInvalidInput)
	})
}

// Names that differ in more than the case of a letter are not a clash.
func TestRecordTakesNamesThatDifferInMoreThanCase(t *testing.T) {
	fl := transcribed(t, nil)
	in := fl.recordIn()
	for _, p := range []string{"ab", "a-b", "aB.json", "ab.txt", "a_b", "Ab2"} {
		mustWrite(t, fl.b.path(p), "x "+p)
		in.Artifacts = append(in.Artifacts, p)
	}
	out, err := fl.f.Record(in)
	if err != nil {
		t.Fatalf("names that differ in more than the case: %v", err)
	}
	r, _ := files.ReadRecord(out)
	if len(r.Artifacts) != len(in.Artifacts) {
		t.Errorf("%d artifacts listed of %d", len(r.Artifacts), len(in.Artifacts))
	}
}

// The artifacts stand in the byte order of the path text, not in the order of the elements of the
// path: a-b (0x2d) stands before a.b (0x2e) before a/b (0x2f) before a0b (0x30), and a capital
// letter stands before every small one. The order that the caller gave does not matter.
func TestRecordListsArtifactsInTheByteOrderOfThePathText(t *testing.T) {
	want := []string{"Z.json", "a-b", "a.b", "a/b", "a0b", "a_b", "roots/A/root.json", "trust/1-00000001/root-list.json"}
	for name, order := range map[string][]int{
		"as listed":    {0, 1, 2, 3, 4, 5, 6, 7},
		"reversed":     {7, 6, 5, 4, 3, 2, 1, 0},
		"interleaved":  {3, 6, 0, 5, 2, 7, 1, 4},
		"slash first":  {3, 2, 1, 0, 4, 5, 6, 7},
		"hyphen last":  {0, 3, 2, 4, 5, 6, 7, 1},
		"slash at end": {0, 1, 2, 4, 5, 6, 7, 3},
	} {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			for _, p := range []string{"Z.json", "a-b", "a.b", "a0b", "a_b"} {
				mustWrite(t, fl.b.path(p), "x "+p)
			}
			mustMkdir(t, fl.b.path("a"))
			mustWrite(t, fl.b.path("a", "b"), "x a/b")
			in := fl.recordIn()
			in.Artifacts = nil
			for _, i := range order {
				in.Artifacts = append(in.Artifacts, want[i])
			}
			out, err := fl.f.Record(in)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := files.ReadRecord(out)
			var got []string
			for _, a := range r.Artifacts {
				got = append(got, a.Path)
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("artifacts in the order\n%v\nwant\n%v", got, want)
			}
		})
	}
}

// A refusal names the fingerprint that breaks its form, and each character that is not a lower-case
// hexadecimal digit is refused at the first and at the last place of the text.
func TestRecordRefusesEachCharacterOfAFingerprintThatIsNotALowerCaseDigit(t *testing.T) {
	bad := []byte{'/', ':', '@', 'G', '`', 'g', 'A', 'F', ' ', 0, 0x7f, 0xff}
	good := []byte("0123456789abcdef")
	for _, kind := range []struct {
		name string
		n    int
		set  func(r *files.PlanRoot, s string)
	}{
		{"X.509", 64, func(r *files.PlanRoot, s string) { r.X509 = s }},
		{"OpenPGP", 40, func(r *files.PlanRoot, s string) { r.OpenPGP = s }},
	} {
		t.Run(kind.name, func(t *testing.T) {
			fl := transcribed(t, nil)
			try := func(s string) error {
				in := fl.recordIn()
				in.Root = &files.PlanRoot{Label: "A", Store: "software", Test: true}
				kind.set(in.Root, s)
				_, err := fl.f.Record(in)
				return err
			}
			base := strings.Repeat("5", kind.n)
			for _, c := range bad {
				for _, at := range []int{0, kind.n / 2, kind.n - 1} {
					s := []byte(base)
					s[at] = c
					err := try(string(s))
					wantKind(t, err, ceremony.ErrInvalidInput)
					if !strings.Contains(err.Error(), kind.name) || !strings.Contains(err.Error(), "fingerprint") {
						t.Errorf("char %#x at %d: the reason does not name the %s fingerprint: %v", c, at, kind.name, err)
					}
				}
			}
			noRecord(t, fl)
			// Each good digit is taken at the first and at the last place, in one record that is
			// written after the refusals above, which stopped nothing.
			s := make([]byte, kind.n)
			for i := range s {
				s[i] = good[i%len(good)]
			}
			if err := try(string(s)); err != nil {
				t.Errorf("a fingerprint of every digit: %v", err)
			}
		})
	}
}

// A root with no member is a root that names no key: the record is written with it.
func TestRecordTakesARootWithNoFingerprint(t *testing.T) {
	for name, root := range map[string]*files.PlanRoot{
		"a root with no member":     {},
		"a root with a label only":  {Label: "A"},
		"no root at all":            nil,
		"a root with both of them":  {Label: "A", X509: rep('1'), OpenPGP: strings.Repeat("2", 40)},
		"a root with the X.509 key": {X509: rep('0')},
	} {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			in := fl.recordIn()
			in.Root = root
			out, err := fl.f.Record(in)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if _, err := files.ReadRecord(out); err != nil {
				t.Errorf("the reader refuses the record: %v", err)
			}
			if rep := fl.b.check(); !rep.Clean() {
				t.Errorf("findings %+v", rep.Findings)
			}
		})
	}
}

// birthText is one line of the birth journal, with its line feed.
func birthText(t testing.TB, label, purpose, store, place string) string {
	t.Helper()
	b, err := (&files.BirthLine{At: ts, Label: label, Purpose: purpose, Store: store, Place: place, PublicKeySHA256: rep('a')}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// plannedBirth is a birth of the plan, with the four members that a line of the journal has.
func plannedBirth(label, purpose, store, place string) map[string]any {
	return map[string]any{"label": label, "purpose": purpose, "store": store, "place": place, "creation_time": ts}
}

// The journal of births is compared with the births of the plan: one line for each birth, in the
// order of the plan, with the label, purpose, store and place that the plan gives. Page, "The
// birth journal" and the births row of "The plan".
func TestRecordComparesTheBirthJournalWithTheBirthsOfThePlan(t *testing.T) {
	const (
		x   = "x509-root"
		sw  = "software"
		pa  = "A.x509.key.pem"
		pb  = "B.x509.key.pem"
		fix = "births.jsonl"
	)
	a := plannedBirth("A", x, sw, pa)
	b := plannedBirth("B", x, sw, pb)
	lineA := func() string { return birthText(t, "A", x, sw, pa) }
	lineB := func() string { return birthText(t, "B", x, sw, pb) }
	without := func(m map[string]any, k string) map[string]any {
		c := map[string]any{}
		for n, v := range m {
			if n != k {
				c[n] = v
			}
		}
		return c
	}
	with := func(m map[string]any, k string, v any) map[string]any {
		c := map[string]any{}
		for n, w := range m {
			c[n] = w
		}
		c[k] = v
		return c
	}
	cases := []struct {
		name    string
		plan    []any // nil leaves the member out of the plan
		journal func() string
		want    string // "" is a record; else a part of the reason
	}{
		{"one birth and its line", []any{a}, lineA, ""},
		{"two births and their lines in the order of the plan", []any{a, b}, func() string { return lineA() + lineB() }, ""},
		{"no birth and no line", nil, func() string { return "" }, ""},
		{"a plan that names no place", []any{without(a, "place")}, func() string { return birthText(t, "A", x, sw, "somewhere-else") }, ""},
		{"a plan that names no purpose or store", []any{without(without(a, "purpose"), "store")}, func() string { return birthText(t, "A", "x509-other", "kms", pa) }, ""},
		{"a plan with no creation time (a line has none)", []any{without(a, "creation_time")}, lineA, ""},
		{"a plan with a member that the line does not have", []any{with(a, "algorithm", "ecdsa-p384")}, lineA, ""},

		{"an empty journal for one birth", []any{a}, func() string { return "" }, "0 lines and the plan lists 1"},
		{"a line missing for the second birth", []any{a, b}, lineA, "1 lines and the plan lists 2"},
		{"a line missing for the first birth", []any{a, b}, lineB, "1 lines and the plan lists 2"},
		{"a line too many", []any{a}, func() string { return lineA() + lineB() }, "2 lines and the plan lists 1"},
		{"a line for a plan that has no birth", nil, lineA, "1 lines and the plan lists 0"},
		{"a line for a label that the plan does not list", []any{a}, lineB, "label"},
		{"the lines in the other order", []any{a, b}, func() string { return lineB() + lineA() }, "label"},
		{"one line twice for two births", []any{a, b}, func() string { return lineA() + lineA() }, "twice"},
		{"another purpose", []any{a}, func() string { return birthText(t, "A", "x509-intermediate", sw, pa) }, "purpose"},
		{"another store", []any{a}, func() string { return birthText(t, "A", x, "kms", pa) }, "store"},
		{"another place", []any{a}, func() string { return birthText(t, "A", x, sw, "somewhere-else") }, "place"},
		{"a place that differs by one letter", []any{a}, func() string { return birthText(t, "A", x, sw, "A.x509.key.pen") }, "place"},
		{"a place that differs in case", []any{a}, func() string { return birthText(t, "A", x, sw, "a.x509.key.pem") }, "place"},
		{"the second birth with another store", []any{a, b}, func() string { return lineA() + birthText(t, "B", x, "kms", pb) }, "store"},
		{"a plan whose store is not a text", []any{with(a, "store", 7)}, lineA, "store"},
		{"a plan whose place is a list", []any{with(a, "place", []any{"x"})}, lineA, "place"},
		{"a plan whose birth names no label", []any{without(a, "label")}, lineA, "no label"},
		{"a plan whose label is a number", []any{with(a, "label", 1)}, lineA, "no label"},
		{"a plan whose birth is a text", []any{"A"}, lineA, "not an object"},
		{"a plan whose birth is a number", []any{5}, lineA, "not an object"},
		{"a plan whose birth is a list", []any{[]any{"A"}}, lineA, "not an object"},
		{"a line that its reader refuses", []any{a}, func() string { return strings.Replace(lineA(), "x509-root", "X509-Root", 1) }, "reader"},
		{"a line with no line feed at its end", []any{a}, func() string { return strings.TrimSuffix(lineA(), "\n") }, "half line"},
		{"an empty line between the lines", []any{a, b}, func() string { return lineA() + "\n" + lineB() }, "half line"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fl := transcribed(t, func(s *spec) {
				s.edit = func(m map[string]any) {
					if c.plan == nil {
						delete(m, "births")
					} else {
						m["births"] = c.plan
					}
				}
			})
			mustWrite(t, fl.b.path("history", name1, fix), c.journal())
			before := tree(t, fl.b.dir)
			mark := fl.b.r.mark()
			out, err := fl.f.Record(fl.recordIn())
			if c.want == "" {
				if err != nil {
					t.Fatalf("a journal that matches the plan is refused: %v", err)
				}
				r, rerr := files.ReadRecord(out)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if r.BirthsSHA256 != sum([]byte(c.journal())) {
					t.Errorf("births_sha256 is not the digest of the file on the disk")
				}
				if rep := fl.b.check(); !rep.Clean() || rep.Records != 1 {
					t.Errorf("findings %+v", rep.Findings)
				}
				return
			}
			if out != nil {
				t.Errorf("Record returned bytes with its error: %s", out)
			}
			wantKind(t, err, ceremony.ErrDiskMismatch)
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the reason is %q, want one that holds %q", err, c.want)
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("a refusal stopped the folder")
			}
			if got := fl.b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused record reached the file system: %v", got)
			}
			sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
			noRecord(t, fl)
		})
	}
}

// After a refusal of the journal the person puts the file right, and the same Folder records.
func TestRecordAfterTheBirthJournalIsPutRightWorks(t *testing.T) {
	a := plannedBirth("A", "x509-root", "software", "A.x509.key.pem")
	b := plannedBirth("B", "x509-root", "software", "B.x509.key.pem")
	fl := transcribed(t, func(s *spec) { s.edit = func(m map[string]any) { m["births"] = []any{a, b} } })
	line := func(l, p string) string { return birthText(t, l, "x509-root", "software", p) }
	jp := fl.b.path("history", name1, "births.jsonl")
	mustWrite(t, jp, line("A", "A.x509.key.pem"))
	_, err := fl.f.Record(fl.recordIn())
	wantKind(t, err, ceremony.ErrDiskMismatch)
	noRecord(t, fl)
	mustWrite(t, jp, line("A", "A.x509.key.pem")+line("B", "B.x509.key.pem"))
	if _, err := fl.f.Record(fl.recordIn()); err != nil {
		t.Fatalf("the record after the repair: %v", err)
	}
}

// Record reads at most 256 MiB in all: the plan, the copies, the attempt, the journals, the
// transcript and the artifacts. Exactly that many are read, and one byte more is refused.
func TestRecordReadsExactly256MiBAndNotOneByteMore(t *testing.T) {
	if testing.Short() {
		t.Skip("reads 256 MiB of zeros")
	}
	const limit = 256 << 20
	build := func(t *testing.T, extra int) *flow {
		fl := transcribed(t, nil)
		rest := 0
		err := filepath.WalkDir(fl.b.path("history", name1), func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				st, serr := d.Info()
				if serr != nil {
					return serr
				}
				rest += int(st.Size())
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		in := fl.recordIn()
		for _, p := range in.Artifacts {
			rest += len(fl.b.read(filepath.FromSlash(p)))
		}
		sizes := make([]int, 0, 33)
		left := limit + extra - rest
		for left > 0 {
			n := min(left, fsx.MaxReadSize)
			sizes = append(sizes, n)
			left -= n
		}
		for i, n := range sizes {
			p := fmt.Sprintf("big/f%02d.bin", i)
			full := fl.b.path(filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := os.Create(full)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(int64(n)); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			in.Artifacts = append(in.Artifacts, p)
		}
		fl.in = func(ri *ceremony.RecordIn) { ri.Artifacts = in.Artifacts }
		return fl
	}
	t.Run("exactly the limit", func(t *testing.T) {
		fl := build(t, 0)
		if err := fl.run(""); err != nil {
			t.Fatalf("256 MiB in all: %v", err)
		}
		if rep := fl.b.check(); !rep.Clean() {
			t.Errorf("findings %+v", rep.Findings)
		}
	})
	t.Run("one byte more", func(t *testing.T) {
		fl := build(t, 1)
		err := fl.run("")
		if err == nil {
			t.Fatal("256 MiB and one byte were recorded")
		}
		wantKind(t, errors.Unwrap(err), ceremony.ErrInvalidInput)
		if !strings.Contains(err.Error(), "in all") {
			t.Errorf("the reason is not the one of the total: %v", err)
		}
		noRecord(t, fl)
	})
}

// A birth journal that is hostile is refused as a mismatch and never crashes Record: bytes that are
// not UTF-8, a line over 4,096 bytes, more lines than a journal takes, a byte that is NUL, a
// folder, a link or a pipe in place of the file. Nothing is written.
func TestRecordRefusesAHostileBirthJournal(t *testing.T) {
	good := birthText(t, "A", "x509-root", "software", "A.x509.key.pem")
	cases := map[string]func(t *testing.T, p string){
		"bytes that are not UTF-8": func(t *testing.T, p string) {
			mustWrite(t, p, strings.Replace(good, "software", "soft\xffware", 1))
		},
		"a line over 4,096 bytes": func(t *testing.T, p string) {
			mustWrite(t, p, strings.Replace(good, "A.x509.key.pem", strings.Repeat("a", 5000), 1))
		},
		"more lines than a journal takes": func(t *testing.T, p string) { mustWrite(t, p, strings.Repeat(good, 200)) },
		"a NUL byte":                      func(t *testing.T, p string) { mustWrite(t, p, strings.Replace(good, "software", "soft\x00ware", 1)) },
		"a line of one NUL":               func(t *testing.T, p string) { mustWrite(t, p, "\x00\n") },
		"only a line feed":                func(t *testing.T, p string) { mustWrite(t, p, "\n") },
		"a carriage return":               func(t *testing.T, p string) { mustWrite(t, p, strings.TrimSuffix(good, "\n")+"\r\n") },
		"a byte order mark":               func(t *testing.T, p string) { mustWrite(t, p, "\xef\xbb\xbf"+good) },
		"a folder": func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, p)
		},
		"a link": func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, p+".elsewhere", good)
			mustLink(t, p+".elsewhere", p)
		},
		"a pipe": func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fl := transcribed(t, nil)
			mutate(t, fl.b.path("history", name1, "births.jsonl"))
			before := tree(t, fl.b.dir)
			mark := fl.b.r.mark()
			out, err := fl.f.Record(fl.recordIn())
			if err == nil {
				t.Fatalf("a record was written: %s", out)
			}
			if out != nil {
				t.Error("Record returned bytes with its error")
			}
			if errors.Is(err, ceremony.ErrFolderStopped) {
				t.Error("a refusal stopped the folder")
			}
			if got := fl.b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused record reached the file system: %v", got)
			}
			sameTree(t, "a refused Record", before, tree(t, fl.b.dir))
			noRecord(t, fl)
			var fe *ceremony.FolderError
			if !errors.As(err, &fe) {
				t.Fatalf("error %T is not a *FolderError", err)
			}
			for i := 0; i < len(err.Error()); i++ {
				if c := err.Error()[i]; c < 0x20 || c > 0x7e {
					t.Errorf("the error text holds the byte %#x", c)
					break
				}
			}
		})
	}
}

// The births of a plan nest as deep as the plan reader lets a plan go; the comparison looks at the
// type of each birth only, and refuses a birth that is not an object, without a deep walk.
func TestRecordRefusesAPlanWhoseBirthIsNestedVeryDeep(t *testing.T) {
	deep := any("A")
	for i := 0; i < 5000; i++ {
		deep = []any{deep}
	}
	fl := transcribed(t, func(s *spec) { s.edit = func(m map[string]any) { m["births"] = []any{deep} } })
	_, err := fl.f.Record(fl.recordIn())
	wantKind(t, err, ceremony.ErrDiskMismatch)
	if !strings.Contains(err.Error(), "not an object") {
		t.Errorf("the reason is %v", err)
	}
	noRecord(t, fl)
}
