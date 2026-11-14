//go:build linux || darwin

package history

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzCheck takes the fuzz bytes as the content of record.json, transcript.txt, attempt.json,
// plan.json and the root list of a bundle of one ceremony, and optionally one entry with a hostile
// name in one of three places. Whatever the bytes are: no panic, the run ends, nothing is changed,
// nothing outside the bundle is read, every text is printable ASCII, the findings are in the fixed
// order, and the report agrees with itself.
func FuzzCheck(f *testing.F) {
	// The seeds: a whole ceremony of each kind that the check tells apart.
	seed := func(b *bundle, r *rec, pick uint8) {
		base := "history/" + r.folder + "/"
		f.Add(b.get(base+"record.json"), r.transcript, b.get(base+"attempt.json"), b.get(base+"plan.json"), b.get("trust/"+r.set+"/root-list.json"), pick)
	}
	b := newBundle(f)
	whole := b.apply()
	seed(b, whole, 0)
	for pick := 1; pick < 60; pick += 7 {
		seed(b, whole, uint8(pick))
	}
	c := newBundle(f)
	c.apply()
	second := c.apply()
	seed(c, second, 3)
	d := newBundle(f)
	stopped := d.unfinished()
	f.Add([]byte{}, []byte{}, d.get("history/"+stopped.folder+"/attempt.json"), d.get("history/"+stopped.folder+"/plan.json"), d.get("trust/"+stopped.set+"/root-list.json"), uint8(0))
	f.Add([]byte(`{"version":2}`), []byte("x"), []byte("{}"), []byte("{}"), []byte("{}"), uint8(5))
	f.Add([]byte(`{`), []byte{}, []byte{}, []byte{}, []byte{}, uint8(200))

	pool := hostileNames()
	pool = append(pool, hostileName{"256 bytes", strings.Repeat("a", 256), "invalid"}, hostileName{"a newline and a colon", "x\n: y", "invalid"})
	f.Fuzz(func(t *testing.T, record, transcript, attempt, plan, rootList []byte, pick uint8) {
		// The bundle is in memory, so that a run costs little and the fuzzer can make many.
		m := newMem()
		const c = "history/20261114T100000Z-apply"
		m.file("ritueel.yaml", "name: x\n")
		if len(record) > 0 {
			m.put(c+"/record.json", &mnode{kind: "file", data: record})
		}
		m.put(c+"/transcript.txt", &mnode{kind: "file", data: transcript})
		m.put(c+"/attempt.json", &mnode{kind: "file", data: attempt})
		m.put(c+"/plan.json", &mnode{kind: "file", data: plan})
		m.put("trust/1-3fa9c1d3/root-list.json", &mnode{kind: "file", data: rootList})
		// One hostile entry, in one of three places, as a file, a folder, a link or a FIFO.
		if i := int(pick) % (len(pool) + 1); i > 0 {
			where := []string{"history", "trust", c, "trust/1-3fa9c1d3", c + "/wanted"}[int(pick/uint8(len(pool)+1))%5]
			kind := []string{"file", "dir", "link", "fifo"}[int(pick/7)%4]
			n := &mnode{kind: kind, data: []byte("x")}
			if kind == "dir" {
				n.kids = map[string]*mnode{"record.json": {kind: "file", data: []byte("not a record")}}
			}
			m.put(where+"/"+pool[i-1].name, n)
		}
		spy, log := newSpy(memFS{m})
		rep, err := runFS(t, spy, nil)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(log.changes) != 0 {
			t.Fatalf("calls that change the bundle: %v", log.changes)
		}
		for p := range log.reads {
			if strings.HasPrefix(p, "/") || slices.Contains(strings.Split(p, "/"), "..") {
				t.Fatalf("a read of %q", p)
			}
		}
		for p := range log.opens {
			if strings.HasPrefix(p, "/") || slices.Contains(strings.Split(p, "/"), "..") {
				t.Fatalf("an open of %q", p)
			}
		}
		checkReport(t, rep)
	})
}

// checkReport holds what is true of every report.
func checkReport(t *testing.T, rep *Report) {
	t.Helper()
	perCode := map[Code]int{}
	for i, f := range rep.Findings {
		line := f.Line()
		if !printable(line) || !printable(f.Path) || !printable(f.Detail) || !utf8.ValidString(line) {
			t.Fatalf("not printable ASCII: %q", line)
		}
		if !slices.Contains(Codes(), f.Code) {
			t.Fatalf("an unknown code %q", f.Code)
		}
		if f.Path == "" || f.Detail == "" {
			t.Fatalf("a finding with no path or no detail: %q", line)
		}
		// A name from the stick is shown with its space as  , so the path has no space and the line
		// is the code, one space, the path, a colon and a space, and the detail: one reading only, and
		// never a line that starts like the end line.
		if strings.Contains(f.Path, " ") {
			t.Fatalf("a space in the path of %q", line)
		}
		if !strings.HasPrefix(line, string(f.Code)+" "+f.Path+": ") || strings.HasPrefix(line, "history:") {
			t.Fatalf("the line %q is not code, path, colon, detail", line)
		}
		perCode[f.Code]++
		if i > 0 && compare(rep.Findings[i-1], f) > 0 {
			t.Fatalf("out of order: %q before %q", rep.Findings[i-1].Line(), line)
		}
	}
	for code, n := range perCode {
		if n > MaxFindingsPerCode {
			t.Fatalf("%d findings of %s", n, code)
		}
	}
	reasons, warnings := rep.Reasons(), rep.Warnings()
	if rep.Clean() != (len(reasons) == 0) {
		t.Fatalf("Clean() = %v with reasons %v", rep.Clean(), reasons)
	}
	for _, c := range reasons {
		if !c.Fails() {
			t.Fatalf("reason %s is a notice", c)
		}
	}
	for _, c := range warnings {
		if !c.Notice() {
			t.Fatalf("warning %s is not a notice", c)
		}
	}
	if !slices.IsSorted(rep.Ends) || rep.Records < 0 {
		t.Fatalf("Records = %d, Ends = %v", rep.Records, rep.Ends)
	}
	if line := rep.EndLine(); !printable(line) || !strings.HasPrefix(line, "history: ") {
		t.Fatalf("EndLine() = %q", line)
	}
	if rep.Records > 0 && len(rep.Ends) == 0 && rep.Clean() {
		t.Fatalf("a clean history of %d records with no end", rep.Records)
	}
}
