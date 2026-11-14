//go:build linux || darwin

package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestChangedValueThatStaysValidBreaksTheRecordAfterIt(t *testing.T) {
	b, r := threeRecords(t)
	rewrite(b, r[1], func(c []byte) []byte {
		return bytes.Replace(c, []byte(`"outcome":"completed"`), []byte(`"outcome":"declined"`), 1)
	})
	rep := b.run()
	// Record 3 names the digest that record 2 had. The root list of set 3 anchors the same digest.
	wantFindings(t, rep, []wf{
		{ChainBroken, folderPath(r[2])},
		{AnchorUnknown, "trust/" + r[2].set + "/root-list.json"},
	})
	wantReasons(t, rep, []Code{ChainBroken, AnchorUnknown}, nil)
	if rep.Records != 3 {
		t.Errorf("Records = %d, want 3", rep.Records)
	}
	// There are two ends, the changed record and the third: no end is printed.
	if len(rep.Ends) != 2 {
		t.Errorf("Ends = %v, want two", rep.Ends)
	}
	if _, _, ok := rep.End(); ok {
		t.Error("End() has an end for a history of two ends")
	}
	if strings.Contains(rep.EndLine(), "end") {
		t.Errorf("EndLine() = %q holds an end", rep.EndLine())
	}
}

func TestChangedValueThatBreaksARuleIsInvalidAndBreaksTheChain(t *testing.T) {
	b, r := threeRecords(t)
	rewrite(b, r[1], func(c []byte) []byte {
		return bytes.Replace(c, []byte(`"outcome":"completed"`), []byte(`"outcome":"done"`), 1)
	})
	rep := b.run()
	// A record that did not pass the strict read lists nothing, so its trust set is unlisted.
	wantFindings(t, rep, []wf{
		{ChainBroken, folderPath(r[2])},
		{RecordInvalid, recordPath(r[1])},
		{TrustSetUnlisted, setPath(r[1])},
		{AnchorUnknown, "trust/" + r[2].set + "/root-list.json"},
	}, RecordOffChain)
	wantReasons(t, rep, []Code{ChainBroken, RecordInvalid, TrustSetUnlisted, AnchorUnknown}, nil, RecordOffChain)
	if rep.Records != 3 {
		t.Errorf("Records = %d: a record that is not valid still counts", rep.Records)
	}
}

func TestPrevChangedInTheLastRecordBreaksOnlyThatRecord(t *testing.T) {
	b := newBundle(t)
	b.apply()
	b.apply()
	r3 := b.apply(noSet, prev(digestA))
	rep := b.run()
	wantFindings(t, rep, []wf{{ChainBroken, folderPath(r3)}})
	wantReasons(t, rep, []Code{ChainBroken}, nil)
}

func TestPrettyPrintedRecordIsNotCanonical(t *testing.T) {
	pretty := func(c []byte) []byte {
		var out bytes.Buffer
		if err := json.Indent(&out, c, "", "  "); err != nil {
			panic(err)
		}
		return out.Bytes()
	}
	t.Run("written so, and the next record names it", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		r2 := b.apply(recordAs(pretty))
		b.apply()
		rep := b.run()
		wantFindings(t, rep, []wf{{RecordNotCanonical, recordPath(r2)}})
	})
	t.Run("made so after the next record was written", func(t *testing.T) {
		b, r := threeRecords(t)
		rewrite(b, r[1], pretty)
		rep := b.run()
		wantFindings(t, rep, []wf{
			{RecordNotCanonical, recordPath(r[1])},
			{ChainBroken, folderPath(r[2])},
			{AnchorUnknown, "trust/" + r[2].set + "/root-list.json"},
		})
	})
}

func TestUnknownVersionOfARecordIsNamed(t *testing.T) {
	for _, v := range []string{"2", "0", "-1", "9007199254740991"} {
		t.Run("version "+v, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet, recordAs(func([]byte) []byte { return []byte(`{"version":` + v + `,"x":{}}`) }))
			rep := b.run()
			has(t, rep, RecordVersionUnknown, recordPath(r))
			lacks(t, rep, RecordInvalid)
			if d := detail(rep, RecordVersionUnknown, recordPath(r)); !strings.Contains(d, v) {
				t.Errorf("the detail %q does not name the version %s", d, v)
			}
			if rep.Records != 1 {
				t.Errorf("Records = %d, want 1", rep.Records)
			}
			if rep.Clean() {
				t.Error("an unknown version is clean")
			}
		})
	}
	t.Run("minus zero is version 0", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet, recordAs(func([]byte) []byte { return []byte(`{"version":-0}`) }))
		rep := b.run()
		has(t, rep, RecordVersionUnknown, recordPath(r))
		if d := detail(rep, RecordVersionUnknown, recordPath(r)); !strings.Contains(d, "0") {
			t.Errorf("the detail %q does not name version 0", d)
		}
	})
	t.Run("nothing else of the record is read", func(t *testing.T) {
		// A member that version 1 would refuse beside a version it does not know.
		b := newBundle(t)
		r := b.apply(noSet, recordAs(func([]byte) []byte {
			return []byte(`{"ceremony":5,"extra":null,"extra":1.5,"version":2}`)
		}))
		rep := b.run()
		has(t, rep, RecordVersionUnknown, recordPath(r))
		lacks(t, rep, RecordInvalid)
	})
	t.Run("a record of version 2 lists no file", func(t *testing.T) {
		// Its trust set shows as unlisted: the check does not read what it lists.
		b := newBundle(t)
		r := b.apply(recordAs(func([]byte) []byte { return []byte(`{"version":2}`) }))
		rep := b.run()
		has(t, rep, RecordVersionUnknown, recordPath(r))
		has(t, rep, TrustSetUnlisted, setPath(r))
	})
}

// A document that is not a valid record of version 1 is record-invalid, whatever way it is wrong.
func TestRecordInvalidForEveryWayTheDocumentIsWrong(t *testing.T) {
	deep := func(n int) string {
		return `,"arguments":` + strings.Repeat(`{"a":`, n-2) + `{}` + strings.Repeat(`}`, n-2)
	}
	cases := map[string]func(base []byte) []byte{
		"unknown member": func(c []byte) []byte { return bytes.Replace(c, []byte("}"), []byte(`,"zzz":1}`), 1) },
		"repeated member": func(c []byte) []byte {
			return bytes.Replace(c, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
		},
		"garbage":                  func([]byte) []byte { return []byte("this is not JSON") },
		"a byte order mark":        func(c []byte) []byte { return append([]byte("\xef\xbb\xbf"), c...) },
		"bytes that are not UTF-8": func(c []byte) []byte { return bytes.Replace(c, []byte(`"completed"`), []byte("\"comp\xffleted\""), 1) },
		"300 KiB": func(c []byte) []byte {
			return append(bytes.TrimSuffix(c, []byte("}")), []byte(`,"arguments":{"p":"`+strings.Repeat("x", 300<<10)+`"}}`)...)
		},
		"256 KiB and one byte": func(c []byte) []byte { return pad(c, 256<<10+1) },
		"10001 levels":         func(c []byte) []byte { return append(bytes.TrimSuffix(c, []byte("}")), []byte(deep(10001)+"}")...) },
		"null":                 func(c []byte) []byte { return bytes.Replace(c, []byte(`"completed"`), []byte(`null`), 1) },
		"a fraction": func(c []byte) []byte {
			return bytes.Replace(c, []byte(`"trust_sequence":1`), []byte(`"trust_sequence":1.5`), 1)
		},
		"the version as a text": func(c []byte) []byte { return bytes.Replace(c, []byte(`"version":1`), []byte(`"version":"1"`), 1) },
		"no version":            func(c []byte) []byte { return bytes.Replace(c, []byte(`"version":1,`), nil, 1) },
		"the version 2^53": func(c []byte) []byte {
			return bytes.Replace(c, []byte(`"version":1`), []byte(`"version":9007199254740992`), 1)
		},
		"an empty file":        func([]byte) []byte { return nil },
		"white space only":     func([]byte) []byte { return []byte(" \n\t") },
		"a list":               func([]byte) []byte { return []byte("[]") },
		"two documents":        func(c []byte) []byte { return append(append([]byte{}, c...), c...) },
		"a digest in capitals": func(c []byte) []byte { return upperDigest(c, `"transcript_sha256":"`) },
		"a name with a space": func(c []byte) []byte {
			return bytes.Replace(c, []byte(`"ceremony":"2026`), []byte(`"ceremony":"a b2026`), 1)
		},
		"the command join": func(c []byte) []byte {
			return bytes.Replace(c, []byte(`"command":"apply"`), []byte(`"command":"join"`), 1)
		},
		"closes in an apply record": func(c []byte) []byte {
			return bytes.Replace(c, []byte("}"), []byte(`,"closes":{"ceremony":"a","attempt_sha256":"`+digestA+`"}}`), 1)
		},
		"the artifacts member absent": func(c []byte) []byte {
			i := bytes.Index(c, []byte(`"ceremony"`))
			return append([]byte("{"), c[i:]...)
		},
		"the wanted member absent": func(c []byte) []byte {
			i := bytes.Index(c, []byte(`,"wanted"`))
			return append(append([]byte{}, c[:i]...), '}')
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet)
			rewrite(b, r, f)
			rep := b.run()
			has(t, rep, RecordInvalid, recordPath(r))
			lacks(t, rep, RecordVersionUnknown)
			if rep.Records != 1 {
				t.Errorf("Records = %d, want 1: a record that is invalid still counts", rep.Records)
			}
			if rep.Clean() {
				t.Error("clean")
			}
			if d := detail(rep, RecordInvalid, recordPath(r)); d == "" {
				t.Error("the finding has no detail")
			}
			checkForm(t, rep)
		})
	}
}

// pad makes a document of exactly n bytes by a member that holds filler.
func pad(c []byte, n int) []byte {
	head := append(bytes.TrimSuffix(c, []byte("}")), []byte(`,"arguments":{"p":"`)...)
	tail := []byte(`"}}`)
	out := slices.Concat(head, bytes.Repeat([]byte("x"), n-len(head)-len(tail)), tail)
	return out
}

func upperDigest(c []byte, key string) []byte {
	i := bytes.Index(c, []byte(key)) + len(key)
	out := slices.Clone(c)
	copy(out[i:i+64], bytes.ToUpper(c[i:i+64]))
	return out
}

func TestRemovedRecordInTheMiddleBreaksItsSuccessorAndOrphansTheRest(t *testing.T) {
	b := newBundle(t)
	r := [4]*rec{b.apply(), b.apply(), b.apply(), b.apply()}
	b.remove("history/" + r[1].folder)
	rep := b.run()
	wantFindings(t, rep, []wf{
		{ChainBroken, folderPath(r[2])},
		{RecordOffChain, folderPath(r[3])},
		{TrustSetUnlisted, setPath(r[1])},
		{AnchorUnknown, "trust/" + r[2].set + "/root-list.json"},
		{AnchorUnknown, "trust/" + r[3].set + "/root-list.json"},
	})
	wantReasons(t, rep, []Code{ChainBroken, RecordOffChain, TrustSetUnlisted, AnchorUnknown}, nil)
	if rep.Records != 3 {
		t.Errorf("Records = %d, want 3", rep.Records)
	}
	if len(rep.Ends) != 2 || !slices.Contains(rep.Ends, r[0].digest) || !slices.Contains(rep.Ends, r[3].digest) {
		t.Errorf("Ends = %v, want the digests of records 1 and 4", rep.Ends)
	}
}

func TestRemovedNewestRecordLeavesItsTrustSetUnlisted(t *testing.T) {
	b, r := threeRecords(t)
	b.remove("history/" + r[2].folder)
	rep := b.run()
	wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(r[2])}})
	if rep.Records != 2 {
		t.Errorf("Records = %d, want 2", rep.Records)
	}
	if !slices.Equal(rep.Ends, []string{r[1].digest}) {
		t.Errorf("Ends = %v", rep.Ends)
	}
}

func TestRemovedOldestRecordBreaksTheNextOne(t *testing.T) {
	b, r := threeRecords(t)
	b.remove("history/" + r[0].folder)
	rep := b.run()
	// Record 2 now names a record that is not there; record 3 names record 2, which is not on the chain.
	has(t, rep, ChainBroken, folderPath(r[1]))
	has(t, rep, RecordOffChain, folderPath(r[2]))
	has(t, rep, TrustSetUnlisted, setPath(r[0]))
	if rep.Clean() {
		t.Error("clean")
	}
}

func TestForkWhenTwoRecordsNameOne(t *testing.T) {
	b := newBundle(t)
	a := b.apply()
	b1 := b.apply()
	c := b.apply(prev(a.digest))
	rep := b.run()
	wantFindings(t, rep, []wf{{Fork, folderPath(a)}})
	d := detail(rep, Fork, folderPath(a))
	if !strings.Contains(d, b1.folder) || !strings.Contains(d, c.folder) {
		t.Errorf("the detail %q does not name both successors, %s and %s", d, b1.folder, c.folder)
	}
	// Both ends are in the report and no end is printed.
	if len(rep.Ends) != 2 || !slices.Contains(rep.Ends, b1.digest) || !slices.Contains(rep.Ends, c.digest) {
		t.Errorf("Ends = %v, want %s and %s", rep.Ends, b1.digest, c.digest)
	}
	if _, count, ok := rep.End(); ok || count != 3 {
		t.Errorf("End() = _, %d, %v; want 3, false", count, ok)
	}
	if want := "history: 3 ceremony records"; rep.EndLine() != want {
		t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
	}
	if !slices.IsSorted(rep.Ends) {
		t.Errorf("Ends is not in the order of the digests: %v", rep.Ends)
	}
}

func TestByteIdenticalCopyOfARecordInAnotherFolderIsAFork(t *testing.T) {
	b, r := threeRecords(t)
	copyOf := "20269999T100000Z-apply"
	b.mkdir("history/" + copyOf)
	b.put("history/"+copyOf+"/record.json", b.get("history/"+r[1].folder+"/record.json"))
	rep := b.run()
	has(t, rep, Fork, folderPath(r[0]))
	d := detail(rep, Fork, folderPath(r[0]))
	if !strings.Contains(d, r[1].folder) || !strings.Contains(d, copyOf) {
		t.Errorf("the detail %q does not name %s and %s", d, r[1].folder, copyOf)
	}
	if rep.Records != 4 {
		t.Errorf("Records = %d, want 4: the copy is a record file", rep.Records)
	}
	if rep.Clean() {
		t.Error("clean")
	}
}

func TestForkNamesAtMostEightSuccessors(t *testing.T) {
	b := newBundle(t)
	root := b.apply(noSet)
	var kids []*rec
	for i := 0; i < 12; i++ {
		kids = append(kids, b.apply(noSet, prev(root.digest)))
	}
	rep := b.run()
	var forks []Finding
	for _, f := range rep.Findings {
		if f.Code == Fork {
			forks = append(forks, f)
		}
	}
	if len(forks) != 1 || forks[0].Path != folderPath(root) {
		t.Fatalf("forks = %v, want one at %s", forks, folderPath(root))
	}
	d := forks[0].Detail
	if n := strings.Count(d, "T100000Z-apply"); n != MaxNamesShown {
		t.Errorf("the detail names %d folders, want %d: %s", n, MaxNamesShown, d)
	}
	for i, k := range kids {
		if got, want := strings.Contains(d, k.folder), i < 8; got != want {
			t.Errorf("successor %d (%s) in the detail: %v, want %v", i+1, k.folder, got, want)
		}
	}
	if len(rep.Ends) != 12 {
		t.Errorf("Ends holds %d digests, want 12", len(rep.Ends))
	}
}

func TestSecondRecordWithoutPrevBreaksBoth(t *testing.T) {
	b := newBundle(t)
	a := b.apply(noSet)
	x := b.apply(noSet, prev(""))
	b.apply(noSet)
	rep := b.run()
	// Only the first record may lack a predecessor; which of two it is cannot be told.
	has(t, rep, ChainBroken, folderPath(a))
	has(t, rep, ChainBroken, folderPath(x))
	if rep.Clean() {
		t.Error("clean")
	}
	if got := fmt.Sprint(rep.Reasons()); !strings.Contains(got, "chain-broken") {
		t.Errorf("Reasons() = %v", rep.Reasons())
	}
}

func TestEveryRecordWithoutPrevButNoneNamedFirstIsBroken(t *testing.T) {
	// Three records, none with a predecessor: every one is chain-broken.
	b := newBundle(t)
	var rs []*rec
	for i := 0; i < 3; i++ {
		rs = append(rs, b.apply(noSet, prev("")))
	}
	rep := b.run()
	for _, r := range rs {
		has(t, rep, ChainBroken, folderPath(r))
	}
}

func TestSingleRecordWithAPredecessorThatIsNotThereIsBroken(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet, prev(digestA))
	rep := b.run()
	wantFindings(t, rep, []wf{{ChainBroken, folderPath(r)}})
	if rep.Records != 1 {
		t.Errorf("Records = %d, want 1", rep.Records)
	}
}

func TestPrevNamingTheRecordItselfIsBroken(t *testing.T) {
	// A record cannot name its own digest, but one that names a copy of itself is a loop of two
	// copies; the walk must not hang and must not call it clean.
	b := newBundle(t)
	a := b.apply(noSet)
	copyOf := "20269999T100000Z-apply"
	b.mkdir("history/" + copyOf)
	b.put("history/"+copyOf+"/record.json", b.get("history/"+a.folder+"/record.json"))
	rep := b.run()
	if rep.Records != 2 {
		t.Errorf("Records = %d, want 2", rep.Records)
	}
	// Two files with no predecessor: both are broken.
	has(t, rep, ChainBroken, folderPath(a))
	has(t, rep, ChainBroken, "history/"+copyOf)
}

func TestLongChainsAreClean(t *testing.T) {
	n := 500
	if testing.Short() {
		n = 100
	}
	b := newBundle(t)
	for i := 0; i < n; i++ {
		b.apply(noSet)
	}
	rep := b.run()
	wantFindings(t, rep, nil)
	if rep.Records != n || len(rep.Ends) != 1 {
		t.Errorf("Records = %d, Ends = %d; want %d and 1", rep.Records, len(rep.Ends), n)
	}
}

// A record that cannot be read names no record before it, so it and every record after it are off the
// chain: each gets that finding, besides the own finding of the damaged record (the page).
func TestRecordThatCannotBeReadPutsItAndEveryRecordAfterItOffTheChain(t *testing.T) {
	cases := map[string]func(*rec){
		"invalid": recordAs(func(c []byte) []byte {
			return bytes.Replace(c, []byte(`"outcome":"completed"`), []byte(`"outcome":"done"`), 1)
		}),
		"version 2":     recordAs(func([]byte) []byte { return []byte(`{"version":2}`) }),
		"not an object": recordAs(func([]byte) []byte { return []byte(`[]`) }),
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r1 := b.apply(noSet)
			r2 := b.apply(noSet, damage)
			r3 := b.apply(noSet)
			r4 := b.apply(noSet)
			rep := b.run()
			for _, r := range []*rec{r2, r3, r4} {
				has(t, rep, RecordOffChain, folderPath(r))
			}
			for _, f := range rep.Findings {
				if f.Code == RecordOffChain && f.Path == folderPath(r1) {
					t.Errorf("the record before the damaged one is called off the chain: %s", f.Line())
				}
			}
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}
