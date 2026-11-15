//go:build linux || darwin

package history

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// The finding trust-sequence under limits and hostile input: it reads nothing more than the walk
// read, it is bounded like every finding, and a name or a sequence that is odd never crashes the
// run or puts a raw byte in a line.

// A bundle with the finding costs the reads of the same bundle with no finding, and nothing
// changes: no file is read twice, no folder is listed twice, nothing is written.
func TestTrustSequenceMakesNoSecondWalk(t *testing.T) {
	clean, _ := numbersChain(t, nums(1, 2, 3, 4)...)
	crepRep, clog := clean.runSpied()
	wantExactly(t, crepRep)
	bad, names := numbersChain(t, nums(1, 3, 3, 2)...)
	rep, blog := bad.runSpied()
	wantExactly(t, rep, wf{TrustSequence, "trust/" + names[2]}, wf{TrustSequence, "trust/" + names[3]})
	sum := func(m map[string]int) (n int) {
		for _, c := range m {
			n += c
		}
		return n
	}
	if sum(blog.reads) != sum(clog.reads) || len(blog.reads) != len(clog.reads) {
		t.Errorf("reads: %d of %d files, the clean bundle costs %d of %d", sum(blog.reads), len(blog.reads), sum(clog.reads), len(clog.reads))
	}
	if sum(blog.lists) != sum(clog.lists) || sum(blog.opens) != sum(clog.opens) {
		t.Errorf("lists %d and opens %d, the clean bundle costs %d and %d", sum(blog.lists), sum(blog.opens), sum(clog.lists), sum(clog.opens))
	}
	for p, n := range blog.reads {
		if n != 1 {
			t.Errorf("%s was read %d times", p, n)
		}
	}
	if len(blog.changes) != 0 {
		t.Errorf("the check changed the bundle: %v", blog.changes)
	}
}

// At most 1,000 findings of one code are kept, and the count of what was left out is said: also for
// a chain whose every set has the number of the one before it.
func TestTrustSequenceFindingsAreBounded(t *testing.T) {
	const sets = MaxFindingsPerCode + 101
	list := make([]cset, sets)
	for i := range list {
		list[i] = cset{fmt.Sprintf("1-%08x", i), keyList(1, kA)}
	}
	rep, err := runMem(t, chainMem(t, list...))
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	if n := countCode(rep, TrustSequence); n != MaxFindingsPerCode {
		t.Errorf("%d findings of trust-sequence are kept, want %d", n, MaxFindingsPerCode)
	}
	if want := sets - 1 - MaxFindingsPerCode; rep.Omitted != want {
		t.Errorf("Omitted = %d, want %d (the first set has none before it)", rep.Omitted, want)
	}
	if rep.Clean() {
		t.Error("clean")
	}
}

// Names and sequences that are odd: every case ends with a report, whose lines are printable ASCII
// of one line, and no case has a trust-sequence line that holds a raw byte of the name.
func TestTrustSequenceOddNamesAndSequences(t *testing.T) {
	names := map[string]string{
		"a line break":          "5-ab\ncd",
		"a carriage return":     "5-ab\rcd",
		"a NUL":                 "5-ab\x00cd",
		"an escape":             "5-\x1b[31mred",
		"a right to left mark":  "5-ab\u202ecd",
		"a letter beyond ASCII": "5-\u00e9",
		"a space":               "5-a b",
		"a long name":           "5-" + strings.Repeat("a", 300),
		"only a hyphen":         "-",
		"dots":                  "..",
		"a backslash":           "5-a\\b",
		"a very long number":    strings.Repeat("9", 300) + "-aaaaaaaa",
		"a colon":               "5-a:b",
	}
	for name, set := range names {
		t.Run(name, func(t *testing.T) {
			// in memory: a real folder cannot hold some of these names
			b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{set, keyList(2, kA)})
			rep, err := runMem(t, b.mem)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			checkReport(t, rep)
			for _, f := range trustSeqFindings(rep) {
				if !printable(f.Line()) {
					t.Errorf("the line %q is not printable ASCII", f.Line())
				}
			}
			if rep.Clean() && set != setN(2) {
				t.Errorf("a clean report for the set %q", set)
			}
			in, err := inspectFS(t, memFS{b.mem})
			if err != nil || in == nil || (!in.Report.Clean() && (in.State != nil || in.OrderErr != nil)) {
				t.Errorf("Inspect: %v %v", in, err)
			}
		})
	}
	// A sequence that is not a whole number, or is written in a form that is not canonical: the list
	// cannot be read, and the finding is the anchor.
	for _, seq := range []string{`"1"`, `1.0`, `1e0`, `01`, `null`, `[]`, `{}`, `true`, `1.5`, `+1`, `0x1`, `1_0`} {
		t.Run("a sequence written "+seq, func(t *testing.T) {
			b := chainBundle(t, false, cset{setN(1), seqList(seq, kA)})
			rep := b.run()
			checkReport(t, rep)
			has(t, rep, AnchorUnknown, listPathOf(setN(1)))
			lacks(t, rep, TrustSequence)
		})
	}
}

// A trust set whose name is not UTF-8 cannot be listed by a record (a record is JSON text), so it
// is a set that no record lists: it is refused by name, and the finding trust-sequence does not
// see it.
func TestTrustSequenceANameThatIsNotUTF8IsNoListedSet(t *testing.T) {
	b := chainBundle(t, true, cset{setN(1), keyList(1, kA)})
	b.mkdir("trust/5-ab\xff\xfecd")
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	lacks(t, rep, TrustSequence)
	if rep.Clean() || countCode(rep, UnexpectedName) == 0 {
		t.Errorf("findings %v", findingsOf(rep))
	}
}

// A sequence written -0 is the number 0: below 1.
func TestAnchorUnknownASequenceOfMinusZeroIsZero(t *testing.T) {
	b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("-0", kA)})
	wantExactly(t, b.run(), wf{AnchorUnknown, listPathOf("0-aaaaaaaa")})
}

// Many sets of growing numbers: many sets of one number do not make the finding grow beyond the
// sets, and the order of 2,000 sets runs in one pass.
func TestTrustSequenceALongChainOfGrowingNumbersIsClean(t *testing.T) {
	const n = 2000
	list := make([]cset, n)
	for i := range list {
		list[i] = cset{setN(i + 1), keyList(int64(i+1), kA)}
	}
	rep, err := runMem(t, chainMem(t, list...))
	if err != nil {
		t.Fatal(err)
	}
	wantExactly(t, rep)
	// the same with every number a skip of three
	for i := range list {
		num := int64(3*i + 1)
		list[i] = cset{setN(int(num)), keyList(num, kA)}
	}
	rep, err = runMem(t, chainMem(t, list...))
	if err != nil {
		t.Fatal(err)
	}
	wantExactly(t, rep)
}

// A model of the finding over random numbers: a name of digits, a sequence written as a number or
// left out; the report must hold exactly the findings of trust-sequence and of the anchor that the
// model of the rules says, and a failing report has no State.
func FuzzTrustNumbers(f *testing.F) {
	f.Add("1", "2", "2", int64(1), int64(2), int64(2), uint8(0))
	f.Add("1", "3", "2", int64(1), int64(3), int64(2), uint8(0))
	f.Add("0", "1", "2", int64(0), int64(1), int64(2), uint8(0))
	f.Add("01", "", "9999999999999999999", int64(-1), int64(-9223372036854775808), int64(9223372036854775807), uint8(0))
	f.Add("2", "3", "4", int64(2), int64(7), int64(4), uint8(2))
	f.Add("5", "5", "5", int64(5), int64(5), int64(5), uint8(7))
	f.Fuzz(func(t *testing.T, p0, p1, p2 string, s0, s1, s2 int64, none uint8) {
		prefixes := []string{p0, p1, p2}
		seqs := []int64{s0, s1, s2}
		sets := make([]cset, 3)
		for i := range sets {
			var digits strings.Builder
			for j := 0; j < len(prefixes[i]) && j < 22; j++ {
				digits.WriteByte('0' + prefixes[i][j]%10)
			}
			name := digits.String() + "-" + strings.Repeat(string(rune('a'+i)), 8)
			if none&(1<<i) != 0 {
				sets[i] = cset{name, rootsJSON(0, kA)}
			} else {
				sets[i] = cset{name, seqList(strconv.FormatInt(seqs[i], 10), kA)}
			}
		}
		b := chainBundle(t, true, sets...)
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		checkReport(t, rep)
		var got []wf
		for _, f := range rep.Findings {
			if f.Code == TrustSequence || f.Code == AnchorUnknown {
				got = append(got, wf{f.Code, f.Path})
			}
		}
		want := modelTrustSeq(sets)
		if g, w := sortWF(got), sortWF(want); fmt.Sprint(g) != fmt.Sprint(w) {
			t.Fatalf("sets %q\n got %v\nwant %v", setNames(sets), g, w)
		}
		in, err := inspectFS(t, memFS{b.mem})
		if err != nil || in == nil {
			t.Fatalf("Inspect: %v", err)
		}
		if !in.Report.Clean() && (in.State != nil || in.OrderErr != nil) {
			t.Fatalf("State %v, OrderErr %v with a failing report", in.State, in.OrderErr)
		}
		sameReport(t, in.Report, rep)
	})
}
