//go:build linux || darwin

package ceremony_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The plan in words (docs/reference/ceremony-record.md, "The plan digest and the confirmation";
// record 0005, rules 9 and 20): one fact a line, printable ASCII, the accepted limit before the
// digest, and the digest in 64 digits last.

const pfLimit = "A software root key is a file. Anyone who copies the file can sign as this root, and nothing records it. This is a TEST ONLY root: it is for rehearsals and tests, never for anything that others rely on."

func TestTheAcceptedLimitIsTheWordsOfTheSoftwareRoot(t *testing.T) {
	if ceremony.AcceptedLimit != pfLimit {
		t.Errorf("AcceptedLimit = %q", ceremony.AcceptedLimit)
	}
	if !strings.Contains(ceremony.AcceptedLimit, "TEST ONLY") || !pfPrintable(ceremony.AcceptedLimit) {
		t.Error("the limit does not say TEST ONLY, or is not printable ASCII")
	}
}

func TestTheGoldenPlanInWords(t *testing.T) {
	got := pfPlan(t, pfFiles()).Words()
	want := []string{
		"ceremony 20261120T100000Z-apply, made at 2026-11-20T10:00:00Z, by ritueel v0.0.0-test (linux/amd64)",
		"writes the first trust set, number 1",
		"make the X.509 root key A: a software key in a file of the folder test-only-keys (x509-root-a), TEST ONLY",
		"make the X.509 root key B: a software key in a file of the folder test-only-keys (x509-root-b), TEST ONLY",
		"leaves out: nothing",
		"signatures: 5; none can be fixed before the keys are born, so each is derived from a key made in this ceremony",
		"touches: 0",
		"wanted file ritueel.yaml, digest " + pfSumSet[:8],
		"wanted file want/roots/x509.yaml, digest " + pfSumRoot[:8],
		"limit: " + pfLimit,
		"plan digest " + pfGoldenDigest,
	}
	if !slices.Equal(got, want) {
		t.Errorf("the plan in words is\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestThePlanInWordsHasTheRequestsItLeavesOut(t *testing.T) {
	files2 := pfFiles()
	files2["requests/acme-ca-2027/request.json"] = "x"
	words := pfPlan(t, files2).Words()
	if slices.Contains(words, "leaves out: nothing") {
		t.Error("the plan says it leaves out nothing")
	}
	want := "leaves out requests/acme-ca-2027: " + pfLeftOutReason
	if !slices.Contains(words, want) {
		t.Errorf("no line %q in\n%s", want, strings.Join(words, "\n"))
	}
	i := slices.Index(words, want)
	if words[i-1] != "make the X.509 root key B: a software key in a file of the folder test-only-keys (x509-root-b), TEST ONLY" || !strings.HasPrefix(words[i+1], "signatures: 5;") {
		t.Errorf("the line is not between the keys and the signatures: %q ... %q", words[i-1], words[i+1])
	}
}

func TestTheWordsEndWithTheLimitAndTheFullDigest(t *testing.T) {
	for _, keys := range []int{1, 2, 26} {
		f := pfMustFind(t, pfFiles())
		f.Applies = pfApplies(keys)
		p, err := ceremony.MakePlan(f, pfEnv())
		if err != nil {
			t.Fatal(err)
		}
		w := p.Words()
		n := len(w)
		if !strings.HasPrefix(w[n-1], "plan digest ") || len(w[n-1]) != len("plan digest ")+64 || strings.TrimPrefix(w[n-1], "plan digest ") != p.SHA256 {
			t.Errorf("%d keys: the last line is %q", keys, w[n-1])
		}
		if w[n-2] != "limit: "+pfLimit {
			t.Errorf("%d keys: the line before the digest is %q", keys, w[n-2])
		}
		var made int
		for _, l := range w {
			if strings.HasPrefix(l, "make the X.509 root key ") {
				made++
			}
		}
		if made != keys {
			t.Errorf("%d keys: %d lines about a key", keys, made)
		}
		if want := fmt.Sprintf("signatures: %d;", 2*keys+1); !strings.HasPrefix(w[slices.IndexFunc(w, func(l string) bool { return strings.HasPrefix(l, "signatures:") })], want) {
			t.Errorf("%d keys: the line of the signatures is not %q", keys, want)
		}
		if !slices.Contains(w, "touches: 0") {
			t.Errorf("%d keys: no line says that there are no touches", keys)
		}
	}
}

func TestEveryLineOfTheWordsIsPrintableAsciiOnOneLine(t *testing.T) {
	files2 := pfFiles()
	files2["requests/a-b/request.json"] = "x"
	for _, l := range pfPlan(t, files2).Words() {
		if !pfPrintable(l) || l == "" {
			t.Errorf("the line %+q is empty or not printable ASCII", l)
		}
	}
}

func TestWordsShowsEveryNameThatCameFromAFileEscaped(t *testing.T) {
	p := &ceremony.PlanOut{
		Name:   "20261120T100000Z-apply\n\x1b[31m",
		SHA256: pfGoldenDigest,
		Program: buildinfo.Program{
			Version: "v1\x00\xe2\x80\xae", OSArch: "linux/\xc3\xa9",
		},
		Births: []ceremony.PlanBirth{{Label: "A\r", Place: "a b\\c\xff.x509.key.pem"}},
		LeavesOut: []ceremony.LeftOut{
			{Object: "requests/a\x1b[2J", Reason: "line one\nline two \xe2\x80\xae"},
		},
		Wanted:     []files.FileRef{{Path: "want/roots/a\tb\xff.yaml", SHA256: pfSumSet}},
		Signatures: make([]ceremony.PlanSignature, 3),
	}
	words := p.Words()
	if len(words) == 0 {
		t.Fatal("no words")
	}
	for _, l := range words {
		if !pfPrintable(l) {
			t.Errorf("the line %+q is not printable ASCII on one line", l)
		}
	}
	joined := strings.Join(words, "\n")
	for _, raw := range []string{"\x1b", "\xe2\x80\xae", "\xff", "\r", "\t", "\x00"} {
		if strings.Contains(joined, raw) {
			t.Errorf("the words hold the raw bytes %+q", raw)
		}
	}
	// A backslash is doubled in a name, so that two names do not print as one line.
	if !strings.Contains(joined, `b\\c`) {
		t.Errorf("the backslash of a name was not doubled: %s", joined)
	}
}

func TestAPlanThatWasNotMadeHasNoWords(t *testing.T) {
	var nilPlan *ceremony.PlanOut
	for name, p := range map[string]*ceremony.PlanOut{
		"nil":            nilPlan,
		"zero":           {},
		"no name":        {SHA256: pfGoldenDigest},
		"no digest":      {Name: pfName},
		"only the bytes": {JSON: []byte(pfGolden)},
	} {
		if w := p.Words(); len(w) != 0 {
			t.Errorf("%s: %d lines of words", name, len(w))
		}
	}
}

func TestAShortDigestOfAWantedFileIsShownWhole(t *testing.T) {
	p := &ceremony.PlanOut{Name: pfName, SHA256: pfGoldenDigest, Wanted: []files.FileRef{{Path: "ritueel.yaml", SHA256: "abc"}}}
	if w := p.Words(); !slices.Contains(w, "wanted file ritueel.yaml, digest abc") {
		t.Errorf("words = %q", w)
	}
}
