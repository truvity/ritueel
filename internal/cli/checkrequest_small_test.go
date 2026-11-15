package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/testrepo"
)

// Small faults of "check request": the rules of check 9 that a missing delegation leaves out (point 2), a repeated
// --delegation (point 3), and the sentence for a delegation of the type openpgp-subkey (point 4).

// ---- point 2: the names of the rules that no delegation leaves out ----------------------------------------

// openPGPPrimariesOf reads the active primaries of the pinned root list of the vectors with go-crypto, the reader of
// the tests and not the reader under test.
func openPGPPrimariesOf(t testing.TB) []handoff.PrimaryRef {
	t.Helper()
	var m struct {
		Pinned struct {
			RootList struct {
				OpenPGP []string `json:"openpgp"`
			} `json:"root_list"`
		} `json:"pinned"`
	}
	if err := json.Unmarshal(testrepo.Read(t, crqVectorsDir, "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Pinned.RootList.OpenPGP) < 2 {
		t.Fatalf("the pinned root list holds %d OpenPGP primaries, want at least 2", len(m.Pinned.RootList.OpenPGP))
	}
	var out []handoff.PrimaryRef
	for _, f := range m.Pinned.RootList.OpenPGP {
		p, err := gopacket.Read(bytes.NewReader(testrepo.Read(t, crqVectorsDir, f)))
		if err != nil {
			t.Fatal(err)
		}
		pk, ok := p.(*gopacket.PublicKey)
		if !ok {
			t.Fatalf("%s: the first packet is %T, want a public key", f, p)
		}
		// The point of the key in the form that crypto/ecdsa takes: the reader of go-crypto keeps it as a point.
		type pointer interface{ MarshalPoint() []byte }
		raw, ok := pk.PublicKey.(pointer)
		if !ok {
			t.Fatalf("%s: the key is %T, want a key with a point", f, pk.PublicKey)
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw.MarshalPoint())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, handoff.PrimaryRef{Fingerprint: hex.EncodeToString(pk.Fingerprint), Key: key, Created: pk.CreationTime.UTC()})
	}
	return out
}

// notRunOfCheckNine runs the library on a request case with no delegation (and with the OpenPGP primaries when the
// case is of that type) and returns the rules that check 9 did not run.
func notRunOfCheckNine(t *testing.T, id string) []string {
	t.Helper()
	m := crqManifestOf(t)
	c := m.byID(t, id)
	cfg := m.Configs[c.Config]
	p := handoff.Policy{MinFirmware: cfg.MinFirmware, ValidityMonths: cfg.ValidityMonths}
	for _, s := range cfg.Stores {
		p.Stores = append(p.Stores, handoff.Store(s))
	}
	for _, s := range cfg.PINPolicy {
		p.PINPolicies = append(p.PINPolicies, handoff.PINPolicy(s))
	}
	clock := m.clock(t)
	hc := handoff.Config{Policy: p, Roots: crqRoots(t, m), Now: func() time.Time { return clock }}
	if c.Type == "openpgp-subkey" {
		hc.Primaries = openPGPPrimariesOf(t)
	}
	checker, err := handoff.New(hc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := crqCheckWith(t, checker, c)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	if v.Accepted() || v.Refused() || len(v.Checks) != 9 {
		t.Fatalf("%s: the verdict is accepted %v, refused %v, with %d checks", id, v.Accepted(), v.Refused(), len(v.Checks))
	}
	for _, ch := range v.Checks[:8] {
		if ch.Status != handoff.StatusPassed || len(ch.NotRun) != 0 {
			t.Fatalf("%s: check %d is %s with %v: the request did not reach check 9 whole", id, ch.N, ch.Status, ch.NotRun)
		}
	}
	if v.Checks[8].Status != handoff.StatusNotRun || len(v.Checks[8].NotRun) == 0 {
		t.Fatalf("%s: check 9 is %s with %v, want not-run with rules named", id, v.Checks[8].Status, v.Checks[8].NotRun)
	}
	return v.Checks[8].NotRun
}

func crqCheckWith(t *testing.T, checker *handoff.Checker, c crqCase) (handoff.Verdict, error) {
	t.Helper()
	root, err := fsx.OpenFS(testrepo.Path(t, crqVectorsDir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	req, err := handoff.LoadRequest(root, "requests", c.stem(t))
	if err != nil {
		t.Fatalf("the case %s: %v", c.ID, err)
	}
	return checker.Check(context.Background(), req)
}

// The command holds one list of the rules that check 9 leaves out for want of a delegation. The library does not
// export its own, so the list is compared here with what the library returns for each type of request that reaches
// check 9 with no delegation: every name the library gives is in the list, and every name of the list is given for
// one type. A name that the library adds or drops makes this test fail.
func TestTheDelegationRulesOfTheCommandAreExactlyTheNamesThatTheLibraryLeavesOut(t *testing.T) {
	x509 := notRunOfCheckNine(t, "x509-software-valid")
	pgp := notRunOfCheckNine(t, "pgp-software-valid")
	if !slices.Equal(slices.Sorted(slices.Values(x509)), []string{"delegation-type", "name-constraints"}) {
		t.Errorf("an x509-intermediate request: the library leaves out %v", x509)
	}
	if !slices.Equal(slices.Sorted(slices.Values(pgp)), []string{"capability", "delegation-type"}) {
		t.Errorf("an openpgp-subkey request: the library leaves out %v", pgp)
	}
	union := map[string]bool{}
	for _, names := range [][]string{x509, pgp} {
		for _, n := range names {
			if !slices.Contains(delegationRules, n) {
				t.Errorf("the library leaves out %q and the command does not know it", n)
			}
			union[n] = true
		}
	}
	for _, n := range delegationRules {
		if !union[n] {
			t.Errorf("the command lists %q and the library leaves out no such rule for any type that it judges", n)
		}
	}
	if len(delegationRules) != len(union) {
		t.Errorf("the command lists %v, the library leaves out %d names", delegationRules, len(union))
	}
}

// Each type's own set is "delegation only" for the command, and so the sentence says to give a delegation.
func TestAnOpenPGPRequestThatCheckNineCannotRunForWantOfADelegationSaysToGiveOne(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []string
	}{
		{"the rules of an openpgp-subkey request", []string{"delegation-type", "capability"}},
		{"the rules in the other order", []string{"capability", "delegation-type"}},
		{"the capability alone", []string{"capability"}},
		{"the rules of an x509-intermediate request", []string{"delegation-type", "name-constraints"}},
		{"all three", []string{"delegation-type", "name-constraints", "capability"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verdictOf(passed(8)...)
			v.Checks[8].NotRun = tc.rules
			list := strings.Join(tc.rules, ", ")
			res, err := requestOutcome("stem", "", v)
			nj := notJudgedOf(t, res, err)
			if want := "request stem is not accepted and not refused: check 9 needs a delegation; give --delegation NAME"; err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
			if want := "check 9: rules not run: " + list + "; give --delegation NAME"; fmt.Sprint(warningsOf(err)) != fmt.Sprint([]string{want}) {
				t.Errorf("warnings = %v, want [%q]", warningsOf(err), want)
			}
			if !strings.HasSuffix(nj.text, "request stem: not complete: check 9 needs a delegation; give --delegation NAME\n") {
				t.Errorf("text = %q", nj.text)
			}
			// With a delegation named the same rules did not run for another reason: no hint, the rules are named.
			res, err = requestOutcome("stem", "d", v)
			_ = notJudgedOf(t, res, err)
			if want := "request stem is not accepted and not refused: check 9 did not run these rules: " + list; err.Error() != want {
				t.Errorf("with a delegation: error = %q, want %q", err.Error(), want)
			}
			if w := warningsOf(err); len(w) != 1 || strings.Contains(w[0], "give --delegation") {
				t.Errorf("with a delegation: warnings = %v, want one with no hint", w)
			}
		})
	}
}

func TestARuleThatIsNotOneOfTheDelegationRulesIsNotTakenForOne(t *testing.T) {
	for _, tc := range []struct {
		rules []string
		want  bool
	}{
		{[]string{"capability"}, true},
		{[]string{"capability", "capability"}, true},
		{[]string{"capability", "primaries"}, false},
		{[]string{"capabilities"}, false},
		{[]string{"Capability"}, false},
		{[]string{"capability "}, false},
		{[]string{"capability\x00"}, false},
		{[]string{""}, false},
		{nil, false},
		{[]string{}, false},
	} {
		if got := onlyDelegationRules(handoff.CheckResult{N: 9, NotRun: tc.rules}); got != tc.want {
			t.Errorf("onlyDelegationRules(%q) = %v, want %v", tc.rules, got, tc.want)
		}
	}
}

// ---- point 3: a repeated --delegation ------------------------------------------------------------------------

const repeatedDelegationSentence = "--delegation is given once: it names the one delegation to check the request under"

func TestARepeatedDelegationFlagIsAUsageErrorInBothModesAndReadsNothing(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	dir := crqBundle(t, m, c)
	stem := c.stem(t)
	gone := t.TempDir() + "/nosuch"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"the same name twice", []string{"--delegation", crqDelegation, "--delegation", crqDelegation}},
		{"two names", []string{"--delegation", crqDelegation, "--delegation", "other"}},
		{"two names, the first one is the good one", []string{"--delegation", "other", "--delegation", crqDelegation}},
		{"with equals signs", []string{"--delegation=" + crqDelegation, "--delegation=other"}},
		{"an equals sign and a word", []string{"--delegation=" + crqDelegation, "--delegation", crqDelegation}},
		{"three times", []string{"--delegation", "a", "--delegation", "b", "--delegation", "c"}},
		{"the first one empty", []string{"--delegation", "", "--delegation", crqDelegation}},
		{"the second one empty", []string{"--delegation", crqDelegation, "--delegation", ""}},
		{"a name that is not valid, twice", []string{"--delegation", "Acme", "--delegation", "a_b"}},
	} {
		for _, where := range []string{"after the stem", "before the stem", "around the stem"} {
			args := slices.Clone(tc.args)
			switch where {
			case "after the stem":
				args = append([]string{stem}, args...)
			case "around the stem":
				args = append(args[:2:2], append([]string{stem}, args[2:]...)...)
			default:
				args = append(args, stem)
			}
			for _, target := range []string{dir, gone} {
				full := append([]string{"check", "request"}, args...)
				full = append(full, "--dir", target)
				before := crqSnapshot(t, dir)
				text := crqRun(t, now, full...)
				js := crqRun(t, now, append([]string{"--output", "json"}, full...)...)
				for _, r := range []result{text, js} {
					if r.code != ExitUsage {
						t.Fatalf("%s, %s, %v: exit code %d\n%s%s", tc.name, where, target == gone, int(r.code), r.stdout, r.stderr)
					}
					if !strings.HasPrefix(r.stderr, "ritueel: "+repeatedDelegationSentence+"\n") {
						t.Errorf("%s, %s: standard error = %q, want the sentence of the repeated flag", tc.name, where, r.stderr)
					}
				}
				if text.stdout != "" {
					t.Errorf("%s: text mode: standard output = %q", tc.name, text.stdout)
				}
				obj := object(t, js.stdout)
				wantObject(t, obj, map[string]any{"output": 1, "command": "check", "exit_code": 2, "outcome": "usage", "error": repeatedDelegationSentence})
				if _, ok := obj["checks"]; ok {
					t.Errorf("a usage error has checks: %s", js.stdout)
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			}
		}
	}
}

// The neighbours: one --delegation is what it was. A good name accepts, a name with no file is exit code 1 that names
// the file, and no --delegation is the run with no delegation.
func TestOneDelegationFlagIsAsItWas(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	dir := crqBundle(t, m, c)
	stem := c.stem(t)
	for _, js := range [][]string{nil, {"--output", "json"}} {
		r := crqRun(t, now, append(js, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir)...)
		if r.code != ExitOK {
			t.Errorf("one good delegation: exit code %d\n%s%s", int(r.code), r.stdout, r.stderr)
		}
		r = crqRun(t, now, append(js, "check", "request", stem, "--delegation=nosuch", "--dir", dir)...)
		if r.code != ExitFailure || !strings.Contains(r.stderr, "want/delegations/nosuch.yaml") {
			t.Errorf("one missing delegation: (%d, %q)", int(r.code), r.stderr)
		}
		r = crqRun(t, now, append(js, "check", "request", stem, "--dir", dir)...)
		if r.code != ExitFailure || !strings.Contains(r.stderr, "check 9 needs a delegation; give --delegation NAME") {
			t.Errorf("no delegation: (%d, %q)", int(r.code), r.stderr)
		}
	}
}

// FlagCount: how many times the flag was given; a name that the word does not declare is a mistake of the
// programmer, like the other accessors.
func TestFlagCountCountsTheTimesAFlagWasGiven(t *testing.T) {
	var got []int
	withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf("x", "y"), run: func(_ context.Context, c *Call) (*Result, error) {
		got = append(got, c.FlagCount("x"), c.FlagCount("y"))
		return &Result{Text: "ok\n"}, nil
	}})
	for _, tc := range []struct {
		args []string
		want []int
	}{
		{[]string{"fake"}, []int{0, 0}},
		{[]string{"fake", "--x", "a"}, []int{1, 0}},
		{[]string{"fake", "--x", "a", "--x=b"}, []int{2, 0}},
		{[]string{"fake", "--x", "a", "--y", "b", "--x", "c", "--x", "d"}, []int{3, 1}},
		{[]string{"fake", "--x", "", "--x", ""}, []int{2, 0}},
	} {
		got = nil
		if r := run(t, tc.args...); r.code != ExitOK {
			t.Fatalf("%v: (%d, %q)", tc.args, int(r.code), r.stderr)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%v: counts %v, want %v", tc.args, got, tc.want)
		}
	}
	withSpecs(t, spec{name: "fake", usage: "u", flags: flagsOf("x"), run: func(_ context.Context, c *Call) (*Result, error) {
		c.FlagCount("nosuch")
		return &Result{Text: "ok\n"}, nil
	}})
	r := run(t, "fake")
	if r.code != ExitFailure || !strings.Contains(r.stderr, `has no flag "nosuch"`) {
		t.Errorf("a flag that the word does not declare: (%d, %q)", int(r.code), r.stderr)
	}
	func() {
		defer func() {
			msg, _ := recover().(string)
			if !strings.Contains(msg, "holds no command") {
				t.Errorf("a Call with no command: panic = %q", msg)
			}
		}()
		(&Call{}).FlagCount("x")
	}()
}

// ---- point 4: the sentence for a delegation of the type openpgp-subkey -------------------------------------

const otherDelegation = "my-subkey"

// subkeyDelegationBundle is the bundle of an x509 request with a delegation of the type openpgp-subkey under a name.
func subkeyDelegationBundle(t *testing.T, id, name string) (m crqManifest, c crqCase, dir string) {
	t.Helper()
	m = crqManifestOf(t)
	c = m.byID(t, id)
	tree := crqBundleTree(t, m, c)
	tree["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: openpgp\ntest: true\n")
	delete(tree, "want/delegations/"+crqDelegation+".yaml")
	tree["want/delegations/"+name+".yaml"] = []byte("version: 1\ntype: openpgp-subkey\nroot: " + crqRoot + "\ncapability: sign\n")
	dir = t.TempDir()
	crqWrite(t, dir, tree)
	return m, c, dir
}

// An x509 request checked under a delegation of the type openpgp-subkey: the request is not of that type, the
// delegation is. The sentence names the delegation and says that the command cannot give it primaries.
func TestAnX509RequestUnderAnOpenPGPDelegationGetsASentenceThatNamesTheDelegation(t *testing.T) {
	m, c, dir := subkeyDelegationBundle(t, "x509-software-valid", otherDelegation)
	before := crqSnapshot(t, dir)
	want := "request " + c.stem(t) + " is not accepted and not refused: this command cannot judge a request under the delegation " +
		otherDelegation + ", which is of the type openpgp-subkey: it cannot give the checker the OpenPGP primaries, " +
		"because where they are read from is not decided"
	text := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--delegation", otherDelegation, "--dir", dir)
	js := crqRun(t, m.clock(t), "--output", "json", "check", "request", c.stem(t), "--delegation", otherDelegation, "--dir", dir)
	for _, r := range []result{text, js} {
		if r.code != ExitFailure {
			t.Fatalf("exit code %d\n%s%s", int(r.code), r.stdout, r.stderr)
		}
		if r.stderr != "ritueel: "+want+"\n" {
			t.Errorf("standard error = %q, want %q", r.stderr, "ritueel: "+want+"\n")
		}
		if strings.Contains(r.stderr, "openpgp-subkey request") {
			t.Errorf("the sentence calls the request an openpgp-subkey request: %q", r.stderr)
		}
	}
	if text.stdout != "" {
		t.Errorf("text mode: standard output = %q", text.stdout)
	}
	obj := object(t, js.stdout)
	wantObject(t, obj, map[string]any{"output": 1, "command": "check", "exit_code": 1, "outcome": "failed", "error": want})
	for _, k := range []string{"checks", "reasons"} {
		if _, ok := obj[k]; ok {
			t.Errorf("the object has %s: %s", k, js.stdout)
		}
	}
	crqSame(t, "check request", before, crqSnapshot(t, dir))
}

// The sentence is the same for a request of any type that the bundle holds, because the fault is the delegation.
func TestTheSentenceOfAnOpenPGPDelegationDoesNotDependOnTheTypeOfTheRequest(t *testing.T) {
	for _, id := range []string{"x509-software-valid", "x509-csr-bad-signature", "pgp-software-valid", "ssh-software-valid"} {
		t.Run(id, func(t *testing.T) {
			m, c, dir := subkeyDelegationBundle(t, id, otherDelegation)
			r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--delegation", otherDelegation, "--dir", dir)
			want := "ritueel: request " + c.stem(t) + " is not accepted and not refused: this command cannot judge a request under the delegation " + otherDelegation + ", which is of the type openpgp-subkey: "
			if r.code != ExitFailure || !strings.HasPrefix(r.stderr, want) || strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) {
				t.Errorf("(%d, %q), want exit code 1 and one line that starts with %q", int(r.code), r.stderr, want)
			}
		})
	}
}

// The neighbours: an OpenPGP request under a delegation of another type, and under none, keep the sentence about the
// request.
func TestAnOpenPGPRequestKeepsItsOwnSentenceUnderAnotherDelegationAndUnderNone(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	tree := crqBundleTree(t, m, c)
	tree["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: x509\ntest: true\n")
	tree["want/delegations/"+crqDelegation+".yaml"] = []byte("version: 1\ntype: x509-intermediate\nroot: " + crqRoot + "\npermitted_uri_hosts: [example.org]\n")
	dir := t.TempDir()
	crqWrite(t, dir, tree)
	for _, args := range [][]string{{"--delegation", crqDelegation}, nil} {
		r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
		if r.code != ExitFailure || !strings.Contains(r.stderr, primariesText) || strings.Contains(r.stderr, "under the delegation") {
			t.Errorf("%v: (%d, %q), want exit code 1 and the sentence about the request", args, int(r.code), r.stderr)
		}
	}
}

// The error carries the checker's error for errors.Is, and its text does not hold what the library said.
func TestTheErrorOfAnOpenPGPDelegationWrapsTheErrorOfTheChecker(t *testing.T) {
	cause := fmt.Errorf("%w: an openpgp-subkey delegation needs primaries", handoff.ErrConfig)
	err := fmt.Errorf("request stem is not accepted and not refused: %w", delegationPrimariesError{name: otherDelegation, err: cause})
	if !errors.Is(err, handoff.ErrConfig) || !errors.Is(err, cause) {
		t.Errorf("the error does not wrap the checker's error: %v", err)
	}
	if strings.Contains(err.Error(), "needs primaries") || strings.Contains(err.Error(), "\n") {
		t.Errorf("the sentence carries the words of the library: %q", err.Error())
	}
	if code, outcome := ExitFor(err); code != ExitFailure || outcome != OutcomeFailed {
		t.Errorf("exit code %d, outcome %q, want 1 and failed", int(code), outcome)
	}
	if !needsPrimaries(err) {
		t.Errorf("needsPrimaries does not see the error that Checker gave")
	}
	// The name is written by the exact escape of a name; a name that is not valid cannot come here, but a text of a
	// person never reaches a terminal raw.
	hostile := delegationPrimariesError{name: "a b\\c\x1b", err: cause}
	if want := "this command cannot judge a request under the delegation a\\x20b\\\\c\\u001b, which is of the type openpgp-subkey: "; !strings.HasPrefix(hostile.Error(), want) {
		t.Errorf("Error() = %q, want it to start with %q", hostile.Error(), want)
	}
}

// An empty name after --delegation has its own sentence, which says to leave the flag out: the flag is given, so the
// run is not the run with no delegation, and the name is not looked up.
func TestAnEmptyDelegationNameIsAUsageErrorWithItsOwnSentence(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "x509-software-valid")
	dir := crqBundle(t, m, c)
	for _, arg := range [][]string{{"--delegation", ""}, {"--delegation="}} {
		r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--dir", dir}, arg...)...)
		want := "ritueel: --delegation needs a name; leave the flag out to run no delegation rule\n"
		if r.code != ExitUsage || !strings.HasPrefix(r.stderr, want) {
			t.Errorf("%q: (%d, %q), want exit code 2 and %q", arg, int(r.code), r.stderr, want)
		}
	}
}

// The check that is named as the first that did not run is a check that did not run, and not one that failed: a
// verdict with a failed check and a check that did not run after it names the second.
func TestTheFirstCheckThatDidNotRunIsNotACheckThatFailed(t *testing.T) {
	v := verdictOf(handoff.StatusPassed, handoff.StatusFailed, handoff.StatusNotRun)
	err := checkRequestError("stem", v, fmt.Errorf("%w", handoff.ErrNoVerifier))
	if !strings.HasSuffix(err.Error(), " (the first check that did not run is check 3)") {
		t.Errorf("error = %q, want the first check that did not run to be check 3", err.Error())
	}
}
