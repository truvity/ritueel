package ceremony

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/wanted"
)

// The parts of the birth of a software test root that are not exported: the table of kinds, the
// store that was not made by its constructor, the writing of errors, and the small readers of the
// checks.

func TestTheTableOfKindsHoldsTheX509RootAndNothingElse(t *testing.T) {
	if len(rootKinds) != 1 {
		t.Fatalf("the table has %d kinds, want 1", len(rootKinds))
	}
	if _, ok := rootKinds[wanted.RootX509]; !ok {
		t.Fatal("the table has no X.509 kind")
	}
	for _, k := range []wanted.RootKind{wanted.RootOpenPGP, wanted.RootSSH, "", "x509 ", "X509"} {
		if _, ok := rootKinds[k]; ok {
			t.Errorf("the table has the kind %q", k)
		}
	}
}

func TestARootOfAKindThatIsNotInTheTableIsNotBuiltAndNoKeyIsMade(t *testing.T) {
	for _, kind := range []string{"openpgp", "ssh"} {
		root, err := wanted.ParseRoot(kind, []byte("version: 1\nkind: "+kind+"\ntest: true\n"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = MakeRoots(context.Background(), MakeIn{Root: root})
		if !errors.Is(err, ErrNotBuilt) {
			t.Errorf("%s: MakeRoots = %v, want ErrNotBuilt", kind, err)
		}
	}
	// A root that its reader did not make, and a nil root, are refused as input.
	for name, root := range map[string]*wanted.Root{"nil": nil, "zero": {}, "kind only": {Kind: wanted.RootX509, Test: true}} {
		_, err := MakeRoots(context.Background(), MakeIn{Root: root})
		var me *MakeError
		if !errors.As(err, &me) || me.Step != "input" {
			t.Errorf("%s root: MakeRoots = %v, want a MakeError of the step input", name, err)
		}
	}
	var nilCtx context.Context
	if _, err := MakeRoots(nilCtx, MakeIn{}); err == nil {
		t.Error("a nil context is accepted")
	}
}

func TestAStoreThatTheConstructorDidNotMakeUsesNoKeyAndSaysSo(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]*softwareStore{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if err := s.Refuse(ctx); err == nil {
				t.Error("Refuse succeeds")
			}
			if k, err := s.Birth(ctx, "A"); err == nil || k != nil {
				t.Errorf("Birth = %v, %v", k, err)
			}
			if err := s.SaveRemoval("A", []byte("a.b.c")); err == nil {
				t.Error("SaveRemoval succeeds")
			}
			if _, err := s.ReadRemoval(ctx, "A"); err == nil {
				t.Error("ReadRemoval succeeds")
			}
			if err := s.Close(); err != nil {
				t.Errorf("Close = %v", err)
			}
			if s.Kind() != keystore.KindSoftware || !s.Copyable() {
				t.Error("Kind and Copyable say something else")
			}
		})
	}
}

func TestAMakeErrorSaysItsStepAndReasonInPrintableAsciiOnce(t *testing.T) {
	var nilErr *MakeError
	if nilErr.Error() == "" || nilErr.Unwrap() != nil {
		t.Errorf("a nil MakeError says %q and unwraps to %v", nilErr.Error(), nilErr.Unwrap())
	}
	cause := errors.New("bad é\n\x1b[31m text")
	e := makeErr("births", cause, "the key %s was not born", "A")
	if e.Step != "births" || !strings.HasPrefix(e.Reason, "the key A was not born: ") {
		t.Errorf("step %q reason %q", e.Step, e.Reason)
	}
	for i := 0; i < len(e.Error()); i++ {
		if c := e.Error()[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("the text %+q is not printable ASCII", e.Error())
		}
	}
	if !errors.Is(e, cause) || !strings.HasPrefix(e.Error(), "make births: ") {
		t.Errorf("Is = %v, text %q", errors.Is(e, cause), e.Error())
	}
	if got := makeErr("input", nil, "no cause"); got.Reason != "no cause" || got.Unwrap() != nil {
		t.Errorf("no cause: %+v", got)
	}
	long := makeErr("x", errors.New(strings.Repeat("y", 5000)), "long")
	if len(long.Error()) > 2000 {
		t.Errorf("a cause of 5000 characters gives a text of %d", len(long.Error()))
	}
	// A cause whose text method panics gives a text and no crash.
	if got := makeErr("x", panicErr{}, "boom"); !strings.Contains(got.Error(), "boom") {
		t.Errorf("a cause that panics: %q", got.Error())
	}
}

type panicErr struct{}

func (panicErr) Error() string { panic("the text of the error panics") }

func TestGuardTurnsAPanicIntoAnErrorAndPassesAnErrorOn(t *testing.T) {
	if err := guard("thing", func() error { panic("x") }); err == nil || !strings.Contains(err.Error(), "thing") {
		t.Errorf("a panic: %v", err)
	}
	want := errors.New("plain")
	if err := guard("thing", func() error { return want }); !errors.Is(err, want) {
		t.Errorf("an error: %v", err)
	}
	if err := guard("thing", func() error { return nil }); err != nil {
		t.Errorf("no error: %v", err)
	}
}

func TestIsNilValueSeesTypedNils(t *testing.T) {
	var p *int
	var m map[string]int
	var s []int
	var f func()
	var c chan int
	var e error
	for name, v := range map[string]any{"nil": nil, "pointer": p, "map": m, "list": s, "func": f, "chan": c, "interface": e} {
		if !isNilValue(v) {
			t.Errorf("%s is not seen as nil", name)
		}
	}
	x := 1
	for name, v := range map[string]any{"pointer": &x, "int": 0, "string": "", "struct": struct{}{}, "list": []int{}, "map": map[string]int{}} {
		if isNilValue(v) {
			t.Errorf("%s is seen as nil", name)
		}
	}
}

func TestMonthsAreAddedByTheRuleOfThePageAndAgreeWithPki(t *testing.T) {
	for _, tc := range []struct {
		from string
		n    int
		want string
	}{
		{"2026-11-20T10:00:00Z", 36, "2029-11-20T10:00:00Z"},
		{"2028-02-29T23:59:59Z", 36, "2031-02-28T23:59:59Z"},
		{"2028-02-29T00:00:00Z", 12, "2029-02-28T00:00:00Z"},
		{"2028-02-29T00:00:00Z", 48, "2032-02-29T00:00:00Z"},
		{"2026-01-31T00:00:00Z", 1, "2026-02-28T00:00:00Z"},
		{"2028-01-31T00:00:00Z", 1, "2028-02-29T00:00:00Z"},
		{"2026-03-31T05:06:07Z", 1, "2026-04-30T05:06:07Z"},
		{"2026-05-31T05:06:07Z", 13, "2027-06-30T05:06:07Z"},
		{"2026-12-15T00:00:00Z", 1, "2027-01-15T00:00:00Z"},
		{"2026-12-31T00:00:00Z", 13, "2028-01-31T00:00:00Z"},
		{"2026-11-20T10:00:00Z", 13, "2027-12-20T10:00:00Z"},
		{"2026-01-01T00:00:00Z", 0, "2026-01-01T00:00:00Z"},
		{"2026-10-31T00:00:00Z", 36, "2029-10-31T00:00:00Z"},
		{"2026-10-30T00:00:00Z", 4, "2027-02-28T00:00:00Z"},
	} {
		from, err := time.Parse(time.RFC3339, tc.from)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := time.Parse(time.RFC3339, tc.want)
		if got := addMonthsClamped(from, tc.n); !got.Equal(want) || got.Location() != time.UTC {
			t.Errorf("%s + %d months = %s, want %s", tc.from, tc.n, got.Format(time.RFC3339), tc.want)
		}
		if got, err := pki.AddMonths(from, tc.n); err != nil || !got.Equal(want) {
			t.Errorf("pki: %s + %d months = %v, %v", tc.from, tc.n, got, err)
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		from := time.Unix(r.Int64N(4_000_000_000), 0).UTC()
		n := []int{13, 36}[i%2]
		got := addMonthsClamped(from, n)
		want, err := pki.AddMonths(from, n)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%s + %d months: %s here, %s and %v in pki", from.Format(time.RFC3339), n, got.Format(time.RFC3339), want.Format(time.RFC3339), err)
		}
	}
	// A time in another zone is read in UTC.
	z := time.FixedZone("x", 5*3600)
	if got := addMonthsClamped(time.Date(2026, 11, 20, 3, 0, 0, 0, z), 36); !got.Equal(time.Date(2029, 11, 19, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("a zone: %s", got)
	}
}

func TestACompactTextIsOfTheAlphabetOfAJWSAndNothingElse(t *testing.T) {
	for _, s := range []string{"", "a", "a.b.c", "A-Z_a-z0-9.", "eyJhbGciOiJFUzM4NCJ9.e30.c2ln"} {
		if !isCompactText(s) {
			t.Errorf("%q is refused", s)
		}
	}
	for _, s := range []string{"a b", "a\n", "a=", "a+b", "a/b", "é", "a\x00", "a,b", "\"", "a\\b", "a:b", " "} {
		if isCompactText(s) {
			t.Errorf("%q is accepted", s)
		}
	}
}

func TestAPinIsSixtyFourLowerCaseHexDigits(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if !isPin(good) {
		t.Fatal("a pin is refused")
	}
	for _, s := range []string{"", good[:63], good + "0", strings.ToUpper(good), strings.Repeat("g", 64), good[:63] + " ", good[:63] + "\n", good[:63] + "G", " " + good[1:]} {
		if isPin(s) {
			t.Errorf("%q is accepted", s)
		}
	}
}

func TestATimeOfThePlanIsOneSecondInUTCAndNothingElse(t *testing.T) {
	want := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	got, err := parseTime("2026-11-20T10:00:00Z")
	if err != nil || !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("parseTime = %v, %v", got, err)
	}
	for _, s := range []string{
		"", "2026-11-20T10:00:00", "2026-11-20T10:00:00z", "2026-11-20t10:00:00Z", "2026-11-20 10:00:00Z",
		"2026-11-20T10:00:00.5Z", "2026-11-20T10:00:00+00:00", "2026-11-20T11:00:00+01:00", "2026-11-31T10:00:00Z",
		"2026-13-20T10:00:00Z", "2026-11-20T24:00:00Z", "2026-11-20T10:60:00Z", "2026-11-20T10:00:60Z", " 2026-11-20T10:00:00Z",
		"2026-11-20T10:00:00Z ", "2026-11-20T10:00:00Z\n", "26-11-20T10:00:00Z", "٢026-11-20T10:00:00Z",
	} {
		if got, err := parseTime(s); err == nil {
			t.Errorf("%q is accepted as %s", s, got)
		}
	}
}

func TestThePathOfARootJSONIsRootsLabelRootJSON(t *testing.T) {
	for _, l := range []string{"A", "B", "Z"} {
		if got, want := rootJSONPath(l), "roots/"+l+"/root.json"; got != want {
			t.Errorf("rootJSONPath(%s) = %q, want %q", l, got, want)
		}
	}
	if rootsDir != "roots" || trustDir != "trust" {
		t.Errorf("the folders are %q and %q", rootsDir, trustDir)
	}
}

func TestAnArtifactErrorEscapesWhatItIsGiven(t *testing.T) {
	e := artifactErr("root certificate A\n", "mem\x1bber", "reason é %s", "x\ty")
	for _, s := range []string{e.Artifact, e.Member, e.Reason, e.Error()} {
		if s != jsonset.Escape(s) || strings.ContainsAny(s, "\n\t\x1b") {
			t.Errorf("%q is not escaped", s)
		}
	}
	var nilErr *ArtifactError
	if nilErr.Error() == "" {
		t.Error("a nil ArtifactError says nothing")
	}
	got := slices.Compact([]string{CheckedRootCertificate, CheckedRemovalAuthorisation, CheckedRootList, CheckedCABundle, CheckedRootJSON, CheckedPlan, CheckedJournals})
	if len(got) != 7 {
		t.Errorf("the seven words of the checks are not seven different words: %v", got)
	}
}
