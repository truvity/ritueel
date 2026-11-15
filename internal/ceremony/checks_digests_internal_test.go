package ceremony

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The journal of signatures holds, for each signature, the digest of the signature that was made. The
// check compares that digest with the digest of the signature in the artifact that the line stands
// for: the DER value in the certificate, the 96 bytes of the removal authorisation and of the list.
// The key of each signature that was made is the pin of the key that was born for its subject. Both
// are judged by code that did not make the artifact, before any artifact is returned.

// withDigest is the line with the digest of its signature changed.
func withDigest(t *testing.T, line []byte, digest string) []byte {
	t.Helper()
	l, err := files.ReadSignatureLine(line)
	if err != nil {
		t.Fatal(err)
	}
	l.SignatureSHA256 = digest
	out, err := l.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// digestOf is the digest that a line holds.
func digestOf(t *testing.T, line []byte) string {
	t.Helper()
	l, err := files.ReadSignatureLine(line)
	if err != nil {
		t.Fatal(err)
	}
	return l.SignatureSHA256
}

// flipped is a digest that differs from d in its last digit.
func flipped(d string) string {
	last := d[len(d)-1]
	if last == '0' {
		return d[:len(d)-1] + "1"
	}
	return d[:len(d)-1] + "0"
}

func wantJournalsError(t *testing.T, err error, line string) {
	t.Helper()
	var ae *ArtifactError
	ok := errors.As(err, &ae)
	if !ok {
		t.Fatalf("the error is %T (%v), want an *ArtifactError", err, err)
	}
	if ae.Artifact != "journals" || ae.Member != "signatures.jsonl" {
		t.Fatalf("the error names %q / %q, want journals / signatures.jsonl: %v", ae.Artifact, ae.Member, err)
	}
	if line != "" && !strings.Contains(err.Error(), "line "+line) {
		t.Errorf("the error does not name the line %s: %v", line, err)
	}
}

func TestTheDigestsOfTheLinesOfARunAreTheDigestsOfItsSignatures(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	if len(sigs.Lines) != 5 {
		t.Fatalf("%d signature lines", len(sigs.Lines))
	}
	if err := CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, sigs); err != nil {
		t.Fatalf("CheckSignatureDigests: %v", err)
	}
	// The five digests are five different values.
	seen := map[string]bool{}
	for _, l := range sigs.Lines {
		seen[digestOf(t, l)] = true
	}
	if len(seen) != 5 {
		t.Errorf("the five signatures have %d digests", len(seen))
	}
}

func TestALineWhoseDigestIsNotTheDigestOfItsSignatureIsRefusedForEachKind(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	kinds := []string{kindRootCertificate, kindRootRemoval, kindRootCertificate, kindRootRemoval, kindRootList}
	empty := sha256.Sum256(nil)
	for i, kind := range kinds {
		own := digestOf(t, sigs.Lines[i])
		other := digestOf(t, sigs.Lines[(i+1)%5])
		for name, digest := range map[string]string{
			"the last digit changed":           flipped(own),
			"the digest of the next line":      other,
			"the digest of nothing":            hex.EncodeToString(empty[:]),
			"the digest of the line's own key": m.pins[m.plan.Signatures[i].Subject],
		} {
			t.Run(kind+" "+string(rune('1'+i))+" "+name, func(t *testing.T) {
				lines := slices.Clone(sigs.Lines)
				lines[i] = withDigest(t, lines[i], digest)
				err := CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines})
				wantJournalsError(t, err, string(rune('1'+i)))
			})
		}
	}
}

func TestARemovalLineThatHoldsTheDigestOfTheCertificateSignatureIsRefused(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	for _, tc := range []struct {
		name     string
		from, to int
	}{
		{"the removal of A holds the certificate of A", 1, 0},
		{"the certificate of A holds the removal of A", 0, 1},
		{"the removal of B holds the certificate of B", 3, 2},
		{"the certificate of B holds the certificate of A", 2, 0},
		{"the removal of B holds the removal of A", 3, 1},
		{"the list holds the certificate of A", 4, 0},
		{"the list holds the removal of B", 4, 3},
		{"the certificate of A holds the list", 0, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := slices.Clone(sigs.Lines)
			lines[tc.from] = withDigest(t, lines[tc.from], digestOf(t, sigs.Lines[tc.to]))
			err := CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines})
			wantJournalsError(t, err, string(rune('1'+tc.from)))
		})
	}
}

func TestTheDigestsAreJudgedWhateverTheLineThatIsWrongInTheMiddleOrAtTheEnd(t *testing.T) {
	// Only the last line is wrong: the check does not stop at the first lines that are right.
	m := stagedMaker(t)
	lines := slices.Clone(m.tap.signatures.read().Lines)
	lines[4] = withDigest(t, lines[4], flipped(digestOf(t, lines[4])))
	wantJournalsError(t, CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines}), "5")
	// Only the first line is wrong.
	lines = slices.Clone(m.tap.signatures.read().Lines)
	lines[0] = withDigest(t, lines[0], flipped(digestOf(t, lines[0])))
	wantJournalsError(t, CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines}), "1")
}

func TestTheArtifactsThatThisCheckReadsAreHeldToTheLinesOfTheirOwnKind(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	other := stagedMaker(t)
	tooLong := slices.Clone(sigs.Lines)
	tooLong = append(tooLong, sigs.Lines[0])
	cases := []struct {
		name string
		run  func() error
	}{
		{"no plan", func() error { return CheckSignatureDigests(nil, m.certs, m.removal, m.set, sigs) }},
		{"an empty plan", func() error { return CheckSignatureDigests(&PlanOut{}, m.certs, m.removal, m.set, sigs) }},
		{"four lines", func() error {
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: sigs.Lines[:4]})
		}},
		{"six lines", func() error {
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: tooLong})
		}},
		{"no lines", func() error { return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{}) }},
		{"a half line at the end", func() error {
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: sigs.Lines, Partial: []byte(`{"at"`)})
		}},
		{"a line that is not JSON", func() error {
			lines := slices.Clone(sigs.Lines)
			lines[2] = []byte("not json")
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines})
		}},
		{"an empty line", func() error {
			lines := slices.Clone(sigs.Lines)
			lines[0] = nil
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines})
		}},
		{"no trust set", func() error { return CheckSignatureDigests(m.plan, m.certs, m.removal, nil, sigs) }},
		{"the trust set of another run", func() error { return CheckSignatureDigests(m.plan, m.certs, m.removal, other.set, sigs) }},
		{"no certificates", func() error { return CheckSignatureDigests(m.plan, nil, m.removal, m.set, sigs) }},
		{"the certificate of A is missing", func() error {
			return CheckSignatureDigests(m.plan, map[string][]byte{"B": m.certs["B"]}, m.removal, m.set, sigs)
		}},
		{"the certificate of A is the certificate of B", func() error {
			return CheckSignatureDigests(m.plan, map[string][]byte{"A": m.certs["B"], "B": m.certs["B"]}, m.removal, m.set, sigs)
		}},
		{"the certificate of A is not DER", func() error {
			return CheckSignatureDigests(m.plan, map[string][]byte{"A": []byte("x"), "B": m.certs["B"]}, m.removal, m.set, sigs)
		}},
		{"no removal authorisations", func() error { return CheckSignatureDigests(m.plan, m.certs, nil, m.set, sigs) }},
		{"the removal authorisation of A is that of B", func() error {
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": m.removal["B"], "B": m.removal["B"]}, m.set, sigs)
		}},
		{"a removal authorisation of two parts", func() error {
			a := m.removal["A"]
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": a[:strings.LastIndex(a, ".")], "B": m.removal["B"]}, m.set, sigs)
		}},
		{"a removal authorisation of four parts", func() error {
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": m.removal["A"] + ".x", "B": m.removal["B"]}, m.set, sigs)
		}},
		{"a removal authorisation whose signature is not Base64url", func() error {
			a := m.removal["A"]
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": a[:strings.LastIndex(a, ".")+1] + "***", "B": m.removal["B"]}, m.set, sigs)
		}},
		{"a removal authorisation whose signature is empty", func() error {
			a := m.removal["A"]
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": a[:strings.LastIndex(a, ".")+1], "B": m.removal["B"]}, m.set, sigs)
		}},
		{"a kind that the check does not know", func() error {
			q := *m.plan
			q.Signatures = slices.Clone(m.plan.Signatures)
			q.Signatures[1].Kind = "something-else"
			return CheckSignatureDigests(&q, m.certs, m.removal, m.set, sigs)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.As(err, new(*ArtifactError)) {
				t.Fatalf("the error is %T (%v), want an *ArtifactError", err, err)
			}
			if !strings.HasPrefix(err.Error(), "artifact check journals") && !strings.Contains(err.Error(), "journals") {
				t.Errorf("the error does not name the journals: %v", err)
			}
		})
	}
}

func TestTheDigestCheckDoesNotChangeItsInput(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	before := make([]string, len(sigs.Lines))
	for i, l := range sigs.Lines {
		before[i] = string(l)
	}
	removal := map[string]string{"A": m.removal["A"], "B": m.removal["B"]}
	_ = CheckSignatureDigests(m.plan, m.certs, removal, m.set, sigs)
	for i, l := range sigs.Lines {
		if string(l) != before[i] {
			t.Errorf("the line %d was changed", i+1)
		}
	}
	if removal["A"] != m.removal["A"] || removal["B"] != m.removal["B"] {
		t.Error("the removal authorisations were changed")
	}
}

// ---- inside a run: the check runs before any artifact is returned ----

func TestARunRefusesALineWhoseDigestIsNotTheDigestOfItsSignatureAndReturnsNoArtifact(t *testing.T) {
	for i, kind := range []string{kindRootCertificate, kindRootRemoval, kindRootCertificate, kindRootRemoval, kindRootList} {
		t.Run(kind+" "+string(rune('1'+i)), func(t *testing.T) {
			m := stagedMaker(t)
			// The line is still whole, in its order and with the pin of its key, so that the check of the
			// journals accepts it and only the digest is wrong.
			m.tap.signatures.lines[i] = withDigest(t, m.tap.signatures.lines[i], flipped(digestOf(t, m.tap.signatures.lines[i])))
			if err := CheckJournals(m.plan, m.pins, m.tap.births.read(), m.tap.signatures.read()); err != nil {
				t.Fatalf("the check of the journals refuses it, so the digest check is not what is tried: %v", err)
			}
			made, err := m.check(context.Background())
			if made != nil {
				t.Fatal("a result comes with a fault")
			}
			wantJournalsError(t, err, string(rune('1'+i)))
		})
	}
}

// ---- the key of each signature that was made is the pin of the key born for its subject ----

func TestARunRefusesASignatureMadeByAnotherKeyThanTheOneBornForItsSubject(t *testing.T) {
	for i := range 5 {
		t.Run(string(rune('1'+i)), func(t *testing.T) {
			m := stagedMaker(t)
			subject := m.plan.Signatures[i].Subject
			var otherPin string
			for _, b := range m.born {
				if b.Label != subject {
					otherPin = b.Pin
				}
			}
			if otherPin == "" || otherPin == m.made[i].Key {
				t.Fatal("no other pin")
			}
			m.made[i].Key = otherPin
			made, err := m.check(context.Background())
			if made != nil {
				t.Fatal("a result comes with a fault")
			}
			var ae *ArtifactError
			ok := errors.As(err, &ae)
			if !ok || ae.Artifact != "plan against the keys" || ae.Member != "signatures" {
				t.Fatalf("the error is %T (%v), want an *ArtifactError of the plan against the keys", err, err)
			}
		})
	}
}

// ---- the plan against the born keys runs before any code reads the list of born keys ----

func TestAListOfBornKeysThatIsNotTheListOfTheLabelsIsAnErrorAndNeverAPanic(t *testing.T) {
	cases := map[string]func(m *x509Maker){
		"one key":            func(m *x509Maker) { m.born = m.born[:1] },
		"no key":             func(m *x509Maker) { m.born = nil },
		"an empty list":      func(m *x509Maker) { m.born = []BornKey{} },
		"three keys":         func(m *x509Maker) { m.born = append(m.born, m.born[0]) },
		"the keys exchanged": func(m *x509Maker) { m.born[0], m.born[1] = m.born[1], m.born[0] },
		"a key under a label that the plan does not list": func(m *x509Maker) { m.born[1].Label = "C" },
		"no signature made":   func(m *x509Maker) { m.made = nil },
		"one signature fewer": func(m *x509Maker) { m.made = m.made[:4] },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			m := stagedMaker(t)
			edit(m)
			var made *Made
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("check panicked: %v", r)
					}
				}()
				made, err = m.check(context.Background())
			}()
			if made != nil {
				t.Fatal("a result comes with a fault")
			}
			var ae *ArtifactError
			ok := errors.As(err, &ae)
			if !ok || ae.Artifact != "plan against the keys" {
				t.Fatalf("the error is %T (%v), want an *ArtifactError of the plan against the keys", err, err)
			}
		})
	}
}

func TestACheckThatFindsTheBornKeysWholeGoesOnAndNamesTheSevenChecksInTheirFixedOrder(t *testing.T) {
	m := stagedMaker(t)
	made, err := m.check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{CheckedRootCertificate, CheckedRemovalAuthorisation, CheckedRootList, CheckedCABundle, CheckedRootJSON, CheckedPlan, CheckedJournals}
	if !slices.Equal(made.Checked, want) {
		t.Fatalf("Checked = %v, want %v", made.Checked, want)
	}
}

// ---- the root of the ceremony record ----

func TestTheRecordsRootIsThePlansRootWithTheFingerprintOfTheKeyBornForIt(t *testing.T) {
	m := stagedMaker(t)
	made, err := m.check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := *m.plan.Plan.Root
	want.X509 = m.pins[want.Label]
	if made.Record != want {
		t.Fatalf("Record = %+v, want %+v", made.Record, want)
	}
	if made.Record.Label != "A" || made.Record.Store != "software" || !made.Record.Test || !made.Record.Copyable || len(made.Record.X509) != 64 {
		t.Errorf("the root of the record: %+v", made.Record)
	}
	if made.Record.OpenPGP != "" {
		t.Errorf("an OpenPGP fingerprint in an X.509 root: %q", made.Record.OpenPGP)
	}
}

func TestARunKeepsAFingerprintThatThePlanGivesWhenItIsThePinAndRefusesAnyOther(t *testing.T) {
	m := stagedMaker(t)
	root := *m.plan.Plan.Root
	root.X509 = m.pins[root.Label]
	m.plan.Plan.Root = &root
	made, err := m.check(context.Background())
	if err != nil || made.Record != root {
		t.Fatalf("a fingerprint that is the pin: %+v, %v", made, err)
	}
	for name, edit := range map[string]func(r *files.PlanRoot){
		"the pin of the other key": func(r *files.PlanRoot) { r.X509 = m.pins["B"] },
		"a digest that is no key":  func(r *files.PlanRoot) { r.X509 = strings.Repeat("ab", 32) },
		"a label with no born key": func(r *files.PlanRoot) { r.Label, r.X509 = "Z", "" },
		"no label":                 func(r *files.PlanRoot) { r.Label, r.X509 = "", "" },
	} {
		t.Run(name, func(t *testing.T) {
			m := stagedMaker(t)
			root := *m.plan.Plan.Root
			edit(&root)
			m.plan.Plan.Root = &root
			made, err := m.check(context.Background())
			if made != nil || err == nil {
				t.Fatalf("a result (%v) and %v for a root that is not the root of the keys", made != nil, err)
			}
			var me *MakeError
			ok := errors.As(err, &me)
			if !ok || me.Step != "checks" {
				t.Fatalf("the error is %T (%v), want a *MakeError of the step checks", err, err)
			}
		})
	}
}

func TestHostileSizesAndShapesAreRefusedByTheDigestCheckAndDoNotCrash(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	big := []byte(`{"at":"` + strings.Repeat("a", 4<<20) + `"}`)
	deep := []byte(strings.Repeat("[", 100000))
	many := make([][]byte, 200000)
	for i := range many {
		many[i] = sigs.Lines[0]
	}
	bigText := strings.Repeat("A", 8<<20)
	cases := map[string]func() error{
		"200000 lines": func() error {
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: many})
		},
		"a line of 4 MiB": func() error {
			l := slices.Clone(sigs.Lines)
			l[2] = big
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: l})
		},
		"a line that is deeply nested": func() error {
			l := slices.Clone(sigs.Lines)
			l[1] = deep
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: l})
		},
		"a half line of 4 MiB": func() error {
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: sigs.Lines, Partial: big})
		},
		"a certificate of 8 MiB": func() error {
			return CheckSignatureDigests(m.plan, map[string][]byte{"A": []byte(bigText), "B": m.certs["B"]}, m.removal, m.set, sigs)
		},
		"a removal authorisation of 8 MiB with no dot": func() error {
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": bigText, "B": m.removal["B"]}, m.set, sigs)
		},
		"a removal authorisation of 8 MiB with two dots": func() error {
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": "a.b." + bigText, "B": m.removal["B"]}, m.set, sigs)
		},
		"a removal authorisation of 100000 dots": func() error {
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": strings.Repeat(".", 100000), "B": m.removal["B"]}, m.set, sigs)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.As(err, new(*ArtifactError)) || len(err.Error()) > 4000 {
				t.Fatalf("the error is %T and %d bytes long", err, len(err.Error()))
			}
		})
	}
}

func TestALineThatHoldsTheDigestOfNothingIsNotTheDigestOfASignatureThatCouldNotBeRead(t *testing.T) {
	// A signature that cannot be read is no signature. If the check took it for empty bytes, a line
	// that holds the digest of nothing would pass for it.
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	nothing := sha256.Sum256(nil)
	empty := hex.EncodeToString(nothing[:])
	a := m.removal["A"]
	head := a[:strings.LastIndex(a, ".")+1]
	cases := map[string]func() error{
		"a removal signature that is not Base64url": func() error {
			lines := slices.Clone(sigs.Lines)
			lines[1] = withDigest(t, lines[1], empty)
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": head + "***", "B": m.removal["B"]}, m.set, JournalRead{Lines: lines})
		},
		"a kind that the check does not know": func() error {
			q := *m.plan
			q.Signatures = slices.Clone(m.plan.Signatures)
			q.Signatures[1].Kind = "something-else"
			lines := slices.Clone(sigs.Lines)
			lines[1] = withDigest(t, lines[1], empty)
			return CheckSignatureDigests(&q, m.certs, m.removal, m.set, JournalRead{Lines: lines})
		},
		"no trust set": func() error {
			lines := slices.Clone(sigs.Lines)
			lines[4] = withDigest(t, lines[4], empty)
			return CheckSignatureDigests(m.plan, m.certs, m.removal, nil, JournalRead{Lines: lines})
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "does not parse") && !strings.Contains(err.Error(), "Base64url") &&
				!strings.Contains(err.Error(), "not one that this check knows") && !strings.Contains(err.Error(), "no trust set") {
				t.Errorf("the error does not say that the signature could not be read: %v", err)
			}
		})
	}
}

func TestWhatIsWrongIsSaidInTheWordsOfItsCause(t *testing.T) {
	m := stagedMaker(t)
	sigs := m.tap.signatures.read()
	for name, tc := range map[string]struct {
		run  func() error
		want string
	}{
		"no trust set": {func() error { return CheckSignatureDigests(m.plan, m.certs, m.removal, nil, sigs) }, "no trust set"},
		"a removal authorisation of two parts": {func() error {
			a := m.removal["A"]
			return CheckSignatureDigests(m.plan, m.certs, map[string]string{"A": a[:strings.LastIndex(a, ".")], "B": m.removal["B"]}, m.set, sigs)
		}, "three parts"},
		"a certificate that does not parse": {func() error {
			return CheckSignatureDigests(m.plan, map[string][]byte{"A": nil, "B": m.certs["B"]}, m.removal, m.set, sigs)
		}, "does not parse"},
		"a digest that is another": {func() error {
			lines := slices.Clone(sigs.Lines)
			lines[0] = withDigest(t, lines[0], flipped(digestOf(t, lines[0])))
			return CheckSignatureDigests(m.plan, m.certs, m.removal, m.set, JournalRead{Lines: lines})
		}, "does not hold the digest"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error is %v, want it to say %q", err, tc.want)
			}
		})
	}
}
