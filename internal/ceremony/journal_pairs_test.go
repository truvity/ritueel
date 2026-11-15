package ceremony_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// A key is born once for the pair of label and purpose: one label names an X.509 key and an OpenPGP
// primary together (docs/reference/ceremony-record.md, "The birth journal"), so the journal of
// births takes two lines for a label, one for each purpose, and refuses the same pair twice.

func pairLine(t testing.TB, label, purpose string, c byte) []byte {
	t.Helper()
	b, err := (&files.BirthLine{At: ts, Label: label, Purpose: purpose, Store: "software", Place: label + "." + purpose + ".key", PublicKeySHA256: rep(c)}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTheBirthJournalTakesTwoLinesForOneLabelOneForEachPurpose(t *testing.T) {
	b, fl := started(t)
	j := fl.tr.Births()
	for i, l := range [][]byte{pairLine(t, "A", "x509-root", 'a'), pairLine(t, "A", "openpgp-primary", 'b'), pairLine(t, "B", "x509-root", 'c'), pairLine(t, "B", "openpgp-primary", 'd')} {
		if err := j.Append(l); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
	}
	if got := strings.Count(string(b.read("history", name1, "births.jsonl")), "\n"); got != 4 {
		t.Errorf("births.jsonl has %d lines, want 4", got)
	}
}

// The order of the two purposes in the journal is the order of the plan; the journal itself does
// not fix it.
func TestTheBirthJournalTakesThePrimaryBeforeTheX509KeyToo(t *testing.T) {
	_, fl := started(t)
	j := fl.tr.Births()
	if err := j.Append(pairLine(t, "A", "openpgp-primary", 'b')); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(pairLine(t, "A", "x509-root", 'a')); err != nil {
		t.Fatal(err)
	}
}

func TestTheBirthJournalRefusesTheSamePairTwiceAndNamesBothWords(t *testing.T) {
	for _, purpose := range []string{"x509-root", "openpgp-primary", "ssh-ca"} {
		t.Run(purpose, func(t *testing.T) {
			b, fl := started(t)
			j := fl.tr.Births()
			if err := j.Append(pairLine(t, "A", purpose, 'a')); err != nil {
				t.Fatal(err)
			}
			mark := b.r.mark()
			// The same pair with another key, another place and another time is the same pair.
			err := j.Append(pairLine(t, "A", purpose, 'b'))
			if err == nil {
				t.Fatal("the pair was born twice")
			}
			wantKind(t, err, ceremony.ErrInvalidInput)
			for _, w := range []string{"A", purpose, "twice"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the error %q does not hold %q", err, w)
				}
			}
			if got := b.r.since(mark); len(got) != 0 {
				t.Errorf("a refused line reached the file system: %v", got)
			}
			if got := strings.Count(string(b.read("history", name1, "births.jsonl")), "\n"); got != 1 {
				t.Errorf("births.jsonl has %d lines, want 1", got)
			}
			// The journal is not stopped by a refusal: another purpose of the label and another
			// label are still taken.
			if err := j.Append(pairLine(t, "B", purpose, 'c')); err != nil {
				t.Errorf("another label after the refusal: %v", err)
			}
		})
	}
}

// A refused line leaves nothing behind that makes a later good line fail: the pair stays free.
func TestAPairThatWasRefusedForItsFormStaysFree(t *testing.T) {
	_, fl := started(t)
	j := fl.tr.Births()
	bad := strings.Replace(string(pairLine(t, "A", "openpgp-primary", 'b')), rep('b'), "xyz", 1)
	if err := j.Append([]byte(bad)); err == nil {
		t.Fatal("a line with a bad digest was written")
	}
	if err := j.Append(pairLine(t, "A", "openpgp-primary", 'b')); err != nil {
		t.Fatalf("the pair after a refused line: %v", err)
	}
}

func TestTheBirthJournalTakesTheMostLinesOfAJournalAndNoMore(t *testing.T) {
	b, fl := started(t)
	j := fl.tr.Births()
	n := 0
	for p := 0; p < 8 && n < files.MaxJournalLines; p++ {
		for l := 0; l < 26 && n < files.MaxJournalLines; l++ {
			if err := j.Append(pairLine(t, string(rune('A'+l)), fmt.Sprintf("purpose-%d", p), 'a')); err != nil {
				t.Fatalf("line %d: %v", n+1, err)
			}
			n++
		}
	}
	if n != 190 {
		t.Fatalf("%d lines were written", n)
	}
	mark := b.r.mark()
	err := j.Append(pairLine(t, "A", "purpose-9", 'a'))
	if err == nil {
		t.Fatal("the 191st line was written")
	}
	wantKind(t, err, ceremony.ErrInvalidInput)
	if !strings.Contains(err.Error(), "190") {
		t.Errorf("the error does not say the limit: %v", err)
	}
	if got := b.r.since(mark); len(got) != 0 {
		t.Errorf("the 191st line reached the file system: %v", got)
	}
	if got := strings.Count(string(b.read("history", name1, "births.jsonl")), "\n"); got != 190 {
		t.Errorf("births.jsonl has %d lines", got)
	}
}

// Two goroutines that give the same pair at once: one line is written and one is refused, whatever
// the order. They start behind a closed channel and are joined; nothing waits for luck.
func TestTwoLinesOfOnePairAtOnceWriteOneAndRefuseOne(t *testing.T) {
	for _, purpose := range []string{"x509-root", "openpgp-primary"} {
		t.Run(purpose, func(t *testing.T) {
			b, fl := started(t)
			j := fl.tr.Births()
			errs := make([]error, 2)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range errs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					errs[i] = j.Append(pairLine(t, "A", purpose, byte('a'+i)))
				}()
			}
			close(start)
			wg.Wait()
			ok := 0
			for _, err := range errs {
				if err == nil {
					ok++
				}
			}
			if ok != 1 {
				t.Fatalf("%d lines were taken: %v", ok, errs)
			}
			if got := strings.Count(string(b.read("history", name1, "births.jsonl")), "\n"); got != 1 {
				t.Errorf("births.jsonl has %d lines, want 1", got)
			}
		})
	}
}

// The journal of signatures knows no pair: it takes the lines of its numbers whatever the keys.
func TestTheJournalOfSignaturesTakesTheFingerprintOfAPrimaryAndThePinOfAnX509Key(t *testing.T) {
	_, fl := started(t)
	j := fl.tr.Signatures()
	lines := []struct {
		kind, key string
	}{
		{"root-certificate", rep('a')}, {"root-removal", rep('a')},
		{"primary-self-signature", strings.Repeat("c", 40)}, {"primary-revocation", strings.Repeat("c", 40)},
		{"primary-revocation", strings.Repeat("c", 40)}, {"root-list", rep('a')},
	}
	for i, l := range lines {
		if err := j.Append(sigBytes(t, int64(i+1), l.kind, l.key)); err != nil {
			t.Fatalf("line %d (%s): %v", i+1, l.kind, err)
		}
	}
}

// The purposes of the page for a key of a label are x509-root, openpgp-primary and ssh-break-glass
// (docs/reference/cards.md): the journal takes the three for one label, one line each.
func TestTheBirthJournalTakesTheThreePurposesOfThePageForOneLabel(t *testing.T) {
	_, fl := started(t)
	j := fl.tr.Births()
	for i, purpose := range []string{"x509-root", "openpgp-primary", "ssh-break-glass"} {
		if err := j.Append(pairLine(t, "A", purpose, byte('a'+i))); err != nil {
			t.Fatalf("%s: %v", purpose, err)
		}
	}
	for _, purpose := range []string{"x509-root", "openpgp-primary", "ssh-break-glass"} {
		if err := j.Append(pairLine(t, "A", purpose, 'f')); err == nil {
			t.Errorf("%s was born twice", purpose)
		}
	}
}

func TestCheckJournalsTakesThreeBirthsForOneLabelWithAPinForEach(t *testing.T) {
	p := tkPlanOut(append(twoBirths(), ceremony.PlanBirth{Label: "A", Purpose: "ssh-break-glass", Store: "software", Place: "A.ssh.key"})...)
	pins := map[string]string{"A": rep('a'), "A/openpgp-primary": rep('b'), "A/ssh-break-glass": rep('c')}
	b := birthLines(t, p, func(i int) string { return []string{rep('a'), rep('b'), rep('c')}[i] })
	if err := ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{}); err != nil {
		t.Fatalf("CheckJournals: %v", err)
	}
	delete(pins, "A/ssh-break-glass")
	mkWantArtifactError(t, ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{}), "journals", "births.jsonl")
}
