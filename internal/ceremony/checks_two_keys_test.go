package ceremony_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The checks of the keys and the journals when a label names two keys: its X.509 key and its OpenPGP
// primary (docs/reference/ceremony-record.md, "The birth journal"). A key is born once for the pair of
// label and purpose; the pin of the X.509 key is the pin that signs the certificate, the removal
// authorisation and the root list.

func tkPlanOut(births ...ceremony.PlanBirth) *ceremony.PlanOut {
	return &ceremony.PlanOut{SHA256: rep('1'), Births: births}
}

func twoBirths() []ceremony.PlanBirth {
	return []ceremony.PlanBirth{
		{Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem"},
		{Label: "A", Purpose: "openpgp-primary", Store: "software", Place: "A.openpgp.key.asc"},
	}
}

func birthLines(t *testing.T, p *ceremony.PlanOut, pin func(i int) string) ceremony.JournalRead {
	t.Helper()
	var j ceremony.JournalRead
	for i, b := range p.Births {
		line, err := (&files.BirthLine{At: ts, Label: b.Label, Purpose: b.Purpose, Store: b.Store, Place: b.Place, PublicKeySHA256: pin(i)}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		j.Lines = append(j.Lines, line)
	}
	return j
}

func TestCheckJournalsTakesTwoBirthsForOneLabelWithAPinForEach(t *testing.T) {
	p := tkPlanOut(twoBirths()...)
	pins := map[string]string{"A": rep('a'), "A/openpgp-primary": rep('b')}
	b := birthLines(t, p, func(i int) string { return []string{rep('a'), rep('b')}[i] })
	if err := ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{}); err != nil {
		t.Fatalf("CheckJournals: %v", err)
	}
}

func TestCheckJournalsRefusesWhatIsNotTheBirthOfEachPair(t *testing.T) {
	good := func() (*ceremony.PlanOut, map[string]string) {
		return tkPlanOut(twoBirths()...), map[string]string{"A": rep('a'), "A/openpgp-primary": rep('b')}
	}
	pinOf := func(i int) string { return []string{rep('a'), rep('b')}[i] }
	cases := []struct {
		name string
		edit func(p *ceremony.PlanOut, pins map[string]string, b *ceremony.JournalRead)
	}{
		{"no pin for the second key", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) {
			delete(pins, "A/openpgp-primary")
		}},
		{"the pin of the second key is under the label", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) {
			delete(pins, "A/openpgp-primary")
			pins["A"] = rep('b')
		}},
		{"the pin of the first key is under the pair", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) {
			delete(pins, "A")
			pins["A/x509-root"] = rep('a')
		}},
		{"another pin for the second key", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) {
			pins["A/openpgp-primary"] = rep('c')
		}},
		{"another pin for the first key", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) { pins["A"] = rep('c') }},
		{"the two pins swapped", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) {
			pins["A"], pins["A/openpgp-primary"] = rep('b'), rep('a')
		}},
		{"the pin of another purpose", func(_ *ceremony.PlanOut, pins map[string]string, _ *ceremony.JournalRead) {
			delete(pins, "A/openpgp-primary")
			pins["A/openpgp-subkey"] = rep('b')
		}},
		{"the second line is the first again", func(_ *ceremony.PlanOut, _ map[string]string, b *ceremony.JournalRead) {
			b.Lines[1] = b.Lines[0]
		}},
		{"the lines in the other order", func(_ *ceremony.PlanOut, _ map[string]string, b *ceremony.JournalRead) {
			b.Lines[0], b.Lines[1] = b.Lines[1], b.Lines[0]
		}},
		{"the line of the primary has the purpose of the first key", func(_ *ceremony.PlanOut, _ map[string]string, b *ceremony.JournalRead) {
			b.Lines[1] = []byte(strings.Replace(string(b.Lines[1]), "openpgp-primary", "x509-root", 1))
		}},
		{"a line is missing", func(_ *ceremony.PlanOut, _ map[string]string, b *ceremony.JournalRead) { b.Lines = b.Lines[:1] }},
		{"a line is too many", func(_ *ceremony.PlanOut, _ map[string]string, b *ceremony.JournalRead) {
			b.Lines = append(b.Lines, b.Lines[1])
		}},
		{"the plan has the same pair twice and the journal too", func(p *ceremony.PlanOut, pins map[string]string, b *ceremony.JournalRead) {
			p.Births[1] = p.Births[0]
			b.Lines[1] = b.Lines[0]
			pins["A"] = rep('a')
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, pins := good()
			b := birthLines(t, p, pinOf)
			c.edit(p, pins, &b)
			mkWantArtifactError(t, ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{}), "journals", "births.jsonl")
		})
	}
}

func TestCheckJournalsTakesOneBirthForEachOfTwoLabelsAsBefore(t *testing.T) {
	p := tkPlanOut(
		ceremony.PlanBirth{Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem"},
		ceremony.PlanBirth{Label: "B", Purpose: "x509-root", Store: "software", Place: "B.x509.key.pem"},
	)
	pins := map[string]string{"A": rep('a'), "B": rep('b')}
	b := birthLines(t, p, func(i int) string { return []string{rep('a'), rep('b')}[i] })
	if err := ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{}); err != nil {
		t.Fatalf("CheckJournals: %v", err)
	}
	// The same label twice for the same purpose is not a second key.
	p.Births[1] = p.Births[0]
	b = birthLines(t, p, func(i int) string { return rep('a') })
	mkWantArtifactError(t, ceremony.CheckJournals(p, pins, b, ceremony.JournalRead{}), "journals", "births.jsonl")
}

func TestCheckJournalsTakesTheMostLinesOfAJournalAndNoMore(t *testing.T) {
	// 190 signature lines of a plan of 190 signatures of one key are whole; the 191st is another plan.
	p := tkPlanOut(ceremony.PlanBirth{Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem"})
	pins := map[string]string{"A": rep('a')}
	for n := int64(1); n <= int64(files.MaxJournalLines); n++ {
		p.Signatures = append(p.Signatures, ceremony.PlanSignature{N: n, Kind: "root-list", Subject: "A"})
	}
	var sigs ceremony.JournalRead
	for _, s := range p.Signatures {
		line, err := (&files.SignatureLine{At: ts, N: s.N, Kind: s.Kind, Key: rep('a'), SignatureSHA256: rep('5')}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		sigs.Lines = append(sigs.Lines, line)
	}
	births := birthLines(t, p, func(int) string { return rep('a') })
	if err := ceremony.CheckJournals(p, pins, births, sigs); err != nil {
		t.Fatalf("190 lines: %v", err)
	}
	line, err := (&files.SignatureLine{At: ts, N: 190, Kind: "root-list", Key: rep('a'), SignatureSHA256: rep('5')}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	p.Signatures = append(p.Signatures, ceremony.PlanSignature{N: 191, Kind: "root-list", Subject: "A"})
	sigs.Lines = append(sigs.Lines, []byte(strings.Replace(string(line), `"n":190`, `"n":191`, 1)))
	mkWantArtifactError(t, ceremony.CheckJournals(p, pins, births, sigs), "journals", "signatures.jsonl")
}

// ---- the plan against the keys ----

func tkKeys() (*ceremony.PlanOut, []ceremony.BornKey, []ceremony.MadeSignature) {
	p := tkPlanOut(twoBirths()...)
	p.Signatures = []ceremony.PlanSignature{
		{N: 1, Kind: "root-certificate", Subject: "A", Derived: true},
		{N: 2, Kind: "root-removal", Subject: "A", Derived: true},
		{N: 3, Kind: "root-list", Subject: "A"},
	}
	born := []ceremony.BornKey{
		{Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem", Pin: rep('a')},
		{Label: "A", Purpose: "openpgp-primary", Store: "software", Place: "A.openpgp.key.asc", Pin: rep('b'), Fingerprint: strings.Repeat("c", 40)},
	}
	var made []ceremony.MadeSignature
	for _, s := range p.Signatures {
		made = append(made, ceremony.MadeSignature{N: s.N, Kind: s.Kind, Subject: s.Subject, Key: rep('a'), SignatureSHA256: rep('5')})
	}
	return p, born, made
}

func TestThePlanAndTwoKeysOfOneLabelAgree(t *testing.T) {
	p, born, made := tkKeys()
	if err := ceremony.CheckPlanAgainstKeys(p, born, made); err != nil {
		t.Fatalf("CheckPlanAgainstKeys: %v", err)
	}
	// The X.509 key of a caller that knows no purpose is judged as before: by its label, store and
	// place, and it is the key that signs.
	born[0].Purpose = ""
	if err := ceremony.CheckPlanAgainstKeys(p, born, made); err != nil {
		t.Fatalf("an X.509 key with no purpose: %v", err)
	}
	// Two keys of one label that both name no purpose cannot be told apart: the pin that signs is not
	// known, and the check refuses (it fails closed).
	born[1].Purpose = ""
	mkWantArtifactError(t, ceremony.CheckPlanAgainstKeys(p, born, made), "plan against the keys", "signatures")
}

func TestEveryDisagreementOfThePlanAndTwoKeysIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(born []ceremony.BornKey, made []ceremony.MadeSignature)
		member string
	}{
		{"the purposes swapped", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) {
			b[0].Purpose, b[1].Purpose = b[1].Purpose, b[0].Purpose
		}, "births"},
		{"the keys swapped", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[0], b[1] = b[1], b[0] }, "births"},
		{"another purpose for the first key", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[0].Purpose = "openpgp-primary" }, "births"},
		{"an unknown purpose for the second key", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[1].Purpose = "ssh-ca" }, "births"},
		{"a purpose in capitals", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[1].Purpose = "OpenPGP-primary" }, "births"},
		{"the place of the first key for the second", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[1].Place = b[0].Place }, "births"},
		{"another store for the second key", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[1].Store = "piv" }, "births"},
		{"a pin that is not a pin for the second key", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) { b[1].Pin = "abc" }, "births"},
		{"one key is missing", func(b []ceremony.BornKey, _ []ceremony.MadeSignature) {}, "births"},
		{"the certificate is signed by the primary's pin", func(_ []ceremony.BornKey, m []ceremony.MadeSignature) { m[0].Key = rep('b') }, "signatures"},
		{"the root list is signed by the primary's pin", func(_ []ceremony.BornKey, m []ceremony.MadeSignature) { m[2].Key = rep('b') }, "signatures"},
		{"the removal is signed by the fingerprint of the primary", func(_ []ceremony.BornKey, m []ceremony.MadeSignature) { m[1].Key = strings.Repeat("c", 40) }, "signatures"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, born, made := tkKeys()
			c.edit(born, made)
			if c.name == "one key is missing" {
				born = born[:1]
			}
			mkWantArtifactError(t, ceremony.CheckPlanAgainstKeys(p, born, made), "plan against the keys", c.member)
		})
	}
}
