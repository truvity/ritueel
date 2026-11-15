package software

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

// The header cases need no scrypt: the header is looked at before the identity of the library
// runs, and these tests give the gate a stub in place of that identity, which counts its calls.

func TestTheProductionWorkFactorsAre18And22AndNoSourceFileLowersThem(t *testing.T) {
	if MinWorkFactor != 18 || MaxWorkFactor != 22 || WriteWorkFactor != 18 {
		t.Errorf("limits %d..%d, written %d", MinWorkFactor, MaxWorkFactor, WriteWorkFactor)
	}
	if workFactorWritten != 18 || workFactorLowest != 18 {
		t.Errorf("the variables hold %d and %d, want 18 and 18", workFactorWritten, workFactorLowest)
	}
	if MaxPassphraseBytes != 1024 || MinPassphraseChars != 15 {
		t.Errorf("passphrase limits %d and %d", MaxPassphraseBytes, MinPassphraseChars)
	}
}

func TestEveryWorkFactorOutsideTheRangeOrNotCanonicalIsRefusedBeforeTheIdentityRuns(t *testing.T) {
	bad := []string{
		"0", "1", "9", "10", "17", "23", "24", "30", "31", "64", "99", "100", "255",
		"018", "0018", "+18", "-18", "18.0", "18.", ".18", " 18", "18 ", "0x12", "0b10010", "1e1", "18e0",
		"99999999999999999999", "1" + strings.Repeat("0", 40), "", " ", "-", "+", "\uff10\uff11\uff18", "\uff11\uff18", "\u0967\u096e",
		"18\x00", "\t18", "18\n",
	}
	for _, wf := range bad {
		t.Run(strings.ReplaceAll(wf, "\x00", "NUL")+"_direct", func(t *testing.T) {
			err := checkStanzas([]*age.Stanza{stanzaOf("scrypt", goodArgs(wf), scryptBody())})
			wantRefusal(t, err, ErrKeyFile, "key-file")
		})
	}
	// the same through a whole header that is read by the library, for the ones that a header can carry
	for _, wf := range bad {
		if wf == "" || strings.ContainsAny(wf, " \t\n\x00") {
			continue // an argument cannot hold a space or an end of line in the text format
		}
		t.Run(wf+"_in_a_file", func(t *testing.T) {
			file := headerOf(scryptStanza(wf))
			wantRefusal(t, inspectHeader(file), ErrKeyFile, "key-file")
			stub := &stubIdentity{}
			// the library may refuse a header text that it cannot parse before it asks the gate
			if _, err := age.Decrypt(bytes.NewReader(file), scryptGate{inner: stub}); err == nil {
				t.Error("the file was opened")
			}
			if stub.calls != 0 {
				t.Errorf("the inner identity ran %d times for the work factor %q", stub.calls, wf)
			}
		})
	}
}

func TestTheWorkFactorsOf18To22PassTheHeaderCheckAndCallTheInnerIdentityOnce(t *testing.T) {
	for _, wf := range []string{"18", "19", "20", "21", "22"} {
		t.Run(wf, func(t *testing.T) {
			file := headerOf(scryptStanza(wf))
			if err := inspectHeader(file); err != nil {
				t.Fatalf("inspect: %v", err)
			}
			stub := &stubIdentity{}
			_, err := age.Decrypt(bytes.NewReader(file), scryptGate{inner: stub})
			var none *age.NoIdentityMatchError
			if !errors.As(err, &none) {
				t.Fatalf("the stub does not match, so the library says no identity matched: %v", err)
			}
			if stub.calls != 1 {
				t.Errorf("the inner identity ran %d times", stub.calls)
			}
		})
	}
}

func TestTheLowestWorkFactorThatIsReadIsTheVariableAndTheHighestIsTheConstant(t *testing.T) {
	lowWork(t)
	for wf, ok := range map[string]bool{"9": false, "10": true, "11": true, "22": true, "23": false} {
		err := checkStanzas([]*age.Stanza{stanzaOf("scrypt", goodArgs(wf), scryptBody())})
		if ok && err != nil {
			t.Errorf("%s refused at the lowered limit: %v", wf, err)
		}
		if !ok && err == nil {
			t.Errorf("%s accepted at the lowered limit", wf)
		}
	}
}

func TestTheHeaderCheckRefusesEveryStanzaListThatIsNotExactlyOneScryptStanza(t *testing.T) {
	good := func() *age.Stanza { return stanzaOf("scrypt", goodArgs("18"), scryptBody()) }
	salt := func(n int) string { return b64(bytes.Repeat([]byte{7}, n)) }
	x25519 := func() *age.Stanza {
		return stanzaOf("X25519", []string{b64(bytes.Repeat([]byte{3}, 32))}, bytes.Repeat([]byte{4}, 32))
	}
	cases := []struct {
		name string
		in   []*age.Stanza
	}{
		{"no stanza", nil},
		{"an empty list", []*age.Stanza{}},
		{"a nil stanza", []*age.Stanza{nil}},
		{"a nil stanza and a good one", []*age.Stanza{nil, good()}},
		{"a good stanza and a nil one", []*age.Stanza{good(), nil}},
		{"one X25519 stanza", []*age.Stanza{x25519()}},
		{"scrypt and X25519", []*age.Stanza{good(), x25519()}},
		{"X25519 and scrypt", []*age.Stanza{x25519(), good()}},
		{"two scrypt stanzas", []*age.Stanza{good(), good()}},
		{"three scrypt stanzas", []*age.Stanza{good(), good(), good()}},
		{"an unknown type", []*age.Stanza{stanzaOf("ssh-ed25519", goodArgs("18"), scryptBody())}},
		{"the type in capitals", []*age.Stanza{stanzaOf("SCRYPT", goodArgs("18"), scryptBody())}},
		{"the type with a space after it", []*age.Stanza{stanzaOf("scrypt ", goodArgs("18"), scryptBody())}},
		{"the type of a passkey stanza of a later format", []*age.Stanza{stanzaOf("piv-p256", goodArgs("18"), scryptBody())}},
		{"an empty type", []*age.Stanza{stanzaOf("", goodArgs("18"), scryptBody())}},
		{"no argument", []*age.Stanza{stanzaOf("scrypt", nil, scryptBody())}},
		{"one argument (the salt)", []*age.Stanza{stanzaOf("scrypt", []string{b64(saltOf16)}, scryptBody())}},
		{"one argument (the work factor)", []*age.Stanza{stanzaOf("scrypt", []string{"18"}, scryptBody())}},
		{"three arguments", []*age.Stanza{stanzaOf("scrypt", append(goodArgs("18"), "x"), scryptBody())}},
		{"a salt of 15 bytes", []*age.Stanza{stanzaOf("scrypt", []string{salt(15), "18"}, scryptBody())}},
		{"a salt of 17 bytes", []*age.Stanza{stanzaOf("scrypt", []string{salt(17), "18"}, scryptBody())}},
		{"a salt of 0 bytes", []*age.Stanza{stanzaOf("scrypt", []string{"", "18"}, scryptBody())}},
		{"a salt of 32 bytes", []*age.Stanza{stanzaOf("scrypt", []string{salt(32), "18"}, scryptBody())}},
		{"a padded salt", []*age.Stanza{stanzaOf("scrypt", []string{salt(16) + "==", "18"}, scryptBody())}},
		{"a salt of 22 characters with bits set in the last one", []*age.Stanza{stanzaOf("scrypt", []string{salt(16)[:21] + "B", "18"}, scryptBody())}},
		{"a salt in the URL alphabet", []*age.Stanza{stanzaOf("scrypt", []string{strings.Repeat("-", 21) + "A", "18"}, scryptBody())}},
		{"a salt of 22 characters that are not Base64", []*age.Stanza{stanzaOf("scrypt", []string{strings.Repeat("!", 22), "18"}, scryptBody())}},
		{"a body of 0 bytes", []*age.Stanza{stanzaOf("scrypt", goodArgs("18"), nil)}},
		{"a body of 16 bytes", []*age.Stanza{stanzaOf("scrypt", goodArgs("18"), scryptBody()[:16])}},
		{"a body of 31 bytes", []*age.Stanza{stanzaOf("scrypt", goodArgs("18"), scryptBody()[:31])}},
		{"a body of 33 bytes", []*age.Stanza{stanzaOf("scrypt", goodArgs("18"), append(scryptBody(), 0))}},
		{"a body of 64 bytes", []*age.Stanza{stanzaOf("scrypt", goodArgs("18"), bytes.Repeat([]byte{1}, 64))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantRefusal(t, checkStanzas(c.in), ErrKeyFile, "key-file")
			stub := &stubIdentity{}
			_, err := scryptGate{inner: stub}.Unwrap(c.in)
			wantRefusal(t, err, ErrKeyFile, "key-file")
			if stub.calls != 0 {
				t.Errorf("the inner identity ran %d times", stub.calls)
			}
		})
	}
	if err := checkStanzas([]*age.Stanza{good()}); err != nil {
		t.Errorf("the good stanza is refused: %v", err)
	}
}

func TestTheHeaderCheckRefusesTheSameCasesInWholeFilesAndCostsNoWork(t *testing.T) {
	x25519 := stanzaText("X25519", []string{b64(bytes.Repeat([]byte{3}, 32))}, bytes.Repeat([]byte{4}, 32))
	cases := []struct {
		name string
		file []byte
	}{
		{"no stanza", headerOf()},
		{"one X25519 stanza", headerOf(x25519)},
		{"scrypt and X25519", headerOf(scryptStanza("18"), x25519)},
		{"X25519 and scrypt", headerOf(x25519, scryptStanza("18"))},
		{"two scrypt stanzas", headerOf(scryptStanza("18"), scryptStanza("20"))},
		{"one argument", headerOf(stanzaText("scrypt", []string{"18"}, scryptBody()))},
		{"three arguments", headerOf(stanzaText("scrypt", append(goodArgs("18"), "x"), scryptBody()))},
		{"a salt of 15 bytes", headerOf(stanzaText("scrypt", []string{b64(saltOf16[:15]), "18"}, scryptBody()))},
		{"a salt of 17 bytes", headerOf(stanzaText("scrypt", []string{b64(append(bytes.Clone(saltOf16), 1)), "18"}, scryptBody()))},
		{"a padded salt", headerOf(stanzaText("scrypt", []string{b64(saltOf16) + "==", "18"}, scryptBody()))},
		{"a body of 16 bytes", headerOf(stanzaText("scrypt", goodArgs("18"), scryptBody()[:16]))},
		{"a body of 100 bytes", headerOf(stanzaText("scrypt", goodArgs("18"), bytes.Repeat([]byte{1}, 100)))},
		{"an unknown stanza type", headerOf(stanzaText("unknown", goodArgs("18"), scryptBody()))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantRefusal(t, inspectHeader(c.file), ErrKeyFile, "key-file")
			wantRefusal(t, ageFormat{}.inspect(c.file), ErrKeyFile, "key-file")
			stub := &stubIdentity{}
			if _, err := age.Decrypt(bytes.NewReader(c.file), scryptGate{inner: stub}); err == nil {
				t.Error("the file was opened")
			}
			if stub.calls != 0 {
				t.Errorf("the inner identity ran %d times", stub.calls)
			}
		})
	}
	if err := inspectHeader(headerOf(scryptStanza("18"))); err != nil {
		t.Errorf("the good header is refused: %v", err)
	}
}

func TestAGateWithNoInnerIdentityRefusesAGoodHeaderWithoutPanicking(t *testing.T) {
	_, err := scryptGate{}.Unwrap([]*age.Stanza{stanzaOf("scrypt", goodArgs("18"), scryptBody())})
	if !errors.Is(err, ErrParams) {
		t.Errorf("%v", err)
	}
}

func TestInspectHeaderRefusesWhatIsNotAnAgeFileAndNeverRepeatsALineOfIt(t *testing.T) {
	canary := "CANARY-LINE-OF-THE-FILE"
	cases := map[string][]byte{
		"empty":                    {},
		"one byte":                 {'a'},
		"a plain PEM":              []byte(armourLine("BEGIN", "PRIVATE KEY") + "\nAAAA\n" + armourLine("END", "PRIVATE KEY") + "\n"),
		"an armoured age file":     []byte(armourLine("BEGIN", "AGE ENCRYPTED FILE") + "\nAAAA\n" + armourLine("END", "AGE ENCRYPTED FILE") + "\n"),
		"another version":          []byte("age-encryption.org/v2\n-> scrypt\n"),
		"the canary as the intro":  []byte(canary + "\n"),
		"the canary as a stanza":   []byte(ageVersionLine + "-> " + canary + " x\nAAAA\n--- AAAA\n"),
		"no MAC line":              []byte(ageVersionLine + scryptStanza("18")),
		"a MAC line of one byte":   []byte(ageVersionLine + scryptStanza("18") + "--- A\n"),
		"a MAC with padding":       []byte(ageVersionLine + scryptStanza("18") + "--- " + b64(bytes.Repeat([]byte{1}, 32)) + "=\n"),
		"a carriage return":        bytes.ReplaceAll(headerOf(scryptStanza("18")), []byte("\n"), []byte("\r\n")),
		"a line of a megabyte":     append([]byte(ageVersionLine+"-> scrypt "), bytes.Repeat([]byte{'a'}, 1<<20)...),
		"a header of many stanzas": []byte(ageVersionLine + strings.Repeat(scryptStanza("18"), 200) + "--- AAAA\n"),
		"only the version line":    []byte(ageVersionLine),
		"NUL bytes":                bytes.Repeat([]byte{0}, 4096),
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			err := inspectHeader(file)
			wantRefusal(t, err, ErrKeyFile, "key-file", canary)
		})
	}
	// a header over the limit of the package is refused by its length
	long := append(headerOf(scryptStanza("18")), bytes.Repeat([]byte{1}, MaxKeyFileSize)...)
	wantRefusal(t, ageFormat{}.inspect(long), ErrKeyFile, "key-file")
}

func TestEveryCutOfAFileThatEndsInsideTheHeaderIsErrKeyFileAndAsksForNoPassphrase(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	asked := src.calls()
	file := readKeyFile(t, keys, "A.x509.key.age")
	hl := headerLen(t, file)
	if hl < 100 || hl > len(file) {
		t.Fatalf("header length %d of %d", hl, len(file))
	}
	rf := recordAge(t, s)
	for cut := 0; cut < hl; cut++ {
		writeKeyFile(t, keys, "B.x509.key.age", file[:cut])
		got, err := s.OpenX509(bg(), "B")
		if got != nil {
			t.Fatalf("cut at %d: a key came", cut)
		}
		if !errors.Is(err, ErrKeyFile) || Code(err) != "key-file" {
			t.Fatalf("cut at %d: %v", cut, err)
		}
	}
	if src.calls() != asked {
		t.Errorf("a cut header asked for a passphrase %d times", src.calls()-asked)
	}
	if rf.unwraps != 0 {
		t.Errorf("scrypt ran %d times for a cut header", rf.unwraps)
	}
	// a cut exactly at the end of the header holds a good header: the passphrase is asked, and the file is damaged
	writeKeyFile(t, keys, "B.x509.key.age", file[:hl])
	_, err := s.OpenX509(bg(), "B")
	wantRefusal(t, err, ErrKeyFile, "key-file")
	if src.calls() != asked+1 {
		t.Errorf("the passphrase was asked %d times for a header with no payload", src.calls()-asked)
	}
}

func TestARefusedHeaderSaysWhichPartOfItWasRefusedInFixedWordsAndKeepsTheSentinel(t *testing.T) {
	x25519 := stanzaText("X25519", []string{b64(bytes.Repeat([]byte{3}, 32))}, bytes.Repeat([]byte{4}, 32))
	cases := []struct {
		name string
		file []byte
		word string
	}{
		{"a work factor of 17", headerOf(scryptStanza("17")), "work factor"},
		{"a work factor of 23", headerOf(scryptStanza("23")), "work factor"},
		{"a work factor with a plus sign", headerOf(scryptStanza("+18")), "work factor"},
		{"two stanzas", headerOf(scryptStanza("18"), scryptStanza("18")), "exactly one stanza"},
		{"an X25519 stanza", headerOf(x25519), "type scrypt"},
		{"one argument", headerOf(stanzaText("scrypt", []string{"18"}, scryptBody())), "two arguments"},
		{"a salt of 15 bytes", headerOf(stanzaText("scrypt", []string{b64(saltOf16[:15]), "18"}, scryptBody())), "salt"},
		{"a body of 16 bytes", headerOf(stanzaText("scrypt", goodArgs("18"), scryptBody()[:16])), "body"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := inspectHeader(c.file)
			wantRefusal(t, err, ErrKeyFile, "key-file")
			if !strings.Contains(err.Error(), c.word) {
				t.Errorf("the words do not say %q: %v", c.word, err)
			}
		})
	}
}
