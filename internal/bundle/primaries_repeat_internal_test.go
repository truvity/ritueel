package bundle

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
)

// repeatedList is the list of the vectors with the fingerprint of B replaced by the one of A.
func repeatedList(t testing.TB) []byte {
	t.Helper()
	list := strings.Replace(string(vec(t, "root-list", "v1", "lists", "seq7-a.json")), "c4288657012230588b51fa66e0831b9c6e084f39", "6df387de63525c9dc0ec1174bd138d2c4889b79b", 1)
	if list == string(vec(t, "root-list", "v1", "lists", "seq7-a.json")) {
		t.Fatal("the list was not changed")
	}
	return []byte(list)
}

// A list that gives one fingerprint to two entries is found before the keyring file is read: no run reads the file,
// whatever it holds, for Primaries and for Checker with no delegation or an openpgp-subkey delegation.
func TestARepeatedFingerprintIsFoundBeforeTheKeyringFileIsRead(t *testing.T) {
	for name, file := range map[string][]byte{"a good file": goodKeyring(t), "no file": nil, "garbage": []byte("garbage")} {
		for _, call := range []struct {
			name string
			run  func(b *Bundle) error
		}{
			{"Primaries", func(b *Bundle) error { _, _, err := b.Primaries(); return err }},
			{"Checker with no delegation", func(b *Bundle) error { _, _, err := b.Checker("", time0, nil); return err }},
			{"Checker with an openpgp-subkey delegation", func(b *Bundle) error { _, _, err := b.Checker("pgpd", time0, nil); return err }},
		} {
			t.Run(name+", "+call.name, func(t *testing.T) {
				b, log := writeRecBundle(t, repeatedList(t), file)
				err := call.run(b)
				if err == nil || !errors.Is(err, ErrPrimaries) || errors.Is(err, openpgp.ErrKeyring) || errors.Is(err, ErrNoKeyring) {
					t.Fatalf("error %v, want one of the kind ErrPrimaries and no other", err)
				}
				if got := countOf(*log, readKeyring); got != 0 {
					t.Errorf("the keyring file was read %d times: %q", got, *log)
				}
				if got := countOf(*log, readList); got != 1 {
					t.Errorf("the list was read %d times: %q", got, *log)
				}
			})
		}
	}
}

// Beside an x509-intermediate or an ssh-ca-key delegation the checker holds no primaries, so the list's repeat is not
// judged and the file is not read; Primaries, which asks for the primaries themselves, gives the error.
func TestARepeatedFingerprintIsNotJudgedBesideADelegationThatTakesNoPrimaries(t *testing.T) {
	for _, delegation := range []string{"x509d", "sshd"} {
		t.Run(delegation, func(t *testing.T) {
			b, log := writeRecBundle(t, repeatedList(t), goodKeyring(t))
			chk, d, err := b.Checker(delegation, time0, nil)
			if err != nil || chk == nil || d == nil {
				t.Fatalf("Checker = (%v, %v, %v), want a checker", chk, d, err)
			}
			if got := countOf(*log, readKeyring); got != 0 {
				t.Errorf("the keyring file was read %d times", got)
			}
			if _, _, err := b.Primaries(); !errors.Is(err, ErrPrimaries) {
				t.Errorf("Primaries: %v, want an error of the kind ErrPrimaries", err)
			}
		})
	}
}

// primariesOf judges the count before the repeat, and the repeat before the file: a list of 17 entries that repeats
// one gives the count, and neither reads the file.
func TestThePrimariesOfAListAreJudgedInTheOrderCountRepeatFile(t *testing.T) {
	entry := func(label string, i int) rootlist.Root {
		return rootlist.Root{Label: label, OpenPGPFingerprint: fmt.Sprintf("%040x", i)}
	}
	var roots []rootlist.Root
	for i := range 17 {
		roots = append(roots, entry(string(rune('A'+i)), i+1))
	}
	roots[16].OpenPGPFingerprint = roots[0].OpenPGPFingerprint
	b, log := writeRecBundle(t, nil, goodKeyring(t))
	n := &newestSet{set: TrustSet{Name: "7-3fa9c1d2", Number: 7}, list: &rootlist.List{Roots: roots}}
	_, err := b.primariesOf(n, true)
	if err == nil || !strings.Contains(err.Error(), "pins 17") || strings.Contains(err.Error(), "openpgp_fingerprint") {
		t.Fatalf("17 entries with a repeat: %v, want the count", err)
	}
	roots[15].OpenPGPFingerprint = roots[0].OpenPGPFingerprint
	n.list = &rootlist.List{Roots: roots[:16]}
	_, err = b.primariesOf(n, true)
	if err == nil || !strings.Contains(err.Error(), "gives one openpgp_fingerprint to two entries: the entry with the label A and the entry with the label P") {
		t.Fatalf("16 entries with a repeat: %v, want the repeat", err)
	}
	if countOf(*log, readKeyring) != 0 {
		t.Errorf("the file was read: %q", *log)
	}
	// 16 entries with no repeat: the file is read.
	roots[15].OpenPGPFingerprint = fmt.Sprintf("%040x", 99)
	if _, err := b.primariesOf(n, true); err == nil || countOf(*log, readKeyring) != 1 {
		t.Errorf("16 entries with no repeat: error %v, reads %d", err, countOf(*log, readKeyring))
	}
}

// sameFingerprint on its own: the earlier entry and the repeating one, in list order, and no repeat when none.
func TestSameFingerprintGivesTheEarlierEntryAndTheRepeatingOne(t *testing.T) {
	e := func(label, fp string) openpgp.KeyringEntry {
		return openpgp.KeyringEntry{Label: label, Fingerprint: fp}
	}
	first, second, twice := sameFingerprint([]openpgp.KeyringEntry{e("A", "1"), e("B", "2"), e("C", "1"), e("D", "2")})
	if !twice || first != e("A", "1") || second != e("C", "1") {
		t.Errorf("(%v, %v, %v), want A and C", first, second, twice)
	}
	if _, _, twice := sameFingerprint([]openpgp.KeyringEntry{e("A", "1"), e("B", "2")}); twice {
		t.Error("a repeat where there is none")
	}
	if _, _, twice := sameFingerprint(nil); twice {
		t.Error("a repeat in no entries")
	}
	if first, second, twice := sameFingerprint([]openpgp.KeyringEntry{e("A", "1"), e("B", "1")}); !twice || first.Label != "A" || second.Label != "B" {
		t.Errorf("(%v, %v, %v), want A and B", first, second, twice)
	}
}

// ---- the cut of the cause ----------------------------------------------------------------------------------------

// bs is one backslash.
const bs = "\\"

// pad is n letters.
func pad(n int) string { return strings.Repeat("a", n) }

// The cut keeps whole escapes only: a text whose escape would pass 240 characters loses the whole escape.
func TestTheCutOfACauseKeepsOrDropsAWholeEscape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause string
		want  string
	}{
		{"239 letters", pad(239), pad(239)},
		{"240 letters", pad(240), pad(240)},
		{"241 letters", pad(241), pad(240) + "..."},
		{"an escape that ends at 240 is kept", pad(234) + "\x01", pad(234) + `\u0001`},
		{"an escape that ends at 240 and a letter after it", pad(234) + "\x01b", pad(234) + `\u0001...`},
		{"an escape that would pass 240 by one is dropped", pad(235) + "\x01", pad(235) + "..."},
		{"an escape that would pass 240 by five is dropped", pad(239) + "\x01", pad(239) + "..."},
		{"an escape that would pass 240 is dropped, and the rest with it", pad(238) + "\x01" + "bbb", pad(238) + "..."},
		{"a pair of surrogates that ends at 240 is kept", pad(228) + "\U0001F600", pad(228) + bs + "ud83d" + bs + "ude00"},
		{"a pair of surrogates that would pass 240 is dropped whole", pad(229) + "\U0001F600", pad(229) + "..."},
		{"a pair of surrogates cut in the middle never stays", pad(234) + "\U0001F600", pad(234) + "..."},
		{"a byte that is not UTF-8 is one escape", pad(234) + "\xff", pad(234) + bs + "ufffd"},
		{"a byte that is not UTF-8 that would pass 240", pad(235) + "\xff", pad(235) + "..."},
		{"a character with a two-byte form", pad(234) + "\u00e9", pad(234) + bs + "u00e9"},
		{"a character with a two-byte form that would pass 240", pad(236) + "é", pad(236) + "..."},
		{"a backslash of the text at the end of the cut is dropped", pad(239) + `\b`, pad(239) + "..."},
		{"a backslash of the text, then u, at the end of the cut", pad(238) + `\ub`, pad(238) + "..."},
		{"a backslash and u and one digit of the text at the end of the cut", pad(237) + `\u1b`, pad(237) + "..."},
		{"a backslash and u and two digits of the text", pad(236) + `\u12b`, pad(236) + "..."},
		{"a backslash and u and three digits of the text", pad(235) + `ሻ`, pad(235) + "..."},
		{"a backslash and u and two upper-case digits of the text", pad(236) + bs + "uABz", pad(236) + "..."},
		{"a whole escape of four digits in the text is kept", pad(234) + bs + "u1234b", pad(234) + bs + "u1234..."},
		{"a backslash of the text inside the limit is not changed", pad(10) + `\u12`, pad(10) + `\u12`},
		{"a backslash at the very end of an uncut text is not changed", pad(10) + `\`, pad(10) + `\`},
		{"letters after a backslash that is not an escape", pad(100) + `\n` + pad(200), pad(100) + `\n` + pad(138) + "..."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := causeText(errors.New(tc.cause))
			if got != tc.want {
				t.Errorf("causeText = %q\nwant        %q", got, tc.want)
			}
		})
	}
}

// For every length around the limit and every kind of tail, the cut text is printable ASCII, at most 243 characters,
// and its part before the three dots never ends in the start of an escape: a backslash, or a backslash and u with
// fewer than four digits, or the first half of a pair of surrogates.
func TestACutCauseNeverEndsInsideAnEscape(t *testing.T) {
	tails := []string{"", "x", "\x01", "\x7f", "\u00e9", "\u20ac", "\U0001F600", "\xff", "\xf0\x9f", bs, bs + "u", bs + "u1", bs + "u12", bs + "u123", bs + "u1234", "\n", "\u202e"}
	for n := 225; n <= 245; n++ {
		for _, tail := range tails {
			for _, more := range []string{"", "z", "zzzzzzzzzzzzzzzz"} {
				cause := pad(n) + tail + more
				got := causeText(errors.New(cause))
				if !onlyPrintableASCII(got) || !utf8.ValidString(got) || len(got) > maxCauseText+3 {
					t.Fatalf("cause of %d letters and tail %q: %q", n, tail+more, got)
				}
				body := strings.TrimSuffix(got, "...")
				if body != got {
					// A cut text: its body is at most 240 characters and ends in no start of an escape.
					if len(body) > maxCauseText {
						t.Errorf("the body of %q is %d characters", got, len(body))
					}
					for k := 1; k <= 5 && k <= len(body); k++ {
						part := body[len(body)-k:]
						if part[0] == '\\' && (k == 1 || (part[1] == 'u' && !strings.ContainsAny(part[2:], "ghijklmnopqrstuvwxyz"))) && len(part) < 6 {
							t.Errorf("cause of %d letters and tail %q ends inside an escape: %q", n, tail+more, got[len(got)-12:])
						}
					}
					if strings.HasSuffix(body, `\ud83d`) || strings.HasSuffix(body, `\ud83d\ude0`) {
						t.Errorf("a pair of surrogates is cut: %q", got[len(got)-16:])
					}
				} else if len(got) > maxCauseText {
					t.Errorf("an uncut text of %d characters: %q", len(got), got)
				}
			}
		}
	}
}

// A sentence of a refused file made from a long cause is no longer than its words and the cut cause, and its end
// is a whole escape.
func TestTheSentenceOfARefusedFileHoldsTheCutCause(t *testing.T) {
	set := TrustSet{Name: "7-3fa9c1d2", Number: 7}
	for _, n := range []int{239, 240, 241} {
		err := refusedKeyring(set, errors.New(pad(n)))
		want := "keyring.gpg of the newest trust set 7-3fa9c1d2 is refused: " + pad(min(n, 240))
		if n > 240 {
			want += "..."
		}
		if err.Error() != want {
			t.Errorf("cause of %d: %q", n, err.Error())
		}
	}
	err := refusedKeyring(set, errors.New(pad(235)+"\x01"))
	if want := "keyring.gpg of the newest trust set 7-3fa9c1d2 is refused: " + pad(235) + "..."; err.Error() != want {
		t.Errorf("a cause that ends inside an escape: %q, want %q", err.Error(), want)
	}
}

// The set name and the two labels in the sentence of a repeat go through the exact escape: a list that the reader of
// the list refused would be the only source of such labels, and the sentence holds none of their bytes raw. The
// entries are handed over as the reader of the list would have made them.
func TestTheNamesInTheSentenceOfARepeatAreEscaped(t *testing.T) {
	b, _ := writeRecBundle(t, nil, goodKeyring(t))
	n := &newestSet{set: TrustSet{Name: "7-\x1b a", Number: 7}, list: &rootlist.List{Roots: []rootlist.Root{
		{Label: "x y", OpenPGPFingerprint: fmt.Sprintf("%040x", 1)},
		{Label: "q" + bs + "\u202e", OpenPGPFingerprint: fmt.Sprintf("%040x", 1)},
	}}}
	_, err := b.primariesOf(n, true)
	want := "the root list of the newest trust set 7-" + bs + "u001b" + bs + "x20a gives one openpgp_fingerprint to two entries: the entry with the label x" + bs + "x20y and the entry with the label q" + bs + bs + bs + "u202e"
	if err == nil || err.Error() != want || !onlyPrintableASCII(err.Error()) {
		t.Errorf("error %v, want %q", err, want)
	}
	roots := make([]rootlist.Root, 17)
	for i := range roots {
		roots[i] = rootlist.Root{Label: string(rune('A' + i)), OpenPGPFingerprint: fmt.Sprintf("%040x", i+1)}
	}
	n = &newestSet{set: TrustSet{Name: "7-\x1b a", Number: 7}, list: &rootlist.List{Roots: roots}}
	_, err = b.primariesOf(n, true)
	want = "the root list of the newest trust set 7-" + bs + "u001b" + bs + "x20a pins 17 OpenPGP primaries, and the checks take at most 16"
	if err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

// dropLooseEscape on its own: the end of a text that looks like the start of an escape goes, a whole escape and an
// end that is not one stay. Upper-case and lower-case hexadecimal digits count the same.
func TestTheLooseStartOfAnEscapeIsDroppedFromTheEndOfACutText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"a", "a"},
		{"ab", "ab"},
		{bs, ""},
		{"a" + bs, "a"},
		{bs + "u", ""},
		{"ab" + bs + "u", "ab"},
		{"ab" + bs + "u1", "ab"},
		{"ab" + bs + "u12", "ab"},
		{"ab" + bs + "u123", "ab"},
		{"ab" + bs + "uAB", "ab"},
		{"ab" + bs + "uaB12", "ab" + bs + "uaB12"},
		{"ab" + bs + "uaB1", "ab"},
		{"ab" + bs + "u1234", "ab" + bs + "u1234"},
		{"ab" + bs + "uABCD", "ab" + bs + "uABCD"},
		{"ab" + bs + "ux", "ab" + bs + "ux"},
		{"ab" + bs + "ug1", "ab" + bs + "ug1"},
		{"ab" + bs + "n", "ab" + bs + "n"},
		{"ab" + bs + "x1", "ab" + bs + "x1"},
		{"u12", "u12"},
		{"ab12", "ab12"},
	} {
		if got := dropLooseEscape(tc.in); got != tc.want {
			t.Errorf("dropLooseEscape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An entry that the reader refuses before it reads the file (a label that is not a capital letter, a label twice, a
// fingerprint of another form) is a fault of the list, with its own sentence that names the list and keeps the cause
// of the reader reachable. The reader of the list refuses such a list earlier, so no bundle holds one; the entries are
// handed over as the reader of the list would have made them.
func TestAnEntryThatTheReaderRefusesBeforeItReadsTheFileIsAFaultOfTheList(t *testing.T) {
	fp := func(i int) string { return fmt.Sprintf("%040x", i) }
	for _, tc := range []struct {
		name  string
		roots []rootlist.Root
		cause string
	}{
		{"a label that is not a capital letter", []rootlist.Root{{Label: "a", OpenPGPFingerprint: fp(1)}}, "entry 1: the label is not one capital letter from A to Z"},
		{"a label twice", []rootlist.Root{{Label: "A", OpenPGPFingerprint: fp(1)}, {Label: "A", OpenPGPFingerprint: fp(2)}}, "entry 2: the label A is twice in the list"},
		{"a fingerprint of another form", []rootlist.Root{{Label: "A", OpenPGPFingerprint: "ABC"}}, "entry 1 (label A): the fingerprint is not 40 lower-case hexadecimal digits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := writeRecBundle(t, nil, goodKeyring(t))
			n := &newestSet{set: TrustSet{Name: "7-3fa9c1d2", Number: 7}, list: &rootlist.List{Roots: tc.roots}}
			refs, err := b.primariesOf(n, true)
			want := "the root list of the newest trust set 7-3fa9c1d2 cannot be held to a keyring file: openpgp: refused parameter: " + tc.cause
			if refs != nil || err == nil || err.Error() != want {
				t.Fatalf("(%v, %v), want an error with the text %q", refs, err, want)
			}
			if !errors.Is(err, ErrPrimaries) || !errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrKeyring) || errors.Is(err, ErrNoKeyring) {
				t.Errorf("kind of %q: want ErrPrimaries, with the cause ErrParams reachable, and no other", err)
			}
		})
	}
}

// FuzzCauseText: whatever text a cause holds (bytes of a file reach it through the error of a reader), the text of
// the sentence is printable ASCII, at most the limit and three dots long, is the escape of the cause when that
// fits, and is the start of that escape when it does not, never ending in the first half of a pair of surrogates.
func FuzzCauseText(f *testing.F) {
	for _, seed := range []string{"", "a", pad(240), pad(241), pad(234) + "\x01", pad(235) + "\x01", pad(228) + "\U0001F600", pad(229) + "\U0001F600",
		pad(236) + "\u00e9", pad(239) + bs + "b", pad(236) + bs + "u12b", pad(234) + bs + "u1234b", pad(100) + "\xff" + pad(200), "\xf0\x9f\x98", "a\x1b[2Jb\u202e"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := causeText(errors.New(s))
		if !onlyPrintableASCII(got) || len(got) > maxCauseText+3 {
			t.Fatalf("cause %q gives %q", s, got)
		}
		full := jsonset.Escape(s)
		if len(full) <= maxCauseText {
			if got != full {
				t.Fatalf("cause %q fits and gives %q, want %q", s, got, full)
			}
			return
		}
		body, cut := strings.CutSuffix(got, "...")
		if !cut || !strings.HasPrefix(full, body) || len(body) > maxCauseText {
			t.Fatalf("cause %q gives %q, want the start of %q and three dots", s, got, full)
		}
		if !strings.Contains(s, bs) && len(body) >= 6 {
			if tail := body[len(body)-6:]; strings.HasPrefix(tail, bs+"ud8") || strings.HasPrefix(tail, bs+"ud9") || strings.HasPrefix(tail, bs+"uda") || strings.HasPrefix(tail, bs+"udb") {
				t.Fatalf("cause %q gives %q, which ends in the first half of a pair", s, got)
			}
		}
	})
}
