package openpgp_test

import (
	"bytes"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// PrimaryKey.TestMark tells the mark " (TEST ONLY)" of the user ID that an accepted keyring file
// holds for the primary (docs/reference/keyring-package.md, "The first form of the keyring file":
// the file never mixes test and real primaries, so one answer holds for all the primaries of a file).

// A primary of a file whose user IDs carry the mark gives true, for one primary and for the most that
// a file may hold.
func TestTestMarkIsTrueForEveryPrimaryOfATestFile(t *testing.T) {
	for _, n := range []int{1, 2, 3, openpgp.MaxKeyringCertificates} {
		t.Run(fmt.Sprintf("%d primaries", n), func(t *testing.T) {
			ms, file := keyringOfKind(t, n, true)
			keys := assertRead(t, "a test file", file, wantOf(ms...), ms...)
			for i, k := range keys {
				if !k.TestMark() {
					t.Errorf("primary %d of a test file has no test mark", i)
				}
			}
		})
	}
}

// A primary of a file whose user IDs carry no mark gives false.
func TestTestMarkIsFalseForEveryPrimaryOfARealFile(t *testing.T) {
	for _, n := range []int{1, 2, 3, openpgp.MaxKeyringCertificates} {
		t.Run(fmt.Sprintf("%d primaries", n), func(t *testing.T) {
			ms, file := keyringOfKind(t, n, false)
			keys := assertRead(t, "a real file", file, wantOf(ms...), ms...)
			for i, k := range keys {
				if k.TestMark() {
					t.Errorf("primary %d of a real file has a test mark", i)
				}
			}
		})
	}
}

// The vector files of the repository, made by another tool, give the answer of their user IDs.
func TestTestMarkOfTheVectorPrimaries(t *testing.T) {
	v := loadVectorKeyring(t)
	file := cat(v.a, v.b)
	keys := assertRead(t, "the vector primaries", file, v.want)
	var uids [][]byte
	for _, p := range splitPackets(t, file) {
		if p.Tag == tagUserID {
			uids = append(uids, p.Body)
		}
	}
	if len(uids) != len(keys) {
		t.Fatalf("%d user IDs for %d primaries", len(uids), len(keys))
	}
	for i, k := range keys {
		if want := bytes.Contains(uids[i], []byte(" (TEST ONLY) <")); k.TestMark() != want {
			t.Errorf("vector primary %d: TestMark = %v, its user ID says %v", i, k.TestMark(), want)
		}
	}
}

// A primary that no keyring file made has no user ID and no mark: NewPrimaryKey, a nil pointer and the
// zero value all say false, and none of them panics.
func TestTestMarkIsFalseWhereNoFileGaveTheKey(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	made, err := openpgp.NewPrimaryKey(&m.key.PublicKey, m.at)
	if err != nil {
		t.Fatal(err)
	}
	if made.TestMark() {
		t.Error("a primary made by NewPrimaryKey has a test mark")
	}
	var none *openpgp.PrimaryKey
	if none.TestMark() {
		t.Error("a nil primary has a test mark")
	}
	var zero openpgp.PrimaryKey
	if zero.TestMark() {
		t.Error("a zero primary has a test mark")
	}
	if (&openpgp.PrimaryKey{}).TestMark() {
		t.Error("an empty primary has a test mark")
	}
}

// The key of the same primary read from a test file has the mark and the one made from the same key by
// NewPrimaryKey has not, and the two are the same key.
func TestTestMarkDoesNotChangeWhichKeyItIs(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	keys := assertRead(t, "one test primary", m.good(t), wantOf(m), m)
	made, err := openpgp.NewPrimaryKey(&m.key.PublicKey, m.at)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Fingerprint() != made.Fingerprint() || !keys[0].Created().Equal(made.Created()) || !keys[0].PublicKey().Equal(made.PublicKey()) {
		t.Error("the primary read from the file is another key than the one NewPrimaryKey made")
	}
	if !keys[0].TestMark() || made.TestMark() {
		t.Errorf("marks: read %v, made %v", keys[0].TestMark(), made.TestMark())
	}
}

// Two reads of one file give the same answer, and a change of the file or of the entries after the read
// changes nothing: the answer is held by the primary, not read again from the bytes.
func TestTestMarkIsTheSameOnASecondReadAndSurvivesAChangeOfTheInput(t *testing.T) {
	for _, test := range []bool{true, false} {
		ms, file := keyringOfKind(t, 2, test)
		want := wantOf(ms...)
		first := assertRead(t, "first", file, want, ms...)
		second := assertRead(t, "second", file, want, ms...)
		for i := range first {
			if first[i].TestMark() != test || second[i].TestMark() != test {
				t.Errorf("test=%v primary %d: %v and %v", test, i, first[i].TestMark(), second[i].TestMark())
			}
		}
		for i := range file {
			file[i] ^= 0xff
		}
		want[0].Label = "Z"
		for i := range first {
			if first[i].TestMark() != test {
				t.Errorf("test=%v primary %d changed with the file", test, i)
			}
		}
	}
}

// Reads at the same time give the same answer (the race detector judges the shared state, if any).
func TestTestMarkOfConcurrentReads(t *testing.T) {
	test, real := newKeyringPrimary(t, "A", true), newKeyringPrimary(t, "A", false)
	testFile, realFile := test.good(t), real.good(t)
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			isTest := i%2 == 0
			file, want := realFile, wantOf(real)
			if isTest {
				file, want = testFile, wantOf(test)
			}
			keys, err := openpgp.ReadKeyring(bytes.Clone(file), want)
			if err != nil || len(keys) != 1 || keys[0].TestMark() != isTest {
				errs <- fmt.Sprintf("reader %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// A user ID that carries the mark anywhere but where UserID writes it (before the address) is not
// a user ID of the page: it is refused, and no primary comes with the refusal, so it cannot give a
// mark.
func TestTestMarkCannotBeSpelledAnyOtherWay(t *testing.T) {
	m := newKeyringPrimary(t, "A", false)
	for name, uid := range map[string]string{
		"in the name":       "Example (TEST ONLY) Release Root A <release@example.org>",
		"after the label":   "Example Release Root A(TEST ONLY) <release@example.org>",
		"in the address":    "Example Release Root A <release(TEST ONLY)@example.org>",
		"after the bracket": "Example Release Root A <release@example.org> (TEST ONLY)",
		"lower case":        "Example Release Root A (test only) <release@example.org>",
		"no leading space":  "Example Release Root A(TEST ONLY) <release@example.org>",
		"two marks":         "Example Release Root A (TEST ONLY) (TEST ONLY) <release@example.org>",
		"a half mark":       "Example Release Root A (TEST ONLY <release@example.org>",
	} {
		t.Run(name, func(t *testing.T) {
			w := m.withUserID(uid)
			keys, err := readSafely(t, name, w.good(t), wantOf(w))
			if err == nil {
				t.Fatalf("accepted; TestMark = %v", keys[0].TestMark())
			}
			if keys != nil {
				t.Errorf("%d primaries with an error", len(keys))
			}
		})
	}
}

// Every file the reader refuses gives no primary, whatever the reason, so there is no answer to ask:
// a nil list with the error, for form faults, primary faults, arguments and a mix, and for files that
// are refused after the user IDs were read (a bad certification).
func TestNoPrimaryAndSoNoMarkComesWithARefusedFile(t *testing.T) {
	a, b := newKeyringPrimary(t, "A", true), newKeyringPrimary(t, "B", true)
	r := newKeyringPrimary(t, "B", false)
	other := newKeyringPrimary(t, "C", true)
	bad := a.assemble(a.sig(t, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }))
	cases := []struct {
		name string
		file []byte
		want []openpgp.KeyringEntry
	}{
		{"an empty file", nil, wantOf(a)},
		{"armour", []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"), wantOf(a)},
		{"a cut file", a.good(t)[:10], wantOf(a)},
		{"a mix of test and real", cat(a.good(t), r.good(t)), wantOf(a, r)},
		{"a mix, real first", cat(r.good(t), a.good(t)), wantOf(r, a)},
		{"a primary that is not on the list", other.good(t), wantOf(a)},
		{"a swapped pair", cat(b.good(t), a.good(t)), wantOf(a, b)},
		{"one certificate too few", a.good(t), wantOf(a, b)},
		{"one certificate too many", cat(a.good(t), b.good(t)), wantOf(a)},
		{"a bad certification of the first", bad, wantOf(a)},
		{"a bad certification of the second", cat(a.good(t), b.assemble(b.sig(t, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }))), wantOf(a, b)},
		{"a list with no entry", a.good(t), nil},
		{"a list with a label twice", a.good(t), []openpgp.KeyringEntry{a.entry(), a.entry()}},
		{"a label that the user ID does not name", a.good(t), []openpgp.KeyringEntry{{Label: "Q", Fingerprint: a.fp}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keys, err := readSafely(t, c.name, c.file, c.want)
			if err == nil {
				t.Fatal("the file is accepted")
			}
			if keys != nil {
				t.Errorf("%d primaries come with the error %v", len(keys), err)
			}
		})
	}
}

// The mark does not depend on the order of the entries or on how many certifications a certificate holds.
func TestTestMarkWithLongerCertificatesAndHeaderForms(t *testing.T) {
	for _, test := range []bool{true, false} {
		m := newKeyringPrimary(t, "A", test)
		file := cat(m.cert(t), m.extension(t, ceremony.Add(time.Hour)), m.extension(t, ceremony.Add(2*time.Hour)))
		keys := assertRead(t, "three certifications", file, wantOf(m), m)
		if keys[0].TestMark() != test {
			t.Errorf("test=%v: TestMark = %v", test, keys[0].TestMark())
		}
		for _, form := range []string{"new1", "new2", "new5", "old1", "old2", "old4"} {
			repacked := repack(t, m.good(t), form)
			keys := assertRead(t, form, repacked, wantOf(m), m)
			if keys[0].TestMark() != test {
				t.Errorf("test=%v header form %s: TestMark = %v", test, form, keys[0].TestMark())
			}
		}
	}
}

// keyringOfKind makes n primaries with the labels A, B, ... of one kind and their file.
func keyringOfKind(t testing.TB, n int, test bool) ([]keyringPrimary, []byte) {
	t.Helper()
	var ms []keyringPrimary
	var parts [][]byte
	for i := 0; i < n; i++ {
		m := newKeyringPrimary(t, string(rune('A'+i)), test)
		ms = append(ms, m)
		parts = append(parts, m.good(t))
	}
	return ms, slices.Concat(parts...)
}
