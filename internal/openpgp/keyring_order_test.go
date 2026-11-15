package openpgp_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The reader does the checks that need no signature check for every certificate of the file before it
// verifies the first certification, and it refuses a certification that repeats another of its
// certificate before any signature check. The tests count the signature checks through
// ReadKeyringCounting, which runs the real check and records each packet it is given.

// ringOf makes n primaries with fresh keys, labelled A, B, ...
func ringOf(t testing.TB, n int, test bool) []keyringPrimary {
	t.Helper()
	ms := make([]keyringPrimary, n)
	for i := range ms {
		ms[i] = newKeyringPrimary(t, string(rune('A'+i)), test)
	}
	return ms
}

// at is the moment of the i-th certification of a primary in these tests: i seconds after the ceremony.
func at(i int) time.Time { return ceremony.Add(time.Duration(i) * time.Second) }

// chain is the certificate of a primary with n certifications, each a second after the one before.
func (m keyringPrimary) chain(t testing.TB, n int) []byte {
	t.Helper()
	sigs := make([][]byte, n)
	for i := range sigs {
		sigs[i] = m.sig(t, at(i), nil)
	}
	return m.assemble(sigs...)
}

// signaturesOf is the signature packets of a file, each whole, in file order.
func signaturesOf(t testing.TB, file []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range splitPackets(t, file) {
		if p.Tag == tagSignature {
			out = append(out, p.Raw)
		}
	}
	return out
}

// assertNoCheckRefused holds that ReadKeyring refuses the file with kind and the words, that the same
// refusal comes from the reader that has no recover, with the same text, no primary, and that the
// reader made no signature check at all.
func assertNoCheckRefused(t testing.TB, what string, file []byte, want []openpgp.KeyringEntry, kind error, words ...string) {
	t.Helper()
	assertKeyringRefused(t, what, file, want, kind, words...)
	keys, checked, err := openpgp.ReadKeyringCounting(file, want)
	if err == nil {
		t.Errorf("%s: the counting reader accepted the file", what)
		return
	}
	if keys != nil {
		t.Errorf("%s: the counting reader returned %d primaries with an error", what, len(keys))
	}
	if len(checked) != 0 {
		t.Errorf("%s: %d signature checks, want none", what, len(checked))
	}
	if _, exported := openpgp.ReadKeyring(file, want); exported == nil || exported.Error() != err.Error() {
		t.Errorf("%s: the counting reader says %q, ReadKeyring says %v", what, err, exported)
	}
}

func TestAnHonestFileCostsExactlyOneSignatureCheckForEachCertificationInFileOrder(t *testing.T) {
	ms := ringOf(t, 4, true)
	for _, counts := range [][]int{{1, 1, 1, 1}, {1, 2, 3, 1}, {3, 1, 1, 2}, {5, 5, 5, 5}} {
		var parts [][]byte
		total := 0
		for i, n := range counts {
			parts = append(parts, ms[i].chain(t, n))
			total += n
		}
		file := cat(parts...)
		keys, checked, err := openpgp.ReadKeyringCounting(file, wantOf(ms...))
		if err != nil {
			t.Fatalf("%v: error = %v", counts, err)
		}
		if len(keys) != len(ms) {
			t.Errorf("%v: %d primaries, want %d", counts, len(keys), len(ms))
		}
		want := signaturesOf(t, file)
		if len(want) != total {
			t.Fatalf("%v: the file holds %d signature packets, want %d", counts, len(want), total)
		}
		if len(checked) != total {
			t.Errorf("%v: %d signature checks, want %d (one for each certification)", counts, len(checked), total)
		}
		for i := range min(len(checked), len(want)) {
			if !bytes.Equal(checked[i], want[i]) {
				t.Errorf("%v: check %d was given another packet than the certification %d of the file", counts, i+1, i+1)
				break
			}
		}
		assertRead(t, fmt.Sprint(counts), file, wantOf(ms...), ms...)
	}
}

func TestAFileWhoseLastCertificateHoldsAFaultThatNeedsNoSignatureCheckCostsNoSignatureCheck(t *testing.T) {
	ms := ringOf(t, 3, true)
	head := cat(ms[0].chain(t, 3), ms[1].chain(t, 2))
	want := wantOf(ms...)
	m2 := ms[2]
	otherLabel, err := openpgp.UserID("Example Test", "B", "release@example.org", true)
	if err != nil {
		t.Fatal(err)
	}
	foreign := newKeyringPrimary(t, "C", true)
	samePoint := keyringPrimaryOf(t, ms[0].key, "C", true, created.Add(time.Second), "release@example.org")
	real := newKeyringPrimary(t, "C", false)
	good := m2.sig(t, ceremony, nil)
	cases := []struct {
		name  string
		file  []byte
		want  []openpgp.KeyringEntry
		kind  error
		words []string
	}{
		{"a key that no entry names", cat(head, foreign.chain(t, 2)), want, openpgp.ErrKeyringPrimaries, []string{"not on the list", "certificate 3 (label C)"}},
		{"the last two certificates swapped", cat(ms[0].chain(t, 3), m2.chain(t, 2), ms[1].chain(t, 2)), want, openpgp.ErrKeyringPrimaries, []string{"out of order", "certificate 2 (label B)", "position 3 (label C)"}},
		{"the key of an earlier certificate", cat(head, ms[0].chain(t, 2)), want, openpgp.ErrKeyringPrimaries, []string{"repeats", "certificate 3 (label C)", "holds the key of certificate 1"}},
		{"the key point of an earlier certificate", cat(head, samePoint.chain(t, 2)), wantOf(ms[0], ms[1], samePoint), openpgp.ErrKeyringPrimaries, []string{"repeats", "certificate 3 (label C)", "holds the key point of certificate 1"}},
		{"a user ID that names another label", cat(head, m2.withUserID(otherLabel).chain(t, 2)), want, openpgp.ErrKeyringPrimaries, []string{"certificate 3 (label C)", "user ID names the label B"}},
		{"a user ID that is not the one shape", cat(head, m2.withUserID("junk").chain(t, 2)), want, openpgp.ErrKeyringForm, []string{"certificate 3 (label C)", "user ID is refused"}},
		{"a key packet that is not read", cat(head, wrap(tagPublicKey, []byte{5, 0, 0, 0, 1}), m2.uidPacket(), good), want, openpgp.ErrKeyringForm, []string{"certificate 3 (label C)", "key packet"}},
		{"a key with the creation time 0", cat(head, wrap(tagPublicKey, keyBody(&m2.key.PublicKey, time.Unix(0, 0))), m2.uidPacket(), good), want, openpgp.ErrKeyringForm, []string{"certificate 3 (label C)", "key packet"}},
		{"a certification that repeats another", cat(head, m2.assemble(good, good)), want, openpgp.ErrKeyringForm, []string{"certificate 3 (label C)", "certification 2 repeats certification 1"}},
		{"a real primary among test primaries", cat(head, real.chain(t, 2)), wantOf(ms[0], ms[1], real), openpgp.ErrKeyringForm, []string{"mixes test and real primaries"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNoCheckRefused(t, c.name, c.file, c.want, c.kind, c.words...)
		})
	}
	// The negative control: the same file with the last certificate good costs one check for each
	// certification (3 + 2 + 2) and is read.
	_, checked, err := openpgp.ReadKeyringCounting(cat(head, m2.chain(t, 2)), want)
	if err != nil || len(checked) != 7 {
		t.Errorf("the file with a good last certificate: %d checks, error %v; want 7 and none", len(checked), err)
	}
}

// The fault is put in each place of three certificates, the first and the middle as well as the last: at
// each place no signature check is made.
func TestAFaultThatNeedsNoSignatureCheckCostsNoneInAnyCertificateOfTheFile(t *testing.T) {
	for place := range 3 {
		ms := ringOf(t, 3, true)
		parts := [][]byte{ms[0].chain(t, 2), ms[1].chain(t, 2), ms[2].chain(t, 2)}
		want := wantOf(ms...)
		bad := ms[place]
		foreign := keyringPrimaryOf(t, genKey(t), bad.label, true, created, "release@example.org")
		cases := []struct {
			name string
			cert []byte
			want []openpgp.KeyringEntry
			kind error
		}{
			{"a foreign key", foreign.chain(t, 2), want, openpgp.ErrKeyringPrimaries},
			{"a user ID that is not the one shape", bad.withUserID("junk").chain(t, 2), want, openpgp.ErrKeyringForm},
		}
		for _, c := range cases {
			file := slices.Clone(parts)
			file[place] = c.cert
			assertNoCheckRefused(t, fmt.Sprintf("%s in certificate %d", c.name, place+1), cat(file...), c.want, c.kind, fmt.Sprintf("certificate %d", place+1))
		}
		s := bad.sig(t, ceremony, nil)
		file := slices.Clone(parts)
		file[place] = bad.assemble(s, bad.sig(t, at(1), nil), s)
		assertNoCheckRefused(t, fmt.Sprintf("a repeated certification in certificate %d", place+1), cat(file...), want, openpgp.ErrKeyringForm,
			fmt.Sprintf("certificate %d (label %s)", place+1, bad.label), "certification 3 repeats certification 1")
	}
}

func TestACertificationThatRepeatsAnotherOfItsCertificateIsRefusedBeforeAnySignatureCheck(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	s0, s1, s2 := m.sig(t, at(0), nil), m.sig(t, at(1), nil), m.sig(t, at(2), nil)
	cases := []struct {
		name string
		sigs [][]byte
		say  string
	}{
		{"the same certification twice", [][]byte{s0, s0}, "certification 2 repeats certification 1"},
		{"the first again at the end", [][]byte{s0, s1, s0}, "certification 3 repeats certification 1"},
		{"the second again at the end", [][]byte{s0, s1, s1}, "certification 3 repeats certification 2"},
		{"the first again after two others", [][]byte{s0, s1, s2, s0}, "certification 4 repeats certification 1"},
		{"the middle one again at the end", [][]byte{s0, s1, s2, s1}, "certification 4 repeats certification 2"},
		{"three copies of one", [][]byte{s0, s0, s0}, "certification 2 repeats certification 1"},
		{"a repeat that stands out of creation order", [][]byte{s2, s1, s2}, "certification 3 repeats certification 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			file := m.assemble(c.sigs...)
			assertNoCheckRefused(t, c.name, file, wantOf(m), openpgp.ErrKeyringForm, "certificate 1 (label A)", c.say)
			_, err := openpgp.ReadKeyring(file, wantOf(m))
			if !strings.HasSuffix(err.Error(), ": certificate 1 (label A): "+c.say) {
				t.Errorf("the sentence is %q, want one that ends with the certificate and the two positions only", err)
			}
		})
	}
	// The negative control: the same certifications without the copy are read, and each is checked.
	_, checked, err := openpgp.ReadKeyringCounting(m.assemble(s0, s1, s2), wantOf(m))
	if err != nil || len(checked) != 3 {
		t.Errorf("three different certifications: %d checks, error %v; want 3 and none", len(checked), err)
	}
}

// The same certification under another header form is a repeat: the bodies of the packets are compared.
func TestTheSameCertificationUnderAnotherHeaderFormIsARepeatToo(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	s0, s1 := m.sig(t, at(0), nil), m.sig(t, at(1), nil)
	body := splitPackets(t, s0)[0].Body
	forms := []string{"new1", "new2", "new5", "old1", "old2", "old4"}
	var copies [][]byte
	var used []string
	for _, f := range forms {
		if pkt, ok := packetIn(f, tagSignature, body); ok {
			copies = append(copies, pkt)
			used = append(used, f)
		}
	}
	if len(copies) < 4 {
		t.Fatalf("only %d header forms fit the body of a certification (%v)", len(copies), used)
	}
	for i, c := range copies {
		for j, first := range copies {
			if i == j {
				continue
			}
			what := used[j] + " then " + used[i]
			assertNoCheckRefused(t, what+", next to each other", m.assemble(first, c), wantOf(m), openpgp.ErrKeyringForm, "certification 2 repeats certification 1")
			assertNoCheckRefused(t, what+", with another between", m.assemble(first, s1, c), wantOf(m), openpgp.ErrKeyringForm, "certification 3 repeats certification 1")
		}
		// The copy in the form that the builder wrote, then the same certification in another form.
		assertNoCheckRefused(t, "the builder's form then "+used[i], m.assemble(s0, c), wantOf(m), openpgp.ErrKeyringForm, "certification 2 repeats certification 1")
	}
	// A certification whose body differs in one bit is not a repeat: it fails the signature check, so a
	// check is made.
	flipped := bytes.Clone(body)
	flipped[len(flipped)-1] ^= 1
	pkt, _ := packetIn("new5", tagSignature, flipped)
	_, checked, err := openpgp.ReadKeyringCounting(m.assemble(s0, pkt), wantOf(m))
	if err == nil || strings.Contains(err.Error(), "repeats certification") || len(checked) != 2 {
		t.Errorf("a certification that differs in the last bit: %d checks, error %v; want the check of the second to refuse it", len(checked), err)
	}
}

func TestARepeatAtTheFirstTheMiddleAndTheLastPlaceOfTheLargestCertificate(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	sigs := make([][]byte, openpgp.MaxCertifications)
	for i := range sigs {
		sigs[i] = m.sig(t, at(i), nil)
	}
	for _, c := range []struct {
		name        string
		place, from int // the packet at place (0-based) is a copy of the one at from
	}{
		{"the second repeats the first", 1, 0},
		{"the middle repeats an early one", 127, 10},
		{"the middle repeats the one before it", 128, 127},
		{"the last repeats the first", 255, 0},
		{"the last repeats the one before it", 255, 254},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := slices.Clone(sigs)
			s[c.place] = sigs[c.from]
			say := fmt.Sprintf("certification %d repeats certification %d", c.place+1, c.from+1)
			assertNoCheckRefused(t, c.name, m.assemble(s...), wantOf(m), openpgp.ErrKeyringForm, "certificate 1 (label A)", say)
		})
	}
	// 256 certifications that are all different are read, and each is checked.
	_, checked, err := openpgp.ReadKeyringCounting(m.assemble(sigs...), wantOf(m))
	if err != nil || len(checked) != openpgp.MaxCertifications {
		t.Errorf("256 different certifications: %d checks, error %v; want 256 and none", len(checked), err)
	}
}

// Two certifications made at one moment differ in the random number of the signature, so they differ in
// their bodies and are not a repeat.
func TestTwoHundredAndFiftySixDifferentCertificationsOfOneMomentAreStillAccepted(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	sigs := make([][]byte, openpgp.MaxCertifications)
	seen := map[string]bool{}
	for i := range sigs {
		sigs[i] = m.sig(t, ceremony, nil)
		seen[string(sigs[i])] = true
	}
	if len(seen) != len(sigs) {
		t.Fatalf("the tests' own signer made %d different packets of 256", len(seen))
	}
	file := m.assemble(sigs...)
	_, checked, err := openpgp.ReadKeyringCounting(file, wantOf(m))
	if err != nil || len(checked) != openpgp.MaxCertifications {
		t.Fatalf("%d checks, error %v; want 256 and none", len(checked), err)
	}
	assertRead(t, "256 certifications of one moment", file, wantOf(m), m)
	// The same in the second of two certificates: the repeat check is for each certificate, not for the
	// file. Two certificates may hold the same certification bytes only if they hold the same key, which
	// the file refuses, so the second certificate holds its own.
	n := newKeyringPrimary(t, "B", true)
	assertRead(t, "two certificates of 256", cat(file, n.assemble(func() [][]byte {
		out := make([][]byte, openpgp.MaxCertifications)
		for i := range out {
			out[i] = n.sig(t, ceremony, nil)
		}
		return out
	}()...)), wantOf(m, n), m, n)
}

// The order of two faults in one file. A fault that needs no signature check comes before a bad
// certification of an earlier certificate, and the first fault is the one of the first certificate.
func TestTwoFaultsInOneFileAreToldInTheOrderOfTheChecks(t *testing.T) {
	ms := ringOf(t, 3, true)
	want := wantOf(ms...)
	badCert := func(m keyringPrimary) []byte {
		return m.assemble(m.sig(t, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }))
	}
	foreign := keyringPrimaryOf(t, genKey(t), "B", true, created, "release@example.org")
	real := newKeyringPrimary(t, "C", false)
	realB := newKeyringPrimary(t, "B", false)
	foreignC := keyringPrimaryOf(t, genKey(t), "C", true, created, "release@example.org")
	tampered := ms[2].assemble(ms[2].sig(t, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }))
	s := ms[0].sig(t, ceremony, nil)
	cases := []struct {
		name  string
		file  []byte
		want  []openpgp.KeyringEntry
		kind  error
		words []string
	}{
		{"a bad certification early and a foreign key later: the key", cat(badCert(ms[0]), foreign.good(t), ms[2].good(t)), want, openpgp.ErrKeyringPrimaries, []string{"not on the list", "certificate 2 (label B)"}},
		{"a bad certification early and a foreign key last: the key", cat(badCert(ms[0]), ms[1].good(t), foreign.good(t)), want, openpgp.ErrKeyringPrimaries, []string{"not on the list", "certificate 3"}},
		{"a bad certification and a mix: the mix", cat(ms[0].good(t), ms[1].good(t), real.assemble(real.sig(t, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }))), wantOf(ms[0], ms[1], real), openpgp.ErrKeyringForm, []string{"mixes test and real primaries"}},
		{"a bad certification in the first of a mix: the mix", cat(badCert(ms[0]), ms[1].good(t), real.good(t)), wantOf(ms[0], ms[1], real), openpgp.ErrKeyringForm, []string{"mixes test and real primaries"}},
		{"a mix and a foreign key: the key", cat(ms[0].good(t), realB.good(t), foreignC.good(t)), []openpgp.KeyringEntry{ms[0].entry(), realB.entry(), ms[2].entry()}, openpgp.ErrKeyringPrimaries, []string{"not on the list", "certificate 3 (label C)"}},
		{"a repeated certification in the first and a foreign key in the second: the repeat", cat(ms[0].assemble(s, s), foreign.good(t), ms[2].good(t)), want, openpgp.ErrKeyringForm, []string{"certificate 1 (label A)", "certification 2 repeats certification 1"}},
		{"a bad user ID in the first and a foreign key in the second: the user ID", cat(ms[0].withUserID("junk").good(t), foreign.good(t), ms[2].good(t)), want, openpgp.ErrKeyringForm, []string{"certificate 1 (label A)", "user ID"}},
		{"a repeated certification and a tampered later certificate: the repeat", cat(ms[0].assemble(s, s), ms[1].good(t), tampered), want, openpgp.ErrKeyringForm, []string{"certificate 1 (label A)", "certification 2 repeats certification 1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNoCheckRefused(t, c.name, c.file, c.want, c.kind, c.words...)
		})
	}
	// A foreign key in the first certificate and a repeat in the second: the first fault, the key.
	twice := ms[1].sig(t, ceremony, nil)
	rep := cat(foreign.good(t), ms[1].assemble(twice, twice), ms[2].good(t))
	assertNoCheckRefused(t, "a foreign key in the first and a repeat in the second", rep, want, openpgp.ErrKeyringPrimaries, "not on the list", "certificate 1")
}

// A bad certification stops the reader at once: the checks are made in file order and none after the
// first that fails.
func TestTheFirstBadCertificationEndsTheChecksAndNoPrimaryComesBack(t *testing.T) {
	ms := ringOf(t, 3, true)
	want := wantOf(ms...)
	bad := func(m keyringPrimary, at time.Time) []byte {
		return m.sig(t, at, func(sp *sigSpec) { sp.Type = 0x10 })
	}
	cases := []struct {
		name   string
		file   []byte
		checks int
		say    string
	}{
		{"the first certification of the first certificate", cat(ms[0].assemble(bad(ms[0], at(0)), ms[0].sig(t, at(1), nil)), ms[1].chain(t, 2), ms[2].chain(t, 1)), 1, "certificate 1 (label A), certification 1"},
		{"the second certification of the first certificate", cat(ms[0].assemble(ms[0].sig(t, at(0), nil), bad(ms[0], at(1))), ms[1].chain(t, 2), ms[2].chain(t, 1)), 2, "certificate 1 (label A), certification 2"},
		{"the only certification of the second certificate", cat(ms[0].chain(t, 2), ms[1].assemble(bad(ms[1], at(0))), ms[2].chain(t, 1)), 3, "certificate 2 (label B), certification 1"},
		{"the last certification of the last certificate", cat(ms[0].chain(t, 2), ms[1].chain(t, 2), ms[2].assemble(ms[2].sig(t, at(0), nil), bad(ms[2], at(1)))), 6, "certificate 3 (label C), certification 2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keys, checked, err := openpgp.ReadKeyringCounting(c.file, want)
			if err == nil || keys != nil {
				t.Fatalf("%d primaries, error %v; want none and an error", len(keys), err)
			}
			if len(checked) != c.checks {
				t.Errorf("%d signature checks, want %d", len(checked), c.checks)
			}
			assertKeyringRefused(t, c.name, c.file, want, openpgp.ErrKeyringForm, c.say)
		})
	}
}

// The branch of the walk for a user ID after a certification is gone: the sentence is not in the code
// and the refusal of a second user ID is the one that is shown.
func TestAUserIDAfterACertificationIsASecondUserIDAndTheOldSentenceIsGone(t *testing.T) {
	ms := ringOf(t, 2, true)
	a, b := ms[0], ms[1]
	s := a.sig(t, ceremony, nil)
	assertNoCheckRefused(t, "after the certification", cat(a.keyPacket(), a.uidPacket(), s, a.uidPacket()), wantOf(a), openpgp.ErrKeyringForm, "certificate 1 (label A)", "second user ID packet")
	assertNoCheckRefused(t, "after two certifications", cat(a.keyPacket(), a.uidPacket(), s, s, a.uidPacket()), wantOf(a), openpgp.ErrKeyringForm, "second user ID packet")
	assertNoCheckRefused(t, "in the second certificate", cat(a.good(t), b.keyPacket(), b.uidPacket(), b.sig(t, ceremony, nil), b.uidPacket()), wantOf(a, b), openpgp.ErrKeyringForm, "certificate 2 (label B)", "second user ID packet")
	for _, file := range []string{"keyring.go", "primary.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, err := strconv.Unquote(lit.Value)
				if err == nil && strings.Contains(s, "packet after a certification") {
					t.Errorf("%s still holds the sentence %q for a branch that no file reaches", file, s)
				}
			}
			return true
		})
	}
}

// recoverersIn names the functions of a file that call recover.
func recoverersIn(t *testing.T, file string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if callsIn(t, file, fd.Name.Name)["recover"] {
			out = append(out, fd.Name.Name)
		}
	}
	return out
}

// identsIn tells whether a function of a file names an identifier anywhere, as a call or as a value.
func identsIn(t *testing.T, file, fn, name string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == fn {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == name {
					found = true
				}
				return true
			})
		}
	}
	return found
}

// The two recovers stay on the exported paths and nowhere else: the work is in functions that have none.
func TestOnlyTheExportedPathsRecoverAndTheWorkIsInFunctionsThatDoNot(t *testing.T) {
	if got := recoverersIn(t, "keyring.go"); !slices.Equal(got, []string{"ReadKeyring"}) {
		t.Errorf("the functions of keyring.go that recover: %v, want [ReadKeyring]", got)
	}
	if got := recoverersIn(t, "primary.go"); !slices.Equal(got, []string{"checkCertification"}) {
		t.Errorf("the functions of primary.go that recover: %v, want [checkCertification]", got)
	}
	for _, c := range []struct{ file, fn, calls string }{
		{"keyring.go", "ReadKeyring", "readKeyring"},
		{"keyring.go", "readKeyring", "readCertificates"},
		{"keyring.go", "readKeyring", "groupKeyring"},
		{"primary.go", "checkCertification", "checkCertificationWork"},
	} {
		if !callsIn(t, c.file, c.fn)[c.calls] {
			t.Errorf("%s does not call %s", c.fn, c.calls)
		}
	}
	// The exported reader hands the real check to the loop, as a value and not a call.
	if !identsIn(t, "keyring.go", "ReadKeyring", "checkCertification") || callsIn(t, "keyring.go", "ReadKeyring")["checkCertification"] {
		t.Error("ReadKeyring does not pass checkCertification to the reader as a value")
	}
	// The loop calls the check it is given and not a fixed one.
	if !callsIn(t, "keyring.go", "readCertificates")["check"] || callsIn(t, "keyring.go", "readCertificates")["checkCertification"] {
		t.Error("readCertificates does not call its parameter check, or calls checkCertification by name")
	}
	// The want list is held to its rules inside the net of ReadKeyring, before the recover is set up, and
	// the inner function takes a list that is held.
	if callsIn(t, "keyring.go", "readKeyring")["checkKeyringEntries"] {
		t.Error("readKeyring checks the list: the check belongs to the exported function")
	}
}

// A panic of the reader reaches a test through the inner function, and the check of a certification is
// not reached when a cheap check refuses the file.
func TestAPanicInTheReaderIsSeenByTheInnerFunctionAndNotRaisedByACheapRefusal(t *testing.T) {
	ms := ringOf(t, 2, true)
	file := cat(ms[0].good(t), ms[1].good(t))
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("the panic of the check did not reach the caller of the inner function")
			}
		}()
		_, _ = openpgp.ReadKeyringWithPanickingCheck(file, wantOf(ms...))
	}()
	foreign := keyringPrimaryOf(t, genKey(t), "B", true, created, "release@example.org")
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("a file that a cheap check refuses reached the check of a certification: %v", r)
		}
	}()
	keys, err := openpgp.ReadKeyringWithPanickingCheck(cat(ms[0].good(t), foreign.good(t)), wantOf(ms...))
	if keys != nil || err == nil || !strings.Contains(err.Error(), "not on the list") {
		t.Errorf("keys %v, error %v; want the refusal of the foreign key", keys, err)
	}
	// A fault of the list is an ErrParams in the inner function too, and the file is not read.
	if _, err := openpgp.ReadKeyringWithPanickingCheck(file, nil); err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Errorf("an empty list: error = %v", err)
	}
}

// The inner functions give what the exported ones give, for each change of one bit of a file and of a
// certification: the net changes no result.
func TestTheInnerFunctionsGiveWhatTheExportedOnesGive(t *testing.T) {
	v := loadVectorKeyring(t)
	file := v.a
	want := v.want[:1]
	same := func(what string, file []byte) {
		k1, e1 := openpgp.ReadKeyring(file, want)
		k2, e2 := openpgp.ReadKeyringNoRecover(file, want)
		if (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) || len(k1) != len(k2) {
			t.Fatalf("%s: ReadKeyring gives %v and %v, the inner function %v and %v", what, len(k1), e1, len(k2), e2)
		}
	}
	same("the file", file)
	for i := 0; i < len(file)*8; i += 3 {
		c := bytes.Clone(file)
		c[i/8] ^= 1 << (i % 8)
		same(fmt.Sprintf("bit %d", i), c)
	}
	for n := 0; n < len(file); n += 7 {
		same(fmt.Sprintf("the first %d bytes", n), file[:n])
	}
	m := newKeyringPrimary(t, "A", true)
	key := m.keyPacket()
	pkt := m.sig(t, ceremony, nil)
	c1, l1, e1 := openpgp.CheckCertificationBytes(pkt, key, m.uid, ceremony)
	c2, l2, e2 := openpgp.CheckCertificationBytesNoRecover(pkt, key, m.uid, ceremony)
	if e1 != nil || e2 != nil || !c1.Equal(c2) || l1 != l2 {
		t.Errorf("the shared check gives %v %v %v, the inner function %v %v %v", c1, l1, e1, c2, l2, e2)
	}
	for i := 0; i < len(pkt)*8; i += 5 {
		c := bytes.Clone(pkt)
		c[i/8] ^= 1 << (i % 8)
		_, _, e1 := openpgp.CheckCertificationBytes(c, key, m.uid, ceremony)
		_, _, e2 := openpgp.CheckCertificationBytesNoRecover(c, key, m.uid, ceremony)
		if (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
			t.Fatalf("bit %d: the shared check says %v, the inner function %v", i, e1, e2)
		}
	}
}

// The doc of ReadKeyring says the order that the code keeps: the cheap checks of every certificate, then
// the mix, and only then the first certification.
func TestTheDocOfReadKeyringSaysTheCheapChecksComeBeforeTheFirstSignatureCheck(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "keyring.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "ReadKeyring" && fd.Doc != nil {
			doc = strings.Join(strings.Fields(fd.Doc.Text()), " ")
		}
	}
	if doc == "" {
		t.Fatal("ReadKeyring has no doc")
	}
	last := -1
	for _, step := range []string{
		"1. want:", "2. The size:", "3. The walk of the packets", "4. Every certificate in order, with no signature check:",
		"repeats another", "5. No mix of the test mark over all the certificates.", "6. Only then the certifications",
		"costs no signature check",
	} {
		i := strings.Index(doc, step)
		if i < 0 {
			t.Errorf("the doc of ReadKeyring does not hold %q", step)
			continue
		}
		if i < last {
			t.Errorf("the doc of ReadKeyring holds %q before an earlier step", step)
		}
		last = i
	}
}
