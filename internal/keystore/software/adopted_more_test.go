package software

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/openpgp"
)

// More tests of the adopted key in the store: what the file holds, what is expected of it, which
// passphrases are asked, and the refusals of the test mode.

func TestAnAdoptedKeyFileHoldsTheLonePacketOfEachAlgorithm(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384", "rsa4096"} {
		t.Run(name, func(t *testing.T) {
			s := adSavedOf(t, name)
			payload, err := adAge.unwrapWith([]byte(testPass), FileOpenPGP, s.file)
			if err != nil || !bytes.Equal(payload, s.pkt) {
				t.Fatalf("the payload of the file is not the lone packet: %v", err)
			}
			clear(payload)
			if _, err := adAge.unwrapWith([]byte(testPass2), FileOpenPGP, s.file); !errors.Is(err, ErrWrongPassphrase) {
				t.Errorf("another passphrase opens the file: %v", err)
			}
			for _, w := range adSecretWords(s.pkt)[:3] {
				if bytes.Contains(s.file, []byte(w)) {
					t.Errorf("the file holds a run of the packet in the clear")
				}
			}
			if s.fk.Wiped() {
				t.Errorf("the export of the caller was wiped by the save")
			}
			again, err := s.fk.SecretPacket(nil)
			if err != nil || !bytes.Equal(again, s.pkt) {
				t.Errorf("the export does not give the same packet after the save: %v", err)
			}
		})
	}
}

func TestEachMemberOfWhatIsExpectedIsHeldAlone(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384", "rsa4096"} {
		t.Run(name, func(t *testing.T) {
			s := adSavedOf(t, name)
			st, _ := adStoreWith(t, s, "A", newPassSource(testPass))
			good := expectOf(s.fk)
			otherAlg := "ed25519"
			if name == "ed25519" {
				otherAlg = "p384"
			}
			other := expectOf(adSavedOf(t, otherAlg).fk)
			flipped := []byte(good.Fingerprint)
			if flipped[0] == 'a' {
				flipped[0] = 'b'
			} else {
				flipped[0] = 'a'
			}
			cases := []struct {
				name string
				want Expect
				says []string
			}{
				{"the fingerprint", Expect{Fingerprint: string(flipped), Created: good.Created, Cert: good.Cert}, []string{"the fingerprint"}},
				{"the fingerprint in capitals", Expect{Fingerprint: strings.ToUpper(good.Fingerprint), Created: good.Created, Cert: good.Cert}, []string{"the fingerprint"}},
				{"the fingerprint cut short", Expect{Fingerprint: good.Fingerprint[:39], Created: good.Created, Cert: good.Cert}, []string{"the fingerprint"}},
				{"the fingerprint with a space", Expect{Fingerprint: good.Fingerprint + " ", Created: good.Created, Cert: good.Cert}, []string{"the fingerprint"}},
				{"the time one second later", Expect{Fingerprint: good.Fingerprint, Created: good.Created.Add(time.Second), Cert: good.Cert}, []string{"the creation time"}},
				{"the time one second earlier", Expect{Fingerprint: good.Fingerprint, Created: good.Created.Add(-time.Second), Cert: good.Cert}, []string{"the creation time"}},
				{"the time a nanosecond later", Expect{Fingerprint: good.Fingerprint, Created: good.Created.Add(time.Nanosecond), Cert: good.Cert}, []string{"the creation time"}},
				{"the certificate of a key of another algorithm", Expect{Fingerprint: good.Fingerprint, Created: good.Created, Cert: other.Cert}, []string{"the public part"}},
			}
			for _, c := range cases {
				k, err := st.OpenAdopted(bg(), "A", c.want)
				if k != nil {
					t.Errorf("%s: a key is returned", c.name)
				}
				wantRefusal(t, err, ErrKeyFile, "key-file", append(adSecretWords(s.pkt), good.Fingerprint)...)
				for _, w := range []string{"the fingerprint", "the creation time", "the public part"} {
					if says := strings.Contains(err.Error(), w); says != contains(c.says, w) {
						t.Errorf("%s: the text says %q: %v, want %v: %v", c.name, w, says, !says, err)
					}
				}
				if err := st.CheckAdopted(bg(), "A", c.want); !errors.Is(err, ErrKeyFile) {
					t.Errorf("%s: CheckAdopted: %v", c.name, err)
				}
			}
			// what is not a difference: the same instant in another zone, a certificate with more packets
			// than the first, and the first packet in the old form of the header
			zone := time.FixedZone("elsewhere", 5*3600)
			sameInstant := Expect{Fingerprint: good.Fingerprint, Created: good.Created.In(zone), Cert: good.Cert}
			first := fkFirst(t, good.Cert)
			oldForm := Expect{Fingerprint: good.Fingerprint, Created: good.Created, Cert: append(oldHeader(6, first), []byte("anything after the first packet")...)}
			for name, want := range map[string]Expect{"another zone": sameInstant, "the old header": oldForm, "the same": good} {
				if k, err := st.OpenAdopted(bg(), "A", want); err != nil {
					t.Errorf("%s: %v", name, err)
				} else {
					_ = k.Close()
				}
			}
			// a certificate that does not start with the public key packet of a key
			for name, cert := range map[string][]byte{
				"a secret key packet first": append([]byte{0xC0 | 5}, good.Cert[1:]...),
				"a subkey packet first":     append([]byte{0xC0 | 14}, good.Cert[1:]...),
				"a user ID first":           append([]byte{0xC0 | 13, 3}, "abc"...),
				"the packet cut":            good.Cert[:10],
				"text":                      []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
			} {
				_, err := st.OpenAdopted(bg(), "A", Expect{Fingerprint: good.Fingerprint, Created: good.Created, Cert: cert})
				wantRefusal(t, err, ErrParams, "")
				if err := st.CheckAdopted(bg(), "A", Expect{Fingerprint: good.Fingerprint, Created: good.Created, Cert: cert}); !errors.Is(err, ErrParams) {
					t.Errorf("%s: CheckAdopted: %v", name, err)
				}
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// fkFirst is the body of the first packet of a certificate that is written in the new format.
func fkFirst(t testing.TB, cert []byte) []byte {
	t.Helper()
	if cert[0]&0xC0 != 0xC0 {
		t.Fatal("the certificate is not in the new format")
	}
	hl := 2
	n := int(cert[1])
	switch {
	case n >= 224:
		t.Fatal("a length of this form is not in the tests")
	case n >= 192:
		hl, n = 3, (n-192)<<8+int(cert[2])+192
	}
	return cert[hl : hl+n]
}

// oldHeader writes a packet in the old format with the two-octet length.
func oldHeader(tag byte, body []byte) []byte {
	return append([]byte{0x80 | tag<<2 | 1, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestAKeyFileOfAnotherKeyOfTheSameAlgorithmIsToldFromTheKeyExpected(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384"} {
		t.Run(name, func(t *testing.T) {
			s := adSavedOf(t, name)
			other := adFresh(t, name)
			if other.Primary.Fingerprint == s.fk.Primary.Fingerprint {
				t.Fatal("the other key is the key")
			}
			src := newPassSource(testPass)
			st, _ := adStoreWith(t, s, "A", src)
			// the same label, the same passphrase, the same algorithm and the same creation time
			k, err := st.OpenAdopted(bg(), "A", expectOf(other))
			if k != nil {
				t.Fatalf("a key is returned for the key of the file against the expectation of another")
			}
			wantRefusal(t, err, ErrKeyFile, "key-file", append(adSecretWords(s.pkt), other.Primary.Fingerprint, s.fk.Primary.Fingerprint)...)
			for _, w := range []string{"the fingerprint", "the public part"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the text does not say %q: %v", w, err)
				}
			}
			if strings.Contains(err.Error(), "the creation time") {
				t.Errorf("the text says that the creation time differs, and it does not: %v", err)
			}
			if err := st.CheckAdopted(bg(), "A", expectOf(other)); !errors.Is(err, ErrKeyFile) {
				t.Errorf("CheckAdopted: %v", err)
			}
		})
	}
}

func TestThePassphrasesThatSaveAdoptedAsks(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "ed25519")
	imp := Purpose{Label: "A", File: FileOpenPGP, Role: Import}
	cho := Purpose{Label: "A", File: FileOpenPGP, Role: Choose}
	long4096 := strings.Repeat("p", openpgp.MaxForeignPassphraseBytes)
	for _, c := range []struct {
		name       string
		exportPass string
		give       func(src *passSource)
		want       []Purpose
		err        error
		files      int
	}{
		{"an unprotected export asks the new passphrase only", "", func(*passSource) {}, []Purpose{cho}, nil, 1},
		{"a protected export asks the export first, then the new one", exportPass, func(*passSource) {}, []Purpose{imp, cho}, nil, 1},
		{"one character for the export", "x", func(src *passSource) { src.by[imp] = "x" }, []Purpose{imp, cho}, nil, 1},
		{"exactly 4096 bytes for the export", long4096, func(src *passSource) { src.by[imp] = long4096 }, []Purpose{imp, cho}, nil, 1},
		{"4097 bytes for the export", exportPass, func(src *passSource) { src.by[imp] = long4096 + "p" }, []Purpose{imp}, ErrPassphrase, 0},
		{"an empty passphrase for the export", exportPass, func(src *passSource) { src.by[imp] = "" }, []Purpose{imp}, ErrPassphrase, 0},
		{"a new passphrase of 14 characters", exportPass, func(src *passSource) { src.by[cho] = "fourteen chars" }, []Purpose{imp, cho}, ErrPassphrase, 0},
		{"a new passphrase of 15 characters", exportPass, func(src *passSource) { src.by[cho] = "fifteen letters" }, []Purpose{imp, cho}, nil, 1},
		{"a new passphrase over the limit", exportPass, func(src *passSource) { src.by[cho] = strings.Repeat("n", MaxPassphraseBytes+1) }, []Purpose{imp, cho}, ErrPassphrase, 0},
		{"an empty new passphrase", exportPass, func(src *passSource) { src.by[cho] = "" }, []Purpose{imp, cho}, ErrPassphrase, 0},
		{"the wrong passphrase of the export", exportPass, func(src *passSource) { src.by[imp] = "not the one" }, []Purpose{imp}, ErrWrongPassphrase, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			fk := b.foreign(t, c.exportPass)
			src := newPassSource(testPass)
			src.by = map[Purpose]string{imp: c.exportPass}
			c.give(src)
			st, _, keys := openPassStore(t, src)
			err := st.SaveAdopted(bg(), "A", fk)
			if got := src.purposes(); !samePurposes(got, c.want) {
				t.Errorf("the source was asked %v, want %v", got, c.want)
			}
			if (err == nil) != (c.err == nil) || (err != nil && !errors.Is(err, c.err)) {
				t.Fatalf("SaveAdopted: %v, want %v", err, c.err)
			}
			if names := dirNames(t, keys); len(names) != c.files {
				t.Errorf("the folder holds %v, want %d files", names, c.files)
			}
			if err != nil {
				for _, w := range []string{exportPass, "not the one", "fourteen chars", long4096[:20]} {
					if strings.Contains(err.Error(), w) {
						t.Errorf("the text holds a passphrase: %v", err)
					}
				}
			}
			// whatever happened, the export of the caller is as it was
			if fk.Wiped() {
				t.Errorf("the export was wiped")
			}
			if _, perr := fk.SecretPacket(passOf(c.exportPass)); perr != nil {
				t.Errorf("the export does not open any more: %v", perr)
			}
			adAllZero(t, c.name, src)
		})
	}
}

func passOf(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func TestAnAdoptedKeyIsOpenedAndCheckedWithThePassphraseOfTheKeyFile(t *testing.T) {
	lowWork(t)
	s := adSavedOf(t, "ed25519")
	key := Purpose{Label: "A", File: FileOpenPGP}
	if key.Role != KeyFile {
		t.Fatalf("the zero role is not KeyFile")
	}
	src := newPassSource(testPass)
	st, _ := adStoreWith(t, s, "A", src)
	k, err := st.OpenAdopted(bg(), "A", expectOf(s.fk))
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Close()
	if err := st.CheckAdopted(bg(), "A", expectOf(s.fk)); err != nil {
		t.Fatal(err)
	}
	if got := src.purposes(); !samePurposes(got, []Purpose{key, key}) {
		t.Errorf("the source was asked %v, want the key file twice, once for each call", got)
	}
	adAllZero(t, "an open and a check", src)
	// the rule of 15 characters holds for the passphrase of the key file, and the refusal comes before
	// any scrypt
	short := newPassSource("short one")
	st2, _ := adStoreWith(t, s, "A", short)
	rec := recordAge(t, st2)
	if _, err := st2.OpenAdopted(bg(), "A", expectOf(s.fk)); !errors.Is(err, ErrPassphrase) {
		t.Errorf("a short passphrase of the key file: %v, want ErrPassphrase", err)
	}
	if rec.unwraps != 0 {
		t.Errorf("scrypt ran for a passphrase that was refused")
	}
	adAllZero(t, "a short passphrase", short)
	// a wrong passphrase, a failing source and a missing file
	wrong := newPassSource(testPass2)
	st3, _ := adStoreWith(t, s, "A", wrong)
	if err := st3.CheckAdopted(bg(), "A", expectOf(s.fk)); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("a wrong passphrase: %v", err)
	}
	adAllZero(t, "a wrong passphrase", wrong)
	failing := newPassSource(testPass)
	failing.err = errors.New("no terminal")
	st4, _ := adStoreWith(t, s, "A", failing)
	if _, err := st4.OpenAdopted(bg(), "A", expectOf(s.fk)); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Errorf("a source that fails: %v", err)
	}
	st5, _, _ := openPassStore(t, newPassSource(testPass))
	_, err = st5.OpenAdopted(bg(), "A", expectOf(s.fk))
	wantRefusal(t, err, ErrKeyFile, "key-file")
}

func TestTheTestModeRefusesTheAdoptedKeyAndTouchesNothing(t *testing.T) {
	s := adSavedOf2(t)
	st, _, keys := openStore(t)
	// a file of the passphrase mode that stands in the folder is not read and not changed
	writeKeyFile(t, keys, "A.openpgp.key.age", s.file)
	before := readKeyFile(t, keys, "A.openpgp.key.age")
	names := dirNames(t, keys)
	for name, f := range map[string]func() error{
		"SaveAdopted":  func() error { return st.SaveAdopted(bg(), "B", s.fk) },
		"OpenAdopted":  func() error { _, err := st.OpenAdopted(bg(), "A", expectOf(s.fk)); return err },
		"CheckAdopted": func() error { return st.CheckAdopted(bg(), "A", expectOf(s.fk)) },
	} {
		err := f()
		wantRefusal(t, err, ErrParams, "")
		if !strings.Contains(err.Error(), "not in the passphrase mode") {
			t.Errorf("%s: the text does not say why: %v", name, err)
		}
		if got := dirNames(t, keys); strings.Join(got, ",") != strings.Join(names, ",") || !bytes.Equal(before, readKeyFile(t, keys, "A.openpgp.key.age")) {
			t.Errorf("%s: the folder changed: %v", name, got)
		}
	}
	// and the store is not stopped by them
	if st.stop != nil {
		t.Errorf("the store is stopped after the refusals: %v", st.stop)
	}
}

// adSavedOf2 is the saved key of the p384 base, for a test that does not call lowWork itself.
func adSavedOf2(t testing.TB) *adSaved {
	t.Helper()
	lowWork(t)
	return adSavedOf(t, "p384")
}

func TestAPayloadThatIsNotTheLonePacketIsNotTakenForAnAdoptedKey(t *testing.T) {
	lowWork(t)
	s := adSavedOf(t, "ed25519")
	damaged := map[string][]byte{}
	// payloads that are not the lone packet, each wrapped as a key file under testPass
	_, canon := s.fk, s.pkt
	damaged["the packet and a byte"] = append(bytes.Clone(canon), 0)
	damaged["the packet cut"] = canon[:len(canon)-1]
	damaged["the packet twice"] = append(bytes.Clone(canon), canon...)
	damaged["a public key packet"] = append([]byte{0xC0 | 6}, canon[1:]...)
	damaged["armour"] = []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n")
	damaged["the whole export"] = adoptedNamed(t, "ed25519").export(t, "")
	for name, payload := range damaged {
		file, err := adAge.wrapWith([]byte(testPass), FileOpenPGP, payload)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		st, _, keys := openPassStore(t, newPassSource(testPass))
		writeKeyFile(t, keys, "A.openpgp.key.age", file)
		k, err := st.OpenAdopted(bg(), "A", expectOf(s.fk))
		if k != nil {
			t.Errorf("%s: a key is returned", name)
		}
		wantRefusal(t, err, ErrKeyFile, "key-file", adSecretWords(s.pkt)...)
		if err := st.CheckAdopted(bg(), "A", expectOf(s.fk)); !errors.Is(err, ErrKeyFile) {
			t.Errorf("%s: CheckAdopted: %v", name, err)
		}
	}
}

func TestTheExportedFileIsNeverTouched(t *testing.T) {
	lowWork(t)
	dir := t.TempDir()
	b := adoptedNamed(t, "p384")
	file := b.export(t, exportPass)
	path := filepath.Join(dir, "export.asc")
	if err := os.WriteFile(path, file, 0o400); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	fk, err := openpgp.ReadForeignKey(file)
	if err != nil {
		t.Fatal(err)
	}
	defer fk.Wipe()
	st, _, _ := openPassStore(t, adoptedSource(exportPass))
	if err := st.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Errorf("the exported file changed")
	}
	if !bytes.Equal(file, before) {
		t.Errorf("the buffer of the export changed")
	}
	if _, err := pgp.ReadKeyRing(bytes.NewReader(file)); err != nil {
		t.Errorf("go-crypto does not read the export after the save: %v", err)
	}
}

func TestAnExistingKeyFileIsRefusedBeforeAnyPassphraseIsAsked(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "ed25519")
	saved := adSavedOf(t, "ed25519")
	born := mustGenerate(t)
	// a protected export, so that a prompt for it would be asked first if the name were looked at late
	fk := b.foreign(t, exportPass)
	for name, plant := range map[string]func(t *testing.T, st *Store, keys string){
		"an adopted key file": func(t *testing.T, _ *Store, keys string) { writeKeyFile(t, keys, adFinal, saved.file) },
		"a key file of a key that ritueel made": func(t *testing.T, st *Store, _ string) {
			if err := st.SaveOpenPGP("A", born, certFor(t, born)); err != nil {
				t.Fatal(err)
			}
		},
		"a file with nothing in it": func(t *testing.T, _ *Store, keys string) { writeKeyFile(t, keys, adFinal, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			src := adoptedSource(exportPass)
			st, _, keys := openPassStore(t, src)
			plant(t, st, keys)
			asked := src.calls()
			before := readKeyFile(t, keys, adFinal)
			names := dirNames(t, keys)
			rec := record(st)
			err := st.SaveAdopted(bg(), "A", fk)
			wantRefusal(t, err, ErrKeyExists, "key-exists", exportPass, testPass)
			if src.calls() != asked {
				t.Errorf("the source was asked %d times for a file that stands there", src.calls()-asked)
			}
			if rec.calls() != 0 || !bytes.Equal(before, readKeyFile(t, keys, adFinal)) || strings.Join(dirNames(t, keys), ",") != strings.Join(names, ",") {
				t.Errorf("the folder was written to")
			}
			if fk.Wiped() {
				t.Errorf("the export was wiped")
			}
			// the store is stopped, as it is for every other key that stands: nothing more is asked
			if again := st.SaveAdopted(bg(), "B", fk); again != err { //nolint:errorlint // the very same error value
				t.Errorf("the next save returns %v, want the first error itself", again)
			}
			if src.calls() != asked {
				t.Errorf("the source was asked after the stop")
			}
		})
	}
}

func TestAnAdoptedKeyShowsAndMarshalsNothingOfItself(t *testing.T) {
	lowWork(t)
	for _, name := range []string{"ed25519", "p384"} {
		k, s := adOpen(t, name)
		words := adSecretWords(s.pkt)
		for _, v := range []any{k, *k, struct{ Key *AdoptedKey }{k}, []*AdoptedKey{k}, map[string]*AdoptedKey{"a": k}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
				out := fmt.Sprintf(verb, v)
				for _, w := range words[:4] {
					if strings.Contains(out, w) {
						t.Errorf("%s of %T holds a run of the secret", verb, v)
					}
				}
			}
		}
		for what, marshal := range map[string]func() ([]byte, error){
			"json": func() ([]byte, error) { return json.Marshal(k) }, //nolint:staticcheck // that it marshals to nothing is what is tested
			"text": func() ([]byte, error) { return json.Marshal(struct{ K *AdoptedKey }{k}) },
		} {
			out, err := marshal()
			if err != nil || strings.Contains(string(out), "secret") || len(out) > 20 {
				t.Errorf("%s: %q %v, want nothing of the key", what, out, err)
			}
		}
	}
}

func TestEveryMethodOfANilOrZeroAdoptedKeyIsSafe(t *testing.T) {
	for name, k := range map[string]*AdoptedKey{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			if k.Close() != nil || k.Public() != nil || k.Fingerprint() != "" || !k.Created().IsZero() || k.Algorithm() != (openpgp.ForeignAlgorithm{}) {
				t.Errorf("a method answers something")
			}
			if k.Kind() != keystore.KindSoftware || !k.Copyable() || len(k.Warnings()) != 1 {
				t.Errorf("the answers that need no key are not those of a software key")
			}
			if _, err := k.Sign(nil, make([]byte, 32), crypto.SHA256); !errors.Is(err, ErrParams) {
				t.Errorf("Sign: %v", err)
			}
			if err := k.selfCheck(); !errors.Is(err, ErrParams) {
				t.Errorf("selfCheck: %v", err)
			}
		})
	}
}

func TestAnAdoptedKeyIsNotOpenedFromAFileOfTheOtherModeOrAFileThatIsNotAnAgeFile(t *testing.T) {
	lowWork(t)
	s := adSavedOf(t, "ed25519")
	for name, c := range map[string]struct {
		file string
		data []byte
		want error
		code string
	}{
		"the plain key file of a test root": {"A.openpgp.key.asc", []byte("TEST ONLY"), ErrWrongMode, "key-file-mode"},
		"a file that is not an age file":    {adFinal, []byte("not an age file at all"), ErrKeyFile, "key-file"},
		"an empty file":                     {adFinal, nil, ErrKeyFile, "key-file"},
		"the age header and nothing else":   {adFinal, []byte("age-encryption.org/v1\n"), ErrKeyFile, "key-file"},
	} {
		t.Run(name, func(t *testing.T) {
			src := newPassSource(testPass)
			st, _, keys := openPassStore(t, src)
			writeKeyFile(t, keys, c.file, c.data)
			k, err := st.OpenAdopted(bg(), "A", expectOf(s.fk))
			if k != nil {
				t.Errorf("a key is returned")
			}
			wantRefusal(t, err, c.want, c.code)
			if err := st.CheckAdopted(bg(), "A", expectOf(s.fk)); !errors.Is(err, c.want) {
				t.Errorf("CheckAdopted: %v", err)
			}
			if src.calls() != 0 {
				t.Errorf("the source was asked for a file that is refused by its look")
			}
		})
	}
}
