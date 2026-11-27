package software

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"

	"ritueel.id/ritueel/internal/openpgp"
)

// More of the kit of the tests of the adopted key. The names start with ad.

// adSaved is the key file of one algorithm, written once for the test binary: RSA-4096 takes a while to
// open, and a test that only needs a key file to open or to damage copies this one.
type adSaved struct {
	fk   *openpgp.ForeignKey
	file []byte // A.openpgp.key.age, under testPass, at the work factor of the tests
	pkt  []byte // the lone packet that it holds
}

var (
	adSavedMu sync.Mutex
	adSavedBy = map[string]*adSaved{}
)

// adSavedOf saves the base of an algorithm unprotected, once, and returns the file. The calling test
// has called lowWork.
func adSavedOf(t testing.TB, name string) *adSaved {
	t.Helper()
	adSavedMu.Lock()
	defer adSavedMu.Unlock()
	if s, ok := adSavedBy[name]; ok {
		return s
	}
	b := adoptedNamed(t, name)
	// the key is read and kept for the whole binary: it is not wiped at the end of the test that made it
	fk, err := openpgp.ReadForeignKey(b.export(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	st, _, keys := openPassStore(t, adoptedSource(""))
	if err := st.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatalf("SaveAdopted: %v", err)
	}
	pkt, err := fk.SecretPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &adSaved{fk: fk, file: readKeyFile(t, keys, "A.openpgp.key.age"), pkt: pkt}
	adSavedBy[name] = s
	return s
}

// adStoreWith opens a passphrase store whose folder holds the saved file under a label.
func adStoreWith(t testing.TB, s *adSaved, label string, src PassphraseSource) (*Store, string) {
	t.Helper()
	st, _, keys := openPassStore(t, src)
	writeKeyFile(t, keys, label+".openpgp.key.age", s.file)
	return st, keys
}

// adOpen opens the adopted key of an algorithm from the saved file.
func adOpen(t testing.TB, name string) (*AdoptedKey, *adSaved) {
	t.Helper()
	s := adSavedOf(t, name)
	st, _ := adStoreWith(t, s, "A", newPassSource(testPass))
	k, err := st.OpenAdopted(bg(), "A", expectOf(s.fk))
	if err != nil {
		t.Fatalf("OpenAdopted: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k, s
}

// adFresh makes another key of an algorithm than the base (not RSA) and reads its export.
func adFresh(t testing.TB, name string) *openpgp.ForeignKey {
	t.Helper()
	b := adoptedNamed(t, name)
	noNotation := false
	cfg := *b.cfg
	cfg.NonDeterministicSignaturesViaNotation = &noNotation
	e, err := pgp.NewEntity(adoptedUserName, "", "quokka@example.org", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&buf, &cfg); err != nil {
		t.Fatal(err)
	}
	fk, err := openpgp.ReadForeignKey(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fk.Wipe)
	return fk
}

// adSecretWords are the forms of a packet that a leak could take: the packet, its tail (the numbers), the
// hex of both, and the passphrases of the tests.
func adSecretWords(pkt []byte) []string {
	tail := pkt[len(pkt)-40:]
	return []string{
		string(tail), fmt.Sprintf("%x", tail), fmt.Sprintf("%X", tail), fmt.Sprintf("% x", tail[:12]),
		exportPass, testPass, testPass2,
	}
}

// adAllZero says whether every slice that the source gave is cleared.
func adAllZero(t testing.TB, what string, src *passSource) {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	if len(src.given) == 0 {
		t.Errorf("%s: the source gave no slice", what)
	}
	for i, b := range src.given {
		if len(b) > 0 && !allZero(b) {
			t.Errorf("%s: the slice %d still holds the passphrase", what, i)
		}
	}
}

// adAge is the format of the passphrase mode, for a test that opens or writes a file by hand.
var adAge = ageFormat{}
