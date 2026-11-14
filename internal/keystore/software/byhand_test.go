package software

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

var keepDir = flag.String("keep", "", "a folder that TestByHand writes a test root's key files into, to be looked at by hand")

// TestByHand writes the four key files of a test root for the label A, reads them back and prints
// their names and modes, never their contents. With -keep DIR the files stay in DIR (an empty
// folder that is not inside a work tree); without it they are in a temporary folder. It checks the
// same things in both cases.
func TestByHand(t *testing.T) {
	bundle, keys := newBundle(t)
	if *keepDir != "" {
		keys = *keepDir
	}
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModeTest})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if has, err := s.HasKeyFiles(); err != nil || has {
		t.Fatalf("the folder is not empty (%v, %v): use a new folder", has, err)
	}
	k := mustGenerate(t)
	cert := certFor(t, k)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRevocation("A", "compromised", revocationFor(t, k, openpgp.Compromised)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRemoval("A", jwsOf("a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	want := []string{"A.openpgp.key.asc", "A.removal.jws", "A.revocation.compromised.asc", "A.x509.key.pem"}
	got := dirNames(t, keys)
	if len(got) != len(want) {
		t.Fatalf("the folder holds %v, want %v", got, want)
	}
	for i, n := range got {
		if n != want[i] {
			t.Errorf("name %d is %s, want %s", i, n, want[i])
		}
		info, err := os.Stat(filepath.Join(keys, n))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v (%v)", n, info.Mode().Perm(), err)
		}
		t.Logf("%s %s", info.Mode(), n)
	}
	if _, err := s.OpenX509(bg(), "A"); err != nil {
		t.Error(err)
	}
	if _, err := s.OpenOpenPGP(bg(), "A"); err != nil {
		t.Error(err)
	}
	if !k.Saved() {
		t.Error("not Saved")
	}
}
