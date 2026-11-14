package software

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"sync"
	"testing"
)

// Writing a key to a file copies its scalar and clears the copy. The key itself goes on signing: the
// scalar that crypto/ecdsa keeps for it is not cleared, and a signature made while the file is
// written verifies.

func TestAKeyStillSignsAfterEachOfItsFilesIsWritten(t *testing.T) {
	s, _, _ := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	digest := sha512.Sum384([]byte("after the save"))
	check := func(when string) {
		t.Helper()
		sig, err := k.Sign(nil, digest[:], crypto.SHA384)
		if err != nil || !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), digest[:], sig) {
			t.Fatalf("%s: the key does not sign: %v", when, err)
		}
	}
	check("before")
	before := scalarBytes(t, k)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	check("after SaveX509")
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatal(err)
	}
	check("after SaveOpenPGP")
	// A refused save leaves it alone too.
	if err := s.SaveOpenPGP("B", k, certFor(t, mustGenerate(t))); err == nil {
		t.Fatal("a certificate of another key was accepted")
	}
	check("after a refused SaveOpenPGP")
	if got := scalarBytes(t, k); string(got) != string(before) {
		t.Error("the scalar of the key changed")
	}
}

func TestSigningWhileTheSecretKeyFileIsWrittenGivesSignaturesThatVerify(t *testing.T) {
	s, _, _ := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	digest := sha512.Sum384([]byte("concurrent"))
	var wg sync.WaitGroup
	bad := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			sig, err := k.Sign(nil, digest[:], crypto.SHA384)
			if err != nil || !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), digest[:], sig) {
				select {
				case bad <- "a signature made during a save does not verify":
				default:
				}
				return
			}
		}
	}()
	for _, label := range []string{"A", "B", "C", "D", "E", "F"} {
		if err := s.SaveOpenPGP(label, k, cert); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}
	wg.Wait()
	close(bad)
	for m := range bad {
		t.Error(m)
	}
}
