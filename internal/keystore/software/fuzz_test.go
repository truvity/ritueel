package software

import (
	"bytes"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The fuzz targets read bytes through the Store, over files held in memory (staticFS): no disk,
// no program, and the Store's writer fails the test if it is called. Each target must not panic,
// must return no key with an error, and must give an error that wraps ErrKeyFile.

func mustRefuseWith(t *testing.T, err error, got any, what string) {
	t.Helper()
	if err == nil {
		return
	}
	if got != nil {
		t.Fatalf("%s: a value came with an error", what)
	}
	if !errors.Is(err, ErrKeyFile) && !errors.Is(err, ErrWrongMode) {
		t.Fatalf("%s: the error wraps neither ErrKeyFile nor ErrWrongMode: %v", what, err)
	}
}

func FuzzOpenTestX509(f *testing.F) {
	k := mustGenerate(f)
	for _, c := range x509Refusals(f, k) {
		f.Add(c.file)
	}
	f.Add(x509File(f, k))
	f.Add(bytes.TrimSuffix(x509File(f, k), []byte("\n")))
	f.Add([]byte(testMarker + "\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		s := staticStore(t, map[string][]byte{"A.x509.key.pem": data})
		key, err := s.OpenX509(bg(), "A")
		if err != nil {
			var v any
			if key != nil {
				v = key
			}
			mustRefuseWith(t, err, v, "OpenX509")
			return
		}
		defer func() { _ = key.Close() }()
		// An accepted file may carry the scalar alone, with the curve, or with the point (the page
		// allows each); written again in the form of this package it opens as the same key.
		if !bytes.HasPrefix(data, []byte(testMarker+"\n")) {
			t.Fatal("an accepted file does not start with the marker line")
		}
		again := staticStore(t, map[string][]byte{"A.x509.key.pem": x509File(t, key)})
		k2, err := again.OpenX509(bg(), "A")
		if err != nil {
			t.Fatalf("the key does not open from the file that is written for it: %v", err)
		}
		defer func() { _ = k2.Close() }()
		if !bytes.Equal(scalarBytes(t, key), scalarBytes(t, k2)) {
			t.Fatal("another scalar")
		}
		if len(data) > MaxKeyFileSize {
			t.Fatal("a file over the limit is accepted")
		}
	})
}

func FuzzOpenTestOpenPGP(f *testing.F) {
	k := mustGenerate(f)
	cert := certFor(f, k)
	for _, c := range openPGPRefusals(f, k, cert) {
		f.Add(c.file)
	}
	good := pgpArmor(f, "PGP PRIVATE KEY BLOCK", testOnly, secretOf(f, k, cert))
	f.Add(good)
	f.Add(bytes.TrimSuffix(good, []byte("\n")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		s := staticStore(t, map[string][]byte{"A.openpgp.key.asc": data})
		got, err := s.OpenOpenPGP(bg(), "A")
		if err != nil {
			var v any
			if got != nil {
				v = got
			}
			mustRefuseWith(t, err, v, "OpenOpenPGP")
			return
		}
		defer func() { _ = got.Key.Close() }()
		want := pgpArmor(t, "PGP PRIVATE KEY BLOCK", testOnly, secretOf(t, got.Key, got.Cert))
		if !bytes.Equal(data, want) && !bytes.Equal(data, bytes.TrimSuffix(want, []byte("\n"))) {
			t.Fatalf("an accepted file is not the file of the page (%d bytes, %d expected)", len(data), len(want))
		}
	})
}

func FuzzReadTestRevocation(f *testing.F) {
	k := mustGenerate(f)
	good := revocationFor(f, k, allReasons[0])
	for _, r := range allReasons {
		f.Add(pgpArmor(f, "PGP SIGNATURE", testOnly, revocationFor(f, k, r)))
	}
	f.Add(pgpArmor(f, "PGP SIGNATURE", testOnly, pgpRevocation(f, k.s.priv, testCeremony, 0x10, 0)))
	f.Add(pgpArmor(f, "PGP SIGNATURE", testOnly, append(bytes.Clone(good), good...)))
	f.Add(pgpArmor(f, "PGP MESSAGE", testOnly, good))
	f.Add(good)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		s := staticStore(t, map[string][]byte{"A.revocation.compromised.asc": data})
		sig, err := s.ReadRevocation(bg(), "A", "compromised")
		if err != nil {
			var v any
			if sig != nil {
				v = sig
			}
			mustRefuseWith(t, err, v, "ReadRevocation")
			return
		}
		if len(sig) == 0 || len(sig) > maxRevocationSize || checkRevocation(sig) != nil {
			t.Fatalf("an accepted file gives a packet that checkRevocation refuses (%d bytes)", len(sig))
		}
		want := pgpArmor(t, "PGP SIGNATURE", testOnly, sig)
		if !bytes.Equal(data, want) && !bytes.Equal(data, bytes.TrimSuffix(want, []byte("\n"))) {
			t.Fatal("an accepted file is not the file of the page")
		}
	})
}

func FuzzReadTestRemoval(f *testing.F) {
	for _, s := range []string{"AAAA.BBBB.CCCC", "AAAA.BBBB.CCCC\n", "A.B.C", "..", "AAAA.BBBB", "AAAA.BBBB.CCCC.DDDD", "AB.AA.AA", "AA+A.BBBB.CCCC", ""} {
		f.Add([]byte(s))
	}
	f.Add(jwsOf("a", "b", "c"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := staticStore(t, map[string][]byte{"A.removal.jws": data})
		jws, err := s.ReadRemoval(bg(), "A")
		if err != nil {
			var v any
			if jws != nil {
				v = jws
			}
			mustRefuseWith(t, err, v, "ReadRemoval")
			return
		}
		if !bytes.Equal(jws, data) || len(jws) > maxRemovalSize {
			t.Fatal("an accepted file is not the text of the JWS")
		}
		if bytes.Count(jws, []byte(".")) != 2 {
			t.Fatal("an accepted file has no two dots")
		}
		// Only the characters of Base64url and the two dots: a carriage return and a line feed are
		// refused too, though the standard decoder would skip them.
		for _, c := range jws {
			ok := c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
			if !ok {
				t.Fatalf("an accepted file holds the byte %#x", c)
			}
		}
	})
}

// A name listed in a folder is data from the folder: no name makes the listing panic, and a name
// that is taken for a key file is a name that the package itself would write.
func FuzzKeyFileName(f *testing.F) {
	for _, n := range keyFileNamesOfBothModes() {
		f.Add(n)
	}
	for _, n := range []string{"", ".", "..", ".rt-abcdefghijk", "A.x509.key.pem\x00", "a.x509.key.pem", "A.revocation..asc"} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, name string) {
		m, ok := isKeyFileName(name)
		if !ok {
			return
		}
		if fsx.CheckName(name) != nil || !labelOK(name[:1]) || m == 0 {
			t.Fatalf("%q is taken for a key file", name)
		}
		// The name is one of those that fileName makes for the label and a kind.
		found := false
		for _, kind := range []FileKind{FileX509, FileOpenPGP, FileRemoval} {
			found = found || fileName(m, name[:1], kind, "") == name
		}
		for _, r := range reasons {
			found = found || fileName(m, name[:1], FileRevocation, r.Text) == name
		}
		if !found {
			t.Fatalf("%q is a key file name that no kind makes", name)
		}
	})
}

func FuzzLabelAndReasonMakeNamesThatFsxAccepts(f *testing.F) {
	f.Add("A", "compromised")
	f.Add("Z", "no-reason")
	f.Add("a", "")
	f.Add("A\x00", "../x")
	f.Fuzz(func(t *testing.T, label, reason string) {
		if !labelOK(label) {
			return
		}
		for _, m := range []Mode{ModeTest, ModePassphrase} {
			for _, kind := range []FileKind{FileX509, FileOpenPGP, FileRemoval} {
				if n := fileName(m, label, kind, ""); fsx.CheckName(n) != nil {
					t.Fatalf("%q", n)
				}
			}
			if reasonOK(reason) {
				if n := fileName(m, label, FileRevocation, reason); fsx.CheckName(n) != nil {
					t.Fatalf("%q", n)
				}
			}
		}
	})
}
