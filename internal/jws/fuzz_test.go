package jws_test

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"math/big"
	"path"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/testrepo"
)

// vectorFiles returns the files of the root-list vectors that the manifest names with the
// extension ext, by their contents. The manifest says which files there are; nothing here knows a
// name, a size or a byte of them.
func vectorFiles(t testing.TB, ext string) [][]byte {
	t.Helper()
	const dir = "testdata/root-list/v1"
	var m struct {
		Lists []struct {
			Files []string `json:"files"`
		} `json:"lists"`
		Removals []struct {
			File string `json:"file"`
		} `json:"removals"`
	}
	if err := json.Unmarshal(testrepo.Read(t, dir, "manifest.json"), &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	var out [][]byte
	add := func(name string) {
		if path.Ext(name) == ext {
			out = append(out, testrepo.Read(t, dir, name))
		}
	}
	for _, l := range m.Lists {
		for _, f := range l.Files {
			add(f)
		}
	}
	for _, r := range m.Removals {
		add(r.File)
	}
	if len(out) == 0 {
		t.Fatalf("the manifest names no %s file", ext)
	}
	return out
}

// checkGeneral is what every successful reading of a general JWS must satisfy.
func checkGeneral(t *testing.T, data []byte, typ string, g *jws.General) {
	t.Helper()
	if len(data) > jws.MaxBytes {
		t.Fatalf("a file of %d bytes was read", len(data))
	}
	if len(g.Signatures) == 0 {
		t.Fatalf("no signature")
	}
	seen := map[string]bool{}
	for i, s := range g.Signatures {
		if s.Header.Alg != "ES384" || s.Header.Typ != typ || len(s.Header.X5C) != 1 || len(s.Sig) != 96 || s.Cert == nil || s.Protected == "" {
			t.Fatalf("signature %d is not of the form: %+v", i, s.Header)
		}
		if len(s.Header.Kid) != 64 || strings.Trim(s.Header.Kid, "0123456789abcdef") != "" || jws.Pin(s.Cert) != s.Header.Kid {
			t.Fatalf("signature %d: the kid %q is not the pin of its key", i, s.Header.Kid)
		}
		if seen[s.Header.Kid] {
			t.Fatalf("the kid %q appears twice", s.Header.Kid)
		}
		seen[s.Header.Kid] = true
		_ = s.Verify([]byte("anything")) // must not panic
	}
}

func FuzzParseGeneral(f *testing.F) {
	for _, data := range vectorFiles(f, ".jws") {
		f.Add(data, "root-list+json")
	}
	k := newKey(f)
	payload := []byte(`{"sequence":1}`)
	f.Add(file(goodEntry(f, k, typList, payload)), typList)
	f.Add(file(goodEntry(f, k, typList, payload), goodEntry(f, newKey(f), typList, payload)), typList)
	f.Add([]byte(`{"signatures":[]}`), typList)
	f.Add([]byte(``), ``)
	f.Fuzz(func(t *testing.T, data []byte, typ string) {
		g, err := jws.ParseGeneral(data, typ)
		if err != nil {
			if g != nil || !errors.Is(err, jws.ErrMalformed) {
				t.Fatalf("a refusal must have no value and wrap ErrMalformed: %v", err)
			}
			mustBeASCII(t, "the error text", err.Error())
			return
		}
		checkGeneral(t, data, typ, g)
		again, err := jws.ParseGeneral(data, typ)
		if err != nil || len(again.Signatures) != len(g.Signatures) {
			t.Fatalf("a second reading differs: %v", err)
		}
	})
}

func FuzzParseCompact(f *testing.F) {
	for _, data := range vectorFiles(f, ".jws") {
		f.Add(string(data), "root-removal+json")
	}
	k := newKey(f)
	f.Add(goodCompact(f, k, typRemoval, []byte(`{"version":1}`)), typRemoval)
	f.Add(``, ``)
	f.Add(`..`, typRemoval)
	f.Fuzz(func(t *testing.T, s, typ string) {
		c, err := jws.ParseCompact(s, typ)
		if err != nil {
			if c != nil || !errors.Is(err, jws.ErrMalformed) {
				t.Fatalf("a refusal must have no value and wrap ErrMalformed: %v", err)
			}
			mustBeASCII(t, "the error text", err.Error())
			return
		}
		if len(s) > jws.MaxBytes || c.Header.Alg != "ES384" || c.Header.Typ != typ || len(c.Sig) != 96 || c.Cert == nil || jws.Pin(c.Cert) != c.Header.Kid {
			t.Fatalf("a reading that is not of the form: %+v", c.Header)
		}
		if strings.Count(s, ".") != 2 || strings.ContainsAny(s, " \r\n\t=+/") {
			t.Fatalf("the text %q is not the one spelling of a compact JWS", s)
		}
		_ = c.Verify() // must not panic
	})
}

// FuzzVerifyES384 compares the function with the standard library: a signature is accepted exactly
// when it has 96 bytes and ecdsa.Verify accepts its two halves, over the SHA-384 of the input.
func FuzzVerifyES384(f *testing.F) {
	k := newKey(f)
	input := []byte("protected.payload")
	good := k.rawSign(f, input)
	f.Add(input, good)
	f.Add(input, good[:95])
	f.Add(input, make([]byte, 96))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, in, sig []byte) {
		err := jws.VerifyES384(&k.priv.PublicKey, in, sig)
		want := false
		if len(sig) == 96 {
			sum := sha512.Sum384(in)
			want = ecdsa.Verify(&k.priv.PublicKey, sum[:], new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:]))
		}
		if (err == nil) != want {
			t.Fatalf("VerifyES384 = %v, the standard library says %v", err, want)
		}
		if err != nil && !errors.Is(err, jws.ErrSignature) {
			t.Fatalf("the error does not wrap ErrSignature: %v", err)
		}
	})
}
