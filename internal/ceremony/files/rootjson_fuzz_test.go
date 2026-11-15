package files_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// FuzzReadRootJSON feeds the reader of roots/<label>/root.json any bytes. The laws: it never panics;
// a refusal is one of the three kinds, with printable ASCII text, and returns no value; an accepted
// file writes in the canonical form without fault, the canonical bytes read back as the same value,
// the canonical form is stable, and a file that is accepted is exactly those bytes: there is no other
// spelling of an accepted file, so no exception to that law.
func FuzzReadRootJSON(f *testing.F) {
	good := encode(f, rjDoc(), nil)
	canon, err := mustRoot(good)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range [][]byte{
		good, canon, nil, []byte("{}"), []byte(`{"version":1}`), []byte(`{"version":2}`), []byte(`{"version":1,"label":"A"}`),
		encode(f, rjDoc(), set("test", false)),
		encode(f, rjDoc(), without("test", "removal_sha256")),
		encode(f, rjDoc(), func(m map[string]any) {
			delete(m, "x509_spki_sha256")
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20), "2026-11-20T09:00:00Z"
		}),
		encode(f, rjDoc(), set("label", "a")), encode(f, rjDoc(), set("store", "hsm")), encode(f, rjDoc(), set("version", 1.5)),
		encode(f, rjDoc(), set("extra", 1)), encode(f, rjDoc(), set("created_at", "2026-11-20T10:00:00.5Z")),
		[]byte(strings.Repeat("[", 5000)), []byte("\xef\xbb\xbf" + string(good)), append(append([]byte{}, good...), good...),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := files.ReadRootJSON(b)
		if err != nil {
			if r != nil {
				t.Fatalf("a value comes with the error %v", err)
			}
			refused(t, err)
			return
		}
		out, err := r.Canonical()
		if err != nil {
			t.Fatalf("an accepted file cannot be written: %v", err)
		}
		if ok, err := canonjson.IsCanonical(out); err != nil || !ok {
			t.Fatalf("Canonical is not canonical: %v", err)
		}
		back, err := files.ReadRootJSON(out)
		if err != nil || *back != *r {
			t.Fatalf("the canonical bytes read back as %+v, %v; want %+v", back, err, *r)
		}
		again, err := back.Canonical()
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("Canonical is not stable")
		}
		if !bytes.Equal(b, out) {
			t.Fatalf("an accepted file is not the bytes that its reading writes:\n%s\n%s", b, out)
		}
		if r.Version != 1 || r.Label == "" || r.Store == "" || r.CreatedAt == "" || (r.X509SPKISHA256 == "" && r.OpenPGPFingerprint == "") {
			t.Fatalf("an accepted file lacks a required member: %+v", r)
		}
	})
}

// mustRoot is the canonical form of the file's reading.
func mustRoot(b []byte) ([]byte, error) {
	r, err := files.ReadRootJSON(b)
	if err != nil {
		return nil, err
	}
	return r.Canonical()
}

func TestAnExplicitTestFalseIsRefusedAsNotCanonical(t *testing.T) {
	// The page says that test is true for a test root key and is silent about a key that is not one.
	// The writer leaves the member out for such a key and never writes false, so a file that says
	// false in words is not the bytes of any reading, and the reader refuses it.
	b := encode(t, rjDoc(), set("test", false))
	r, err := files.ReadRootJSON(b)
	if r != nil || err == nil {
		t.Fatalf("a file with test false is read: %+v, %v", r, err)
	}
	var fe *files.FormatError
	if !errors.As(err, &fe) || fe.Member != "file" {
		t.Fatalf("the error is %T %v, want a *FormatError of the member file", err, err)
	}
	// The same key without the member is read, and its canonical form has no test member.
	b = encode(t, rjDoc(), without("test"))
	r, err = files.ReadRootJSON(b)
	if err != nil || r.Test {
		t.Fatalf("a file without test: %+v, %v", r, err)
	}
	out, err := r.Canonical()
	if err != nil || strings.Contains(string(out), "test") || !bytes.Equal(out, b) {
		t.Errorf("Canonical = %s, %v", out, err)
	}
}
