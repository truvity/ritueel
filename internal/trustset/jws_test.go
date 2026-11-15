package trustset

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

// signFile signs a list with each key and returns the pieces that marshalGeneral takes, in the
// order of the keys.
func signFile(t testing.TB, listJSON []byte, typ string, keys ...ikey) []fileSignature {
	t.Helper()
	var sigs []fileSignature
	for _, k := range keys {
		info, err := inspect(k.signer)
		if err != nil {
			t.Fatal(err)
		}
		protected, err := protectedText(info, typ)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := ask(k.signer, info, jws.SigningInput(protected, listJSON))
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, fileSignature{protected: protected, sig: sig})
	}
	return sigs
}

// firstList is the first list of the keys, in the bytes MarshalList writes.
func firstList(t testing.TB, keys ...ikey) []byte {
	t.Helper()
	var roots []Root
	for _, k := range keys {
		roots = append(roots, Root{Label: k.label, X509SPKISHA256: k.pin})
	}
	out, err := MarshalList(ListSpec{Sequence: 1, SignedAt: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The header is the canonical JSON of the four members in the order alg, kid, typ, x5c.
func TestProtectedTextIsTheFourMembersInOrder(t *testing.T) {
	k := newIKey(t, "A", 0)
	info, err := inspect(k.signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{rootlist.ListTyp, rootlist.RemovalTyp} {
		got, err := protectedText(info, typ)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("not Base64url without padding: %v", err)
		}
		want := `{"alg":"ES384","kid":"` + k.pin + `","typ":"` + typ + `","x5c":["` + base64.StdEncoding.EncodeToString(k.cert.Raw) + `"]}`
		if string(raw) != want {
			t.Errorf("typ %s:\n got  %s\n want %s", typ, raw, want)
		}
		if strings.ContainsAny(got, "=+/") {
			t.Errorf("the text has padding or a character of standard Base64: %s", got)
		}
	}
}

func TestMarshalGeneralWritesTheFileOfThePage(t *testing.T) {
	a, c, z := newIKey(t, "A", 0), newIKey(t, "C", 0), newIKey(t, "Z", 0)
	listJSON := firstList(t, a, c, z)
	sigs := signFile(t, listJSON, rootlist.ListTyp, a, c, z)
	out, err := marshalGeneral(sigs)
	if err != nil {
		t.Fatal(err)
	}
	// The exact bytes, written out by hand: one object, one member, the signatures in the order given.
	var want strings.Builder
	want.WriteString(`{"signatures":[`)
	for i, s := range sigs {
		if i > 0 {
			want.WriteString(",")
		}
		want.WriteString(`{"protected":"` + s.protected + `","signature":"` + base64.RawURLEncoding.EncodeToString(s.sig) + `"}`)
	}
	want.WriteString(`]}`)
	if string(out) != want.String() {
		t.Fatalf("got  %s\nwant %s", out, want.String())
	}
	if ok, err := canonjson.IsCanonical(out); err != nil || !ok {
		t.Errorf("not canonical: %v", err)
	}
	if bytes.HasSuffix(out, []byte("\n")) {
		t.Errorf("a trailing newline")
	}
	// The reader of the page reads it, in the order given, with the kid of each signer.
	g, err := jws.ParseGeneral(out, rootlist.ListTyp)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Signatures) != 3 {
		t.Fatalf("%d signatures", len(g.Signatures))
	}
	for i, k := range []ikey{a, c, z} {
		s := g.Signatures[i]
		if s.Header.Kid != k.pin || s.Header.Typ != "root-list+json" || s.Header.Alg != "ES384" || len(s.Sig) != 96 {
			t.Errorf("signature %d: %+v", i, s.Header)
		}
		if err := s.Verify(listJSON); err != nil {
			t.Errorf("signature %d does not verify: %v", i, err)
		}
	}
	// The whole of the host's reading: the list is accepted against the pins of its keys, and
	// against the pin of one of them alone.
	clock := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, pins := range [][]string{{a.pin, c.pin, z.pin}, {c.pin}} {
		trust, err := rootlist.PinTrust(pins)
		if err != nil {
			t.Fatal(err)
		}
		if v := rootlist.Verify(rootlist.Signed{JSON: listJSON, JWS: out}, trust, clock); !v.Accepted {
			t.Errorf("pins %v: %s %d %s", pins, v.Reason, v.Check, v.Detail)
		}
	}
}

// A signature file of one signature is a file of the page, and of 26 too; 27 is not.
func TestMarshalGeneralLimits(t *testing.T) {
	keys := make([]ikey, 0, 27)
	for i := 0; i < 27; i++ {
		keys = append(keys, newIKey(t, string(rune('A'+i%26)), 0))
	}
	listJSON := firstList(t, keys[0])
	all := signFile(t, listJSON, rootlist.ListTyp, keys...)
	for _, n := range []int{1, 2, 26} {
		out, err := marshalGeneral(all[:n])
		if err != nil {
			t.Errorf("%d signatures: %v", n, err)
			continue
		}
		g, err := jws.ParseGeneral(out, rootlist.ListTyp)
		if err != nil || len(g.Signatures) != n {
			t.Errorf("%d signatures read back as %v, %v", n, g, err)
		}
	}
	for _, c := range []struct {
		name string
		sigs []fileSignature
	}{
		{"none", nil},
		{"an empty list", []fileSignature{}},
		{"27", all[:27]},
	} {
		out, err := marshalGeneral(c.sigs)
		if err == nil || out != nil {
			t.Errorf("%s: %q, %v", c.name, out, err)
			continue
		}
		kindOf(t, err, ErrParams)
		if !strings.Contains(err.Error(), "from 1 to 26 signatures") {
			t.Errorf("%s: the refusal %q does not say how many signatures a file holds", c.name, err)
		}
	}
}

func TestMarshalGeneralRefusals(t *testing.T) {
	a, c := newIKey(t, "A", 0), newIKey(t, "C", 0)
	listJSON := firstList(t, a, c)
	good := signFile(t, listJSON, rootlist.ListTyp, a, c)
	removalHeader := signFile(t, listJSON, rootlist.RemovalTyp, a)
	withSig := func(i int, sig []byte) []fileSignature {
		out := append([]fileSignature(nil), good...)
		out[i].sig = sig
		return out
	}
	withProtected := func(i int, p string) []fileSignature {
		out := append([]fileSignature(nil), good...)
		out[i].protected = p
		return out
	}
	why := func(name string) string {
		switch {
		case strings.Contains(name, "bytes") && strings.Contains(name, "signature"), name == "no signature bytes":
			return "is not 96 bytes"
		case name == "an empty protected text":
			return "has no header"
		}
		return "the reader of the page refuses"
	}
	for _, c := range []struct {
		name string
		sigs []fileSignature
	}{
		{"a signature of 95 bytes", withSig(0, make([]byte, 95))},
		{"a signature of 97 bytes", withSig(1, make([]byte, 97))},
		{"no signature bytes", withSig(0, nil)},
		{"a signature of 48 bytes", withSig(0, make([]byte, 48))},
		{"an empty protected text", withProtected(0, "")},
		{"a protected text that is not Base64url", withProtected(0, "!!!")},
		{"a protected text with padding", withProtected(0, good[0].protected+"=")},
		{"a protected text of garbage", withProtected(1, base64.RawURLEncoding.EncodeToString([]byte("not json")))},
		{"a protected text of an empty object", withProtected(1, base64.RawURLEncoding.EncodeToString([]byte("{}")))},
		{"a protected text with another typ", append([]fileSignature(nil), removalHeader[0])},
		{"the same signature twice (one kid twice)", []fileSignature{good[0], good[0]}},
		{"the same signer twice with two signatures", []fileSignature{good[0], good[1], signFile(t, listJSON, rootlist.ListTyp, a)[0]}},
	} {
		out, err := marshalGeneral(c.sigs)
		if err == nil {
			t.Errorf("%s: accepted %s", c.name, out)
			continue
		}
		if out != nil {
			t.Errorf("%s: bytes come with the error", c.name)
		}
		kindOf(t, err, ErrParams)
		if w := why(c.name); !strings.Contains(err.Error(), w) {
			t.Errorf("%s: the refusal %q does not say %q", c.name, err, w)
		}
	}
}

// The order of the signatures is the order given: the writer sorts nothing.
func TestMarshalGeneralKeepsTheOrderGiven(t *testing.T) {
	a, c, z := newIKey(t, "A", 0), newIKey(t, "C", 0), newIKey(t, "Z", 0)
	listJSON := firstList(t, a, c, z)
	sigs := signFile(t, listJSON, rootlist.ListTyp, z, a, c)
	out, err := marshalGeneral(sigs)
	if err != nil {
		t.Fatal(err)
	}
	g, err := jws.ParseGeneral(out, rootlist.ListTyp)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range []ikey{z, a, c} {
		if g.Signatures[i].Header.Kid != k.pin {
			t.Errorf("signature %d is not by %s", i, k.label)
		}
	}
}

// A file over the limit is refused: 26 signatures whose certificates are large.
func TestMarshalGeneralOverTheLimit(t *testing.T) {
	var keys []ikey
	for i := 0; i < MaxRoots; i++ {
		keys = append(keys, newIKey(t, string(rune('A'+i)), 8000))
	}
	listJSON := firstList(t, keys[0])
	sigs := signFile(t, listJSON, rootlist.ListTyp, keys...)
	out, err := marshalGeneral(sigs)
	if err == nil {
		t.Fatalf("a file of %d bytes", len(out))
	}
	if out != nil {
		t.Errorf("bytes come with the error")
	}
	kindOf(t, err, ErrParams)
	// (The canonical writer has the same limit and says it first.)
	if !strings.Contains(err.Error(), "longer than 262144 bytes") {
		t.Errorf("the refusal %q does not say that the file is too long", err)
	}
	// Ten of the same are under the limit.
	if out, err := marshalGeneral(sigs[:10]); err != nil || len(out) > MaxBytes {
		t.Errorf("ten signatures: %d bytes, %v", len(out), err)
	}
}

// The writer's file is not the reader's only form: a header with a member added, written by hand,
// is refused by the reader, so the writer's four members are the exact shape.
func TestReaderRefusesAHeaderWithAMemberAdded(t *testing.T) {
	a := newIKey(t, "A", 0)
	listJSON := firstList(t, a)
	info, err := inspect(a.signer)
	if err != nil {
		t.Fatal(err)
	}
	protected := `{"alg":"ES384","extra":1,"kid":"` + a.pin + `","typ":"root-list+json","x5c":["` + base64.StdEncoding.EncodeToString(a.cert.Raw) + `"]}`
	text := base64.RawURLEncoding.EncodeToString([]byte(protected))
	sig, err := ask(a.signer, info, jws.SigningInput(text, listJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := marshalGeneral([]fileSignature{{protected: text, sig: sig}}); err == nil {
		t.Errorf("a header with a fifth member was written")
	}
}
