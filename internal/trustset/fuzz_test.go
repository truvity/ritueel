package trustset_test

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// The fuzz targets run the pure functions on any bytes; none starts a program or touches a file.
// The seeds are the vector files, which the manifest names, so a run in CI (which runs the seeds
// only) reads the vectors too.

// fuzzSpec reads a list file with a plain JSON reader that applies no rule of the page, so that a
// fuzzed list reaches the writer whatever it holds. Bytes that are not a JSON object give no spec.
// A time that does not read is replaced by a time made from the sequence, which gives odd times,
// fractions of a second and years far outside 1 to 9999.
func fuzzSpec(data []byte) (trustset.ListSpec, bool) {
	var raw struct {
		SignedAt         string `json:"signed_at"`
		LastRecordSHA256 string `json:"last_record_sha256"`
		Sequence         int64  `json:"sequence"`
		Roots            []struct {
			Label       string `json:"label"`
			Fingerprint string `json:"openpgp_fingerprint"`
			Pin         string `json:"x509_spki_sha256"`
		} `json:"roots"`
		Removals []struct {
			Authorisation string `json:"authorisation"`
			Label         string `json:"label"`
			Pin           string `json:"x509_spki_sha256"`
		} `json:"removals"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return trustset.ListSpec{}, false
	}
	signed, err := time.Parse(time.RFC3339Nano, raw.SignedAt)
	if err != nil {
		signed = time.Unix(raw.Sequence*1000003, int64(len(raw.SignedAt))*1000+raw.Sequence%7)
	}
	spec := trustset.ListSpec{Sequence: raw.Sequence, SignedAt: signed, LastRecordSHA256: raw.LastRecordSHA256}
	for _, r := range raw.Roots {
		spec.Roots = append(spec.Roots, trustset.Root{Label: r.Label, X509SPKISHA256: r.Pin, OpenPGPFingerprint: r.Fingerprint})
	}
	for _, r := range raw.Removals {
		spec.Removals = append(spec.Removals, trustset.Removal{Label: r.Label, X509SPKISHA256: r.Pin, Authorisation: r.Authorisation})
	}
	return spec, true
}

func FuzzMarshalList(f *testing.F) {
	m := loadVectors(f)
	for _, l := range m.Lists {
		f.Add(vectorFile(f, l.Files[0]))
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"sequence":1,"signed_at":"0001-01-01T00:00:00Z","roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("a", 64) + `"}]}`))
	f.Add([]byte(`{"sequence":1,"signed_at":"2026-01-01T00:00:00Z","roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("a", 64) +
		`"}],"removals":[{"label":"B","x509_spki_sha256":"` + strings.Repeat("a", 64) + `","authorisation":"a.b.c"}]}`))
	f.Add([]byte(`{"sequence":1,"signed_at":"2026-01-01T00:00:00Z","roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("a", 64) +
		`"}],"removals":[{"label":"B","x509_spki_sha256":"` + strings.Repeat("b", 64) + `","authorisation":"a.b.c"},{"label":"B","x509_spki_sha256":"` +
		strings.Repeat("c", 64) + `","authorisation":"a.b.c"}]}`))
	f.Add([]byte(`{"sequence":1,"signed_at":"2026-01-01T00:00:00.5Z","roots":[{"label":"A","x509_spki_sha256":""}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		spec, ok := fuzzSpec(data)
		if !ok {
			return
		}
		out, err := trustset.MarshalList(spec)
		if err != nil {
			if out != nil {
				t.Fatalf("bytes come with the error")
			}
			wantParams(t, err)
			return
		}
		l, err := rootlist.ParseList(out)
		if err != nil {
			t.Fatalf("the reader refuses what was written: %v\n%s", err, out)
		}
		if ok, err := canonjson.IsCanonical(out); err != nil || !ok {
			t.Fatalf("not canonical: %v", err)
		}
		if bytes.HasSuffix(out, []byte("\n")) || len(out) > trustset.MaxBytes {
			t.Fatalf("a trailing newline or %d bytes", len(out))
		}
		if !l.ExpiresAt.Equal(rootlist.ExpiresFor(l.SignedAt)) {
			t.Fatalf("expires_at %v is not 13 months after %v", l.ExpiresAt, l.SignedAt)
		}
		if l.SignedAt.Nanosecond() != 0 || !l.SignedAt.Equal(spec.SignedAt) {
			t.Fatalf("signed_at %v for %v", l.SignedAt, spec.SignedAt)
		}
		for i := 1; i < len(l.Roots); i++ {
			if l.Roots[i-1].Label >= l.Roots[i].Label {
				t.Fatalf("roots are not in label order")
			}
		}
		for i := 1; i < len(l.Removals); i++ {
			if l.Removals[i-1].Label >= l.Removals[i].Label {
				t.Fatalf("removals are not in label order, or a label stands twice")
			}
		}
		if l.SignedAt.IsZero() {
			t.Fatalf("a list with no time was written")
		}
		active := map[string]bool{}
		for _, r := range l.Roots {
			active[r.X509SPKISHA256] = true
		}
		for _, r := range l.Removals {
			if active[r.X509SPKISHA256] {
				t.Fatalf("the pin of removal %s is the pin of a root", r.Label)
			}
		}
		// The order the caller gave changes nothing.
		turned := spec
		turned.Roots, turned.Removals = slices.Clone(spec.Roots), slices.Clone(spec.Removals)
		slices.Reverse(turned.Roots)
		slices.Reverse(turned.Removals)
		if back, err := trustset.MarshalList(turned); err != nil || !bytes.Equal(back, out) {
			t.Fatalf("the entries in the other order give other bytes (%v)", err)
		}
		if (l.Sequence == 1) != (l.LastRecordSHA256 == "") {
			t.Fatalf("sequence %d with the anchor %q", l.Sequence, l.LastRecordSHA256)
		}
		// Writing what was read gives the same bytes.
		again, err := trustset.MarshalList(specOf(l))
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("a second writing differs (%v)", err)
		}
	})
}

// packCerts and unpackCerts carry a list of certificates in the one bytes of a fuzz input: for each
// certificate a length of two bytes and its bytes.
func packCerts(ders ...[]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = binary.BigEndian.AppendUint16(out, uint16(len(d)))
		out = append(out, d...)
	}
	return out
}

func unpackCerts(data []byte) [][]byte {
	var out [][]byte
	for len(data) >= 2 && len(out) < 30 {
		n := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		n = min(n, len(data))
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

func FuzzMarshalCABundle(f *testing.F) {
	m := loadVectors(f)
	a, b := m.certificate(f, "A"), m.certificate(f, "B")
	f.Add(int64(7), packCerts(a, b), byte(0))
	f.Add(int64(8), packCerts(b), byte(0))
	f.Add(int64(7), packCerts(b, a), byte(0))
	f.Add(int64(7), packCerts(a, b), byte(1))
	f.Add(int64(7), packCerts(a, b), byte(2))
	f.Add(int64(7), packCerts(a, b), byte(4))
	f.Add(int64(0), packCerts(a), byte(0))
	f.Add(int64(1), packCerts(), byte(0))
	f.Add(int64(1), packCerts(a[:len(a)-1]), byte(0))
	f.Add(int64(1), packCerts(append(bytes.Clone(a), 0)), byte(0))
	for _, bf := range m.Bundles {
		var ders [][]byte
		rest := vectorFile(f, bf.File)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			ders = append(ders, block.Bytes)
		}
		f.Add(bf.Sequence, packCerts(ders...), byte(0))
	}
	f.Fuzz(func(t *testing.T, seq int64, packed []byte, flags byte) {
		ders := unpackCerts(packed)
		var roots []trustset.Root
		for i, der := range ders {
			r := trustset.Root{Label: string(rune('A' + i%26)), X509SPKISHA256: hexOf(string(der))}
			if c, err := x509.ParseCertificate(der); err == nil {
				r.X509SPKISHA256 = jws.Pin(c)
			}
			if flags&1 != 0 {
				r.OpenPGPFingerprint = hexOf("fp " + r.Label)[:40]
			}
			roots = append(roots, r)
		}
		if flags&2 != 0 && len(roots) > 0 {
			roots[0].X509SPKISHA256 = hexOf("another pin")
		}
		if flags&4 != 0 {
			slices.Reverse(roots)
		}
		out, err := trustset.MarshalCABundle(seq, roots, ders)
		if err != nil {
			if out != nil {
				t.Fatalf("bytes come with the error")
			}
			wantParams(t, err)
			return
		}
		if !strings.HasPrefix(string(out), "# trust-sequence: ") || len(out) > trustset.MaxBytes {
			t.Fatalf("the bundle starts %.40q and has %d bytes", out, len(out))
		}
		if v := verifyAs(out, seq, roots); !v.Accepted {
			t.Fatalf("the reader refuses what was written: %s %s", v.Reason, v.Detail)
		}
		rest := bytes.TrimPrefix(out, []byte("# trust-sequence: "))
		_, rest, _ = bytes.Cut(rest, []byte("\n"))
		for i, der := range ders {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil || !bytes.Equal(block.Bytes, der) {
				t.Fatalf("block %d is not the certificate that was given", i)
			}
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("text after the blocks")
		}
	})
}

func FuzzSetName(f *testing.F) {
	f.Add(int64(1), strings.Repeat("a", 64))
	f.Add(int64(13), "3fa9c1d2"+strings.Repeat("0", 56))
	f.Add(int64(0), strings.Repeat("a", 64))
	f.Add(int64(9007199254740992), strings.Repeat("a", 64))
	f.Add(int64(5), strings.Repeat("A", 64))
	f.Add(int64(5), strings.Repeat("a", 63)+"\x00")
	f.Fuzz(func(t *testing.T, seq int64, digest string) {
		name, err := trustset.SetName(seq, digest)
		if err != nil {
			if name != "" {
				t.Fatalf("a name comes with the error")
			}
			wantParams(t, err)
			return
		}
		if !bundleSpelling.MatchString(name) {
			t.Fatalf("%q is not the spelling of a name", name)
		}
		if !strings.HasSuffix(name, digest[:8]) || !strings.HasPrefix(name, strings.TrimSuffix(name, digest[:8])) {
			t.Fatalf("%q does not end with the first eight characters of %q", name, digest)
		}
	})
}

// FuzzNewRemovalSignerAnswer gives the signer any answer: bytes, an error with any text, a panic.
// No answer that was not made by the key is a valid signature, so the call never gives a text.
func FuzzNewRemovalSignerAnswer(f *testing.F) {
	f.Add([]byte{}, "", byte(0))
	f.Add(make([]byte, 96), "", byte(0))
	f.Add(make([]byte, 95), "", byte(0))
	f.Add(bytes.Repeat([]byte{0xff}, 97), "", byte(0))
	f.Add([]byte{}, "the card was removed \x1b[31m \xff", byte(1))
	f.Add([]byte{}, "boom", byte(2))
	f.Add(make([]byte, 96), "both", byte(3))
	f.Add([]byte{}, "", byte(4))
	f.Add([]byte{}, "", byte(5))
	f.Add([]byte{}, strings.Repeat("\U0001f600", 100), byte(1))
	r := newRoot(f, "A", true)
	f.Fuzz(func(t *testing.T, sig []byte, text string, mode byte) {
		cause := errors.New(text)
		var nilPointer *erroringValue
		s := counting(r.signer(t))
		s.sign = func([]byte) ([]byte, error) {
			switch mode % 6 {
			case 1:
				return nil, cause
			case 2:
				panic(text)
			case 3:
				return sig, cause
			case 4:
				return sig, erroringPanic{}
			case 5:
				return nil, nilPointer
			}
			return sig, nil
		}
		got, err := trustset.NewRemoval(s)
		if err == nil {
			t.Fatalf("a text was made from an answer that the key did not give: %s", got)
		}
		if got != "" {
			t.Fatalf("a text comes with the error")
		}
		// The text of the signer's own error is escaped and cut at 200 bytes, so the text of the
		// error is short whatever the signer says; the kind and the characters are the package's,
		// and the error of the signer is not in the chain.
		wantSign(t, err)
		if errors.Is(err, cause) {
			t.Fatalf("the error of the signer is in the chain")
		}
		if max := len(trustset.ErrSign.Error()+": the signer of A failed: ") + 200 + len("..."); len(err.Error()) > max {
			t.Fatalf("the text of the error is %d bytes, more than %d", len(err.Error()), max)
		}
		if mode%6 == 4 || mode%6 == 5 {
			if !strings.HasSuffix(err.Error(), ": the cause could not be shown") {
				t.Fatalf("an error with no text is shown as %q", err)
			}
		}
		if s.count() != 1 {
			t.Fatalf("the key was asked %d times", s.count())
		}
	})
}
