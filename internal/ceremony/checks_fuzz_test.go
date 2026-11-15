//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
)

// The fuzz targets of the checks of the artifacts. Each takes bytes that a hostile or a broken
// writer could produce, never starts a program, and keeps its laws to what the check promises: no
// panic, an error that is an *ArtifactError of printable ASCII, and what is accepted is the artifact
// that was made.

// mkFixedKey is a key of fixed bytes, so that a failing input replays.
func mkFixedKey(seed byte) *ecdsa.PrivateKey {
	raw := make([]byte, 48)
	for i := range raw {
		raw[i] = seed + byte(i)*3
	}
	raw[0] &= 0x7f
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), raw)
	if err != nil {
		panic(err)
	}
	return k
}

func mkWantArtifactErrorFuzz(t *testing.T, err error) {
	t.Helper()
	ae, ok := mkAs[*ceremony.ArtifactError](err)
	if !ok {
		t.Fatalf("the error is %T: %v", err, err)
	}
	if !pfPrintable(err.Error()) || ae.Artifact == "" || ae.Member == "" || ae.Reason == "" || len(err.Error()) > 4000 {
		t.Fatalf("the error is not whole, printable and short: %.200q", err.Error())
	}
}

func FuzzCheckRootCertificate(f *testing.F) {
	key := mkFixedKey(1)
	good := mkCertSpec{Key: key}.build()
	want := good.Want
	for _, c := range controls() {
		b := c.spec
		if b.Key == nil && b.SPKI == nil {
			b.Key = key
		}
		f.Add(b.build().DER)
	}
	f.Add(good.DER)
	f.Add([]byte(nil))
	f.Add(good.DER[:len(good.DER)/2])
	f.Add(append(append([]byte{}, good.DER...), 0))
	f.Add(bytes.Repeat([]byte{0x30, 0x82}, 100))
	f.Fuzz(func(t *testing.T, der []byte) {
		err := ceremony.CheckRootCertificate(der, want)
		if err != nil {
			mkWantArtifactErrorFuzz(t, err)
			return
		}
		// An accepted certificate is a certificate of the profile: it parses, with no byte after it.
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("an accepted certificate does not parse: %v", err)
		}
		if len(cert.Raw) != len(der) {
			t.Fatalf("bytes after the certificate were accepted")
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		switch {
		case cert.Version != 3 || cert.SignatureAlgorithm != x509.ECDSAWithSHA384:
			t.Fatalf("version %d, algorithm %v", cert.Version, cert.SignatureAlgorithm)
		case cert.Subject.String() != "CN=Example Root A (TEST ONLY)" || !bytes.Equal(cert.RawIssuer, cert.RawSubject):
			t.Fatalf("subject %q", cert.Subject)
		case !ok || pub.Curve != elliptic.P384() || mkPin(pub) != want.Pin:
			t.Fatalf("the key is not the born key")
		case cert.SerialNumber.Text(16) != want.Serial:
			t.Fatalf("serial %x", cert.SerialNumber)
		case !cert.NotBefore.Equal(want.NotBefore) || !cert.NotAfter.Equal(want.NotAfter) || !cert.NotAfter.Equal(mkAddMonths(cert.NotBefore, 36)):
			t.Fatalf("validity %v to %v", cert.NotBefore, cert.NotAfter)
		case !cert.IsCA || !cert.BasicConstraintsValid || cert.MaxPathLen != -1 || cert.MaxPathLenZero:
			t.Fatalf("basic constraints")
		case cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign:
			t.Fatalf("key usage %v", cert.KeyUsage)
		case len(cert.Extensions) != 3 || len(cert.AuthorityKeyId) != 0 || len(cert.PermittedDNSDomains) != 0:
			t.Fatalf("%d extensions", len(cert.Extensions))
		case !bytes.Equal(cert.SubjectKeyId, mkSKI(pub)):
			t.Fatalf("subject key identifier")
		}
		if cert.CheckSignatureFrom(cert) != nil {
			t.Fatalf("an accepted certificate is not signed by its own key")
		}
	})
}

func FuzzCheckRemovalAuthorisation(f *testing.F) {
	key := mkFixedKey(2)
	good := mkRemovalSpec{Key: key}.build()
	other := mkFixedKey(3)
	for _, s := range []string{
		good.Text, "", "a.b.c", good.Text + "\n", good.Text + ".", strings.Repeat(".", 2),
		mkRemovalSpec{Key: key, SignKey: other}.build().Text,
		mkRemovalSpec{Key: key, Typ: "root-list+json"}.build().Text,
		mkRemovalSpec{Key: key, Payload: `{"version":1,"x509_spki_sha256":"x"}`}.build().Text,
		mkRemovalSpec{Key: key, Cert: mkCertSpec{Key: key, Serial: mkSerial(5)}.build().DER}.build().Text,
	} {
		f.Add(s, s)
		f.Add(s, good.Text)
	}
	f.Fuzz(func(t *testing.T, text, stored string) {
		err := ceremony.CheckRemovalAuthorisation("A", good.Pin, good.Cert, text, []byte(stored))
		if err != nil {
			mkWantArtifactErrorFuzz(t, err)
			return
		}
		if stored != text || strings.Count(text, ".") != 2 || strings.ContainsAny(text, " \n\r\t=+/") {
			t.Fatalf("an accepted text is not a compact text that is stored as it is")
		}
		if err := rootlist.CheckRemoval(rootlist.Removal{X509SPKISHA256: good.Pin, Authorisation: text}, nil, []string{good.Pin}); err != nil {
			t.Fatalf("an accepted text is refused by the reader of the root list: %v", err)
		}
	})
}

func FuzzCheckCABundle(f *testing.F) {
	keys := []mkRootKey{{Label: "A"}, {Label: "B"}}
	for i := range keys {
		k := mkFixedKey(byte(10 + i))
		c := mkCertSpec{Key: k, Label: keys[i].Label, Serial: mkSerial(byte(i + 1))}.build()
		keys[i] = mkRootKey{Label: keys[i].Label, Key: k, Cert: c, Pin: mkPin(&k.PublicKey)}
	}
	set := mkSetSpec{Keys: keys}.build(f)
	w := mkWantFor(keys, "A")
	list, err := ceremony.CheckRootList(set, w)
	if err != nil {
		f.Fatal(err)
	}
	good := set.CABundle()
	blk := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	for _, s := range [][]byte{
		good, nil, []byte("# trust-sequence: 1\n"), good[:len(good)-1], append(append([]byte{}, good...), '\n'),
		append([]byte("# trust-sequence: 2\n"), good[len("# trust-sequence: 1\n"):]...),
		bytes.Join([][]byte{[]byte("# trust-sequence: 1\n"), blk(keys[1].Cert.DER), blk(keys[0].Cert.DER)}, nil),
		bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, bundle []byte) {
		err := ceremony.CheckCABundle(bundle, list, w)
		if err != nil {
			mkWantArtifactErrorFuzz(t, err)
			return
		}
		if !bytes.Equal(bundle, good) {
			t.Fatalf("a bundle that is not the one of the set is accepted:\n%q", bundle)
		}
	})
}

func FuzzCheckRootJSON(f *testing.F) {
	want := mkRootJSONWant()
	good := mkRootJSON(f, nil)
	for _, s := range [][]byte{
		good, nil, []byte("{}"), append(append([]byte{}, good...), '\n'), bytes.Replace(good, []byte(`"label":"A"`), []byte(`"label":"B"`), 1),
		mkRootJSON(f, func(r *files.RootJSON) { r.Test = false }),
		mkRootJSON(f, func(r *files.RootJSON) { r.CreatedAt = "2026-11-20T10:00:01Z" }),
		bytes.Replace(good, []byte(`"test":true`), []byte(`"test": true`), 1),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		err := ceremony.CheckRootJSON(b, want)
		if err != nil {
			mkWantArtifactErrorFuzz(t, err)
			return
		}
		if !bytes.Equal(b, good) {
			t.Fatalf("a file that is not the canonical file of the facts is accepted:\n%q", b)
		}
	})
}

func FuzzCheckJournals(f *testing.F) {
	p := pfPlan(f, pfFiles())
	pins, births, sigs := mkJournals(f, p)
	join := func(r ceremony.JournalRead) []byte {
		var out []byte
		for _, l := range r.Lines {
			out = append(out, l...)
			out = append(out, '\n')
		}
		return out
	}
	f.Add(join(births), join(sigs))
	f.Add([]byte(nil), []byte(nil))
	f.Add(join(births), join(sigs)[:len(join(sigs))-5])
	f.Add(join(births)[:30], join(sigs))
	f.Add(join(sigs), join(births))
	f.Add(append(join(births), join(births)...), join(sigs))
	split := func(b []byte) ceremony.JournalRead {
		var r ceremony.JournalRead
		for {
			i := bytes.IndexByte(b, '\n')
			if i < 0 {
				r.Partial = b
				return r
			}
			r.Lines = append(r.Lines, b[:i])
			b = b[i+1:]
		}
	}
	f.Fuzz(func(t *testing.T, b, s []byte) {
		br, sr := split(b), split(s)
		err := ceremony.CheckJournals(p, pins, br, sr)
		if err != nil {
			mkWantArtifactErrorFuzz(t, err)
			return
		}
		if len(br.Partial) != 0 || len(sr.Partial) != 0 || len(br.Lines) != len(p.Births) || len(sr.Lines) != len(p.Signatures) {
			t.Fatalf("accepted journals of %d and %d lines with partial %q %q", len(br.Lines), len(sr.Lines), br.Partial, sr.Partial)
		}
		for i, l := range br.Lines {
			bl, err := files.ReadBirthLine(l)
			if err != nil || bl.Label != p.Births[i].Label || bl.PublicKeySHA256 != pins[bl.Label] {
				t.Fatalf("birth line %d: %+v %v", i, bl, err)
			}
		}
		for i, l := range sr.Lines {
			sl, err := files.ReadSignatureLine(l)
			if err != nil || sl.N != int64(i+1) || sl.Kind != p.Signatures[i].Kind || sl.Key != pins[p.Signatures[i].Subject] {
				t.Fatalf("signature line %d: %+v %v", i, sl, err)
			}
		}
	})
}

// FuzzCheckSignatureDigests gives the check the certificate of A, the removal authorisation of A and the
// lines of the journal of signatures, as any bytes. The laws: no panic; an error is an *ArtifactError
// of printable ASCII; what is accepted is a journal of five whole lines whose first two digests are
// the digests of the signature in the certificate and in the removal authorisation that were given.
func FuzzCheckSignatureDigests(f *testing.F) {
	p := pfPlan(f, pfFiles())
	keys := []mkRootKey{{Label: "A"}, {Label: "B"}}
	for i := range keys {
		k := mkFixedKey(byte(10 + i))
		c := mkCertSpec{Key: k, Label: keys[i].Label, Serial: mkSerial(byte(i + 1))}.build()
		keys[i] = mkRootKey{Label: keys[i].Label, Key: k, Cert: c, Pin: mkPin(&k.PublicKey)}
	}
	set := mkSetSpec{Keys: keys}.build(f)
	removals := map[string]string{}
	certs := map[string][]byte{}
	for _, k := range keys {
		removals[k.Label] = mkRemovalSpec{Key: k.Key, Cert: k.Cert.DER}.build().Text
		certs[k.Label] = k.Cert.DER
	}
	digest := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	sigOfCert := func(der []byte) []byte {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			f.Fatal(err)
		}
		return c.Signature
	}
	sigOfRemoval := func(text string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(text[strings.LastIndex(text, ".")+1:])
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	g, err := jws.ParseGeneral(set.ListJWS(), rootlist.ListTyp)
	if err != nil {
		f.Fatal(err)
	}
	digests := []string{
		digest(sigOfCert(certs["A"])), digest(sigOfRemoval(removals["A"])),
		digest(sigOfCert(certs["B"])), digest(sigOfRemoval(removals["B"])),
		digest(g.Signatures[0].Sig),
	}
	var lines [][]byte
	for i, s := range p.Signatures {
		l, err := (&files.SignatureLine{At: "2026-11-20T10:00:02Z", N: s.N, Kind: s.Kind, Key: mkPin(&keys[i/2%2].Key.PublicKey), SignatureSHA256: digests[i]}).Canonical()
		if err != nil {
			f.Fatal(err)
		}
		lines = append(lines, l)
	}
	join := func(ls [][]byte) []byte { return append(bytes.Join(ls, []byte("\n")), '\n') }
	if err := ceremony.CheckSignatureDigests(p, certs, removals, set, ceremony.JournalRead{Lines: lines}); err != nil {
		f.Fatalf("the first seed is not accepted: %v", err)
	}
	f.Add(certs["A"], removals["A"], join(lines))
	f.Add(certs["B"], removals["A"], join(lines))
	f.Add(certs["A"], removals["B"], join(lines))
	f.Add([]byte(nil), "", []byte(nil))
	f.Add(certs["A"], removals["A"], join(lines[:4]))
	f.Add(certs["A"], removals["A"], join(lines)[:len(join(lines))-9])
	f.Add(certs["A"][:len(certs["A"])-1], removals["A"], join(lines))
	f.Add(certs["A"], removals["A"]+".x", join(lines))
	f.Add(certs["A"], strings.Replace(removals["A"], ".", "..", 1), join(lines))
	f.Fuzz(func(t *testing.T, certA []byte, removalA string, raw []byte) {
		var in ceremony.JournalRead
		for {
			i := bytes.IndexByte(raw, '\n')
			if i < 0 {
				in.Partial = raw
				break
			}
			in.Lines = append(in.Lines, raw[:i])
			raw = raw[i+1:]
		}
		c := map[string][]byte{"A": certA, "B": certs["B"]}
		r := map[string]string{"A": removalA, "B": removals["B"]}
		err := ceremony.CheckSignatureDigests(p, c, r, set, in)
		if err != nil {
			mkWantArtifactErrorFuzz(t, err)
			return
		}
		if len(in.Partial) != 0 || len(in.Lines) != 5 {
			t.Fatalf("accepted %d lines with partial %q", len(in.Lines), in.Partial)
		}
		l0, err0 := files.ReadSignatureLine(in.Lines[0])
		l1, err1 := files.ReadSignatureLine(in.Lines[1])
		pc, perr := x509.ParseCertificate(certA)
		if err0 != nil || err1 != nil || perr != nil {
			t.Fatalf("accepted lines or a certificate that do not read: %v %v %v", err0, err1, perr)
		}
		if l0.SignatureSHA256 != digest(pc.Signature) {
			t.Fatalf("the first line holds %s, the signature of the certificate has %s", l0.SignatureSHA256, digest(pc.Signature))
		}
		if l1.SignatureSHA256 != digest(sigOfRemoval(removalA)) {
			t.Fatalf("the second line holds %s, not the digest of the removal signature", l1.SignatureSHA256)
		}
	})
}
