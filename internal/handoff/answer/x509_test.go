package answer_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // a key identifier of another method, for a test that refuses it
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/pki"
)

// run is the answer of a case with the files changed after they were written.
func (x *x509Case) run(chk *answer.Checker, change func(files map[string][]byte)) (answer.Verdict, error) {
	x.t.Helper()
	ans := x.answer()
	if change != nil {
		change(ans.Files)
	}
	return chk.Check(x.csr.asked(x.t), ans)
}

func nameDER(cn string) []byte {
	return mustMarshal(pkix.Name{CommonName: cn}.ToRDNSequence())
}

const (
	st4 = "pppfnnnnn" // refused at check 4
	st5 = "ppppfnnnn"
	st6 = "pppppfnnn"
	st7 = "ppppppfnn"
	st8 = "pppppppfn"
	st9 = "ppppppppf"
)

// Check 2 for an X.509 answer: the two files and the certificate file's form.
func TestTheFilesOfAnX509AnswerAreExactlyTheTwoOfThePage(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	der := k.newX509(nil).certDER()
	block := func(label string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
	}
	good := block("CERTIFICATE", der)
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	join := func(l []string) []byte { return []byte(strings.Join(l, "\n") + "\n") }
	for _, c := range []struct {
		name string
		file []byte
	}{
		{"not PEM", []byte("not a certificate")},
		{"empty", []byte{}},
		{"a second block", []byte(good + good)},
		{"a header line", join(append([]string{lines[0], "Proc-Type: 4,ENCRYPTED"}, lines[1:]...))},
		{"a blank line", join(append(append([]string{}, lines[:2]...), append([]string{""}, lines[2:]...)...))},
		{"a line of 77 characters", join(append([]string{lines[0], lines[1] + "AAAAAAAAAAAAA"}, lines[2:]...))},
		{"mixed line ends", []byte(strings.Replace(good, "\n", "\r\n", 1))},
		{"a request label", []byte(block("CERTIFICATE REQUEST", der))},
		{"text before the block", []byte("# a note\n" + good)},
		{"text after the block", []byte(good + "x\n")},
		{"two line ends after the block", []byte(good + "\n")},
		{"spaces after the footer", []byte(strings.TrimSuffix(good, "\n") + " \n")},
		{"no line end after the first line", []byte(strings.Replace(good, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE----- \n", 1))},
		{"bytes after the DER", []byte(block("CERTIFICATE", append(bytes.Clone(der), 0)))},
		{"a DER that is not a certificate", []byte(block("CERTIFICATE", []byte{0x30, 0x03, 0x02, 0x01, 0x01}))},
		{"a DER of 100000 nested elements of indefinite length", []byte(block("CERTIFICATE", bytes.Repeat([]byte{0x30, 0x80}, 90000)))},
		{"a DER of zeros", []byte(block("CERTIFICATE", make([]byte, 150000)))},
		{"a DER with a length past the end", []byte(block("CERTIFICATE", []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00}))},
		{"a DER that is one certificate and one more", []byte(block("CERTIFICATE", append(bytes.Clone(der), der...)))},
		{"a great file", bytes.Repeat([]byte("A"), pki.MaxRequestSize+1)},
		{"the standard library's reading of a block with spaces", []byte(strings.Replace(good, "\n", " \n", 2))},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(nil)
			x.der = der
			x.pemFile = c.file
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, malformedAt2)
		})
	}
	t.Run("base64 with bits after the data", func(t *testing.T) {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		for try := 0; try < 40; try++ {
			x := k.newX509(nil)
			text := string(certPEM(x.certDER()))
			ls := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			last := ls[len(ls)-2]
			pad := len(last) - len(strings.TrimRight(last, "="))
			if pad == 0 {
				continue
			}
			i := len(last) - pad - 1
			idx := strings.IndexByte(alphabet, last[i])
			mask := 3
			if pad == 2 {
				mask = 15
			}
			ls[len(ls)-2] = last[:i] + string(alphabet[idx&^mask|((idx+1)&mask)]) + last[i+1:]
			x.pemFile = []byte(strings.Join(ls, "\n") + "\n")
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, malformedAt2)
			return
		}
		t.Fatal("no certificate with a padded last line in 40 tries")
	})
	t.Run("no result file", func(t *testing.T) {
		v, err := k.newX509(nil).run(chk, func(f map[string][]byte) { delete(f, answer.FileResult) })
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
	})
	t.Run("no certificate file", func(t *testing.T) {
		v, err := k.newX509(nil).run(chk, func(f map[string][]byte) { delete(f, answer.FileCert) })
		want(t, v, err, answer.CodeMalformed, malformedAt2)
	})
	t.Run("no files at all", func(t *testing.T) {
		v, err := k.newX509(nil).run(chk, func(f map[string][]byte) { clear(f) })
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
	})
	t.Run("a bound file beside the certificate", func(t *testing.T) {
		v, err := k.newX509(nil).run(chk, func(f map[string][]byte) { f[answer.FileBound] = []byte{1} })
		want(t, v, err, answer.CodeMalformed, malformedAt2)
	})
	t.Run("a file of a name that the page does not give", func(t *testing.T) {
		v, err := k.newX509(nil).run(chk, func(f map[string][]byte) { f["extra.txt"] = []byte("x") })
		want(t, v, err, answer.CodeMalformed, malformedAt2)
	})
	t.Run("a certificate file that is over the limit", func(t *testing.T) {
		v, err := k.newX509(nil).run(chk, func(f map[string][]byte) { f[answer.FileCert] = make([]byte, answer.MaxFileSize+1) })
		want(t, v, err, answer.CodeMalformed, malformedAt2)
	})
	t.Run("the certificate file that CRLF writes, with the digest of the old file", func(t *testing.T) {
		x := k.newX509(nil)
		ans := x.answer()
		ans.Files[answer.FileCert] = bytes.ReplaceAll(ans.Files[answer.FileCert], []byte("\n"), []byte("\r\n"))
		v, err := chk.Check(x.csr.asked(t), ans)
		want(t, v, err, answer.CodeMalformed, st9)
	})
}

// Check 3.
func TestAnAnswerForAnotherRequestIsRefusedAtCheckThree(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	other := newCSR(t, nil, nil)
	for _, c := range []struct {
		name string
		mod  func(x *x509Case)
	}{
		{"one digit of the digest changed", func(x *x509Case) {
			x.with(func(m map[string]any) {
				s := m["request_sha256"].(string)
				m["request_sha256"] = flipHex(s)
			})
		}},
		{"the right digest of another request", func(x *x509Case) {
			x.with(func(m map[string]any) { m["request_sha256"] = sha256Hex(other.der) })
		}},
		{"the digest of the request file and not of its DER", func(x *x509Case) {
			x.with(func(m map[string]any) { m["request_sha256"] = sha256Hex(x.csr.file) })
		}},
		{"the digest of nothing", func(x *x509Case) {
			x.with(func(m map[string]any) { m["request_sha256"] = sha256Hex(nil) })
		}},
		{"another type of the right shape", func(x *x509Case) {
			x.with(func(m map[string]any) {
				m["type"] = "openpgp-subkey"
				m["issuer"] = strings.Repeat("a", 40)
			})
		}},
		{"a type that is ssh-ca-key, of the right shape", func(x *x509Case) {
			x.with(func(m map[string]any) {
				m["type"] = "ssh-ca-key"
				m["artifacts"] = []any{}
				delete(m, "valid_until")
			})
		}},
		{"the answer of another request, with a certificate that is valid", func(x *x509Case) {
			x.der = k.issue(other, certSpec{})
			x.csr = other
			x.with(func(m map[string]any) { m["request_sha256"] = sha256Hex(other.der) })
			x.csr = newCSR(t, nil, nil) // the requester asked for a request of its own
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(nil)
			c.mod(x)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeRequestMismatch, "ppfnnnnnn")
		})
	}
}

func flipHex(s string) string {
	b := []byte(s)
	if b[10] == 'a' {
		b[10] = 'b'
	} else {
		b[10] = 'a'
	}
	return string(b)
}

// Check 4.
func TestTheCertificateMustVerifyToAnAnchorOfTheHeldList(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	issued := func(mod func(x *x509Case)) *x509Case {
		x := k.newX509(nil)
		mod(x)
		return x
	}
	for _, c := range []struct {
		name string
		x    *x509Case
	}{
		{"an issuer that is not on the list", issued(func(x *x509Case) { x.issuerPin = k.z.pin })},
		{"an issuer of 64 digits that is no key at all", issued(func(x *x509Case) { x.issuerPin = strings.Repeat("0", 64) })},
		{"a trust sequence above the held list's", issued(func(x *x509Case) { x.sequence = 8 })},
		{"a trust sequence of the largest safe integer", issued(func(x *x509Case) { x.sequence = 9007199254740991 })},
		{"a certificate of root B that names root A", issued(func(x *x509Case) { x.spec.issuer = &k.b; x.issuerPin = k.a.pin })},
		{"a certificate of root A that names root B", issued(func(x *x509Case) { x.issuerPin = k.b.pin })},
		{"a certificate signed by root Z", issued(func(x *x509Case) { x.spec.issuer = &k.z })},
		{"a certificate signed by root Z that names root A", issued(func(x *x509Case) { x.spec.issuer = &k.z; x.issuerPin = k.a.pin })},
		{"a certificate that names root A and is signed by the key of B", issued(func(x *x509Case) { x.spec.signWith = k.b.key })},
		{"a certificate whose issuer name is the name of root B, signed by A", issued(func(x *x509Case) { x.spec.issuerName = k.b.cert.RawSubject })},
		{"a certificate whose issuer name is in capitals", issued(func(x *x509Case) {
			x.spec.issuerName = nameDER(strings.ToUpper(k.a.cert.Subject.CommonName))
		})},
		{"a certificate whose issuer name is empty", issued(func(x *x509Case) { x.spec.issuerName = mustMarshal(pkix.Name{}.ToRDNSequence()) })},
		{"a signature with SHA-256", issued(func(x *x509Case) { x.spec.sigAlg = oidECDSASHA256; x.spec.digest = crypto.SHA256 })},
		{"a signature with SHA-1", issued(func(x *x509Case) { x.spec.sigAlg = oidECDSASHA1; x.spec.digest = crypto.SHA1 })},
		{"a signature with a flipped bit", issued(func(x *x509Case) { x.spec.flipSigByte = true })},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, err := c.x.check(chk)
			want(t, v, err, answer.CodeIssuer, st4)
		})
	}
	t.Run("the words of the refusals of check 4", func(t *testing.T) {
		for _, c := range []struct {
			x    *x509Case
			text string
		}{
			{issued(func(x *x509Case) { x.issuerPin = k.z.pin }), "issuer is not a root of the root list"},
			{issued(func(x *x509Case) { x.sequence = 8 }), "trust sequence 8"},
			{issued(func(x *x509Case) { x.spec.sigAlg = oidECDSASHA256; x.spec.digest = crypto.SHA256 }), "ecdsa-with-SHA384"},
			{issued(func(x *x509Case) { x.spec.flipSigByte = true }), "does not verify"},
			{issued(func(x *x509Case) { x.spec.issuerName = k.b.cert.RawSubject }), "issuer name"},
		} {
			v, err := c.x.check(chk)
			if err != nil || !strings.Contains(v.Detail, c.text) {
				t.Errorf("detail %q, want it to say %q (%v)", v.Detail, c.text, err)
			}
		}
	})
	t.Run("an anchor of the held list that is not a key on P-384 is no anchor of this contract", func(t *testing.T) {
		p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		odd := newForeignCA(t, caSpec{key: p256, cn: "Example Odd Root"})
		odd.root.label = "C"
		odd.root.primary = newPGPKey(t, pgpPrimaryAt)
		ko := newKit(t)
		ko.writeList([]memRoot{ko.a, odd.root})
		x := ko.newX509(nil)
		x.spec.issuer = &odd.root
		x.spec.exts = profileExts(x.csr, &ko.a.key.PublicKey) // the key identifiers are of a P-384 key
		x.spec.sigAlg, x.spec.digest = oidECDSASHA256, crypto.SHA256
		v, err := x.check(ko.checker(nil))
		want(t, v, err, answer.CodeIssuer, st4)
		if !strings.Contains(v.Detail, "P-384") {
			t.Errorf("detail %q", v.Detail)
		}
	})
	t.Run("a wrong issuer together with a wrong key is the issuer", func(t *testing.T) {
		x := k.newX509(nil)
		x.der = k.issue(newCSR(t, nil, nil), certSpec{})
		x.issuerPin = k.z.pin
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, st4)
	})
	t.Run("a trust sequence of 7 or less is held", func(t *testing.T) {
		for _, seq := range []int64{1, 6, 7} {
			x := k.newX509(nil)
			x.sequence = seq
			v, err := x.check(chk)
			want(t, v, err, "", "ppppppppp")
			if v.Info.TrustSequence != seq {
				t.Errorf("Info holds trust sequence %d for an answer of %d", v.Info.TrustSequence, seq)
			}
		}
	})
	t.Run("the other anchor of the list is used when the pin names it", func(t *testing.T) {
		x := k.newX509(nil)
		x.spec.issuer = &k.b
		v, err := x.check(chk)
		want(t, v, err, "", "ppppppppp")
		if v.Info.Issuer != k.b.pin {
			t.Errorf("issuer %s", v.Info.Issuer)
		}
	})
	t.Run("the list of a higher sequence is held by a checker that holds it", func(t *testing.T) {
		k8 := newKit(t)
		k8.sequence = 8
		k8.writeList([]memRoot{k8.a, k8.b})
		x := k8.newX509(nil)
		x.sequence = 8
		v, err := x.check(k8.checker(nil))
		want(t, v, err, "", "ppppppppp")
	})
}

// Check 4 with the anchor's own dates, with the held list that has expired, and with the choice of the anchor
// by its pin and by nothing else (record 0006, rules 23 and 52).
func TestTheAnchorIsChosenByItsPinAndHasToBeValid(t *testing.T) {
	t.Run("an anchor that is not yet valid", func(t *testing.T) {
		k := newKit(t)
		future := newRootAt(t, "C", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		k.writeList([]memRoot{k.a, future})
		x := k.newX509(nil)
		x.spec.issuer = &future
		v, err := x.check(k.checker(nil))
		want(t, v, err, answer.CodeIssuer, st4)
	})
	t.Run("an anchor that has ended", func(t *testing.T) {
		k := newKit(t)
		old := newRootAt(t, "C", time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC))
		k.writeList([]memRoot{k.a, old})
		x := k.newX509(nil)
		x.spec.issuer = &old
		v, err := x.check(k.checker(nil))
		want(t, v, err, answer.CodeIssuer, st4)
	})
	t.Run("an anchor that ends this second is valid and one that ended a second ago is not", func(t *testing.T) {
		// A root lasts 36 months from its ceremony time.
		k := newKit(t)
		edge := newRootAt(t, "C", time.Date(2023, 11, 15, 12, 0, 0, 0, time.UTC))
		gone := newRootAt(t, "D", time.Date(2023, 11, 15, 11, 59, 59, 0, time.UTC))
		k.writeList([]memRoot{k.a, edge, gone})
		x := k.newX509(nil)
		x.spec.issuer = &edge
		v, err := x.check(k.checker(nil))
		want(t, v, err, "", "ppppppppp")
		y := k.newX509(nil)
		y.spec.issuer = &gone
		v, err = y.check(k.checker(nil))
		want(t, v, err, answer.CodeIssuer, st4)
	})
	t.Run("two anchors of one name and two keys: the pin chooses", func(t *testing.T) {
		k := newKit(t)
		twin := newRoot(t, "A") // the same name as A, another key
		if !bytes.Equal(twin.cert.RawSubject, k.a.cert.RawSubject) || twin.pin == k.a.pin {
			t.Fatal("the twin is not a root of the same name and another key")
		}
		twin.label = "C"
		k.writeList([]memRoot{k.a, twin})
		chk := k.checker(nil)
		x := k.newX509(nil)
		x.spec.issuer = &twin
		v, err := x.check(chk)
		want(t, v, err, "", "ppppppppp")
		if v.Info.Issuer != twin.pin {
			t.Errorf("issuer %s, want the twin's pin", v.Info.Issuer)
		}
		// The certificate of the twin, with the pin of A and the same issuer name: the name does not choose.
		y := k.newX509(nil)
		y.spec.issuer = &twin
		y.issuerPin = k.a.pin
		v, err = y.check(chk)
		want(t, v, err, answer.CodeIssuer, st4)
		// And the other way.
		z := k.newX509(nil)
		z.issuerPin = twin.pin
		v, err = z.check(chk)
		want(t, v, err, answer.CodeIssuer, st4)
	})
	t.Run("the order of the bundle does not choose", func(t *testing.T) {
		k := newKit(t)
		k.writeList([]memRoot{k.b, k.a}) // B first
		x := k.newX509(nil)
		v, err := x.check(k.checker(nil)) // signed by A, names A
		want(t, v, err, "", "ppppppppp")
		y := k.newX509(nil)
		y.issuerPin = k.b.pin
		v, err = y.check(k.checker(nil))
		want(t, v, err, answer.CodeIssuer, st4)
	})
	t.Run("a held list that has expired judges the answer and warns", func(t *testing.T) {
		k := newKit(t)
		k.expires = "2026-11-01T00:00:00Z"
		k.writeList([]memRoot{k.a, k.b})
		v, err := k.newX509(nil).check(k.checker(nil))
		want(t, v, err, "", "ppppppppp")
		if len(v.Warnings) != 1 || v.Warnings[0] != "held-expired" {
			t.Errorf("warnings %v", v.Warnings)
		}
		// The same list at the second before it expires: no warning. At that second: a warning.
		k.expires = "2026-11-15T12:00:01Z"
		k.writeList([]memRoot{k.a, k.b})
		v, err = k.newX509(nil).check(k.checker(nil))
		want(t, v, err, "", "ppppppppp")
		if len(v.Warnings) != 0 {
			t.Errorf("warnings %v one second before the list expires", v.Warnings)
		}
		k.expires = "2026-11-15T12:00:00Z"
		k.writeList([]memRoot{k.a, k.b})
		v, err = k.newX509(nil).check(k.checker(nil))
		want(t, v, err, "", "ppppppppp")
		if len(v.Warnings) != 1 {
			t.Errorf("warnings %v at the second the list expires", v.Warnings)
		}
	})
	t.Run("a warning stands in a refused verdict too", func(t *testing.T) {
		k := newKit(t)
		k.expires = "2026-11-01T00:00:00Z"
		k.writeList([]memRoot{k.a, k.b})
		x := k.newX509(nil)
		x.sequence = 8
		v, err := x.check(k.checker(nil))
		want(t, v, err, answer.CodeIssuer, st4)
		if len(v.Warnings) != 1 {
			t.Errorf("warnings %v", v.Warnings)
		}
	})
}

// Check 5.
func TestTheKeyOfTheCertificateIsTheKeyOfTheRequest(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	t.Run("the key of another request", func(t *testing.T) {
		x := k.newX509(nil)
		x.der = k.issue(newCSR(t, nil, nil), certSpec{})
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, st5)
	})
	t.Run("a key on P-256", func(t *testing.T) {
		p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		x := k.newX509(nil)
		x.spec.spki = spki
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, st5)
	})
	t.Run("a key that is not on a curve", func(t *testing.T) {
		x := k.newX509(nil)
		spki, err := x509.MarshalPKIXPublicKey(x.csr.req.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		bad := bytes.Clone(spki)
		bad[len(bad)-1] ^= 0x01 // the point is not on the curve any more
		x.spec.spki = bad
		v, err := x.check(chk)
		if err != nil || v.Accepted() {
			t.Fatalf("%v accepted %v", err, v.Accepted())
		}
		if v.Code != answer.CodeMalformed || statuses(v) != malformedAt2 {
			t.Errorf("code %q statuses %s: the standard library does not read a point that is not on the curve", v.Code, statuses(v))
		}
	})
	t.Run("the key of the root itself", func(t *testing.T) {
		x := k.newX509(nil)
		spki, err := x509.MarshalPKIXPublicKey(&k.a.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		x.spec.spki = spki
		v, err := x.check(chk)
		want(t, v, err, answer.CodeKeyMismatch, st5)
	})
}

// extsWith returns the profile's six extensions for a request after the change.
func extsWith(k *memKit, c *memCSR, change func(e []pkix.Extension) []pkix.Extension) []pkix.Extension {
	return change(profileExts(c, &k.a.key.PublicKey))
}

func moreExtensions(n int) []pkix.Extension {
	var out []pkix.Extension
	for i := 0; i < n; i++ {
		out = append(out, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, i + 1}, Value: tlv(0x05)})
	}
	return out
}

// Check 6: the profile row by row.
func TestTheProfileIsWhatWasAsked(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	csr := newCSR(t, nil, nil)
	ids := []asn1.ObjectIdentifier{oidBasicConstraints, oidKeyUsage, oidNameConstraints, oidEKU}
	names := []string{"basic constraints", "key usage", "name constraints", "extended key usage"}
	crit := []bool{true, true, true, false}
	cases := []struct {
		name string
		spec certSpec
	}{
		{"a subject that differs in one character", certSpec{subjectDER: mustMarshal(pkix.Name{CommonName: "Example Test Intermediatf", Organization: []string{"acme"}}.ToRDNSequence())}},
		{"a subject of the same text in another order", certSpec{subjectDER: mustMarshal(pkix.Name{CommonName: "Example Test Intermediate"}.ToRDNSequence())}},
		{"a certificate of version 2", certSpec{version: 1}},
		{"a certificate of version 1", certSpec{version: -1}},
		{"a path length of 1", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return replaceExt(e, extBasic(true, 1)) })}},
		{"a key usage that adds cRLSign", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return replaceExt(e, extKeyUsage(true, keyCertSign|0x02)) })}},
		{"a permitted name that is changed", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			return replaceExt(e, extNameConstraints(true, "example.com"))
		})}},
		{"clientAuth where serverAuth was asked", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			return replaceExt(e, extEKU(false, oidClientAuth, oidClientAuth))
		})}},
		{"the two purposes reordered", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			return replaceExt(e, extEKU(false, oidClientAuth, oidServerAuth))
		})}},
		{"a purpose widened", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			return replaceExt(e, extEKU(false, oidServerAuth, oidClientAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}))
		})}},
		{"no authority key identifier", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return dropExt(e, oidAKI) })}},
		{"no subject key identifier", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return dropExt(e, oidSKI) })}},
		{"an extension outside the profile that is not critical", certSpec{extraExts: []pkix.Extension{{Id: oidCertPolicies, Value: tlv(0x30)}}}},
		{"an extension outside the profile that is critical", certSpec{extraExts: []pkix.Extension{{Id: oidCertPolicies, Critical: true, Value: tlv(0x30)}}}},
		{"an authority information access that is not critical", certSpec{extraExts: []pkix.Extension{{Id: oidAIA, Value: tlv(0x30)}}}},
		{"a certificate with no extension at all", certSpec{noExts: true}},
		{"a certificate with 32 extensions", certSpec{extraExts: moreExtensions(26)}},
		{"a certificate with 33 extensions", certSpec{extraExts: moreExtensions(27)}},
		{"a certificate with 400 extensions", certSpec{extraExts: moreExtensions(394)}},
	}
	for i, id := range ids {
		i, id := i, id
		cases = append(cases,
			struct {
				name string
				spec certSpec
			}{"no " + names[i], certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return dropExt(e, id) })}},
			struct {
				name string
				spec certSpec
			}{"the " + names[i] + " with the other criticality", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
				c := e[i]
				c.Critical = !crit[i]
				return replaceExt(e, c)
			})}},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(csr)
			x.spec = c.spec
			v, err := x.check(chk)
			want(t, v, err, answer.CodeProfile, st6)
		})
	}
	t.Run("a certificate that is not version 3 says so", func(t *testing.T) {
		for _, version := range []int{1, -1} {
			x := k.newX509(csr)
			x.spec = certSpec{version: version}
			v, err := x.check(chk)
			want(t, v, err, answer.CodeProfile, st6)
			if v.Detail != "the certificate is not version 3" {
				t.Errorf("version %d: detail %q", version, v.Detail)
			}
		}
	})
	t.Run("a missing extension is named in the detail", func(t *testing.T) {
		for i, id := range ids {
			x := k.newX509(csr)
			x.spec.exts = extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return dropExt(e, id) })
			v, _ := x.check(chk)
			if want := "the certificate has no " + names[i]; v.Detail != want {
				t.Errorf("detail %q, want %q", v.Detail, want)
			}
		}
	})
	t.Run("the limit of the extensions is named in the detail", func(t *testing.T) {
		x := k.newX509(csr)
		x.spec = certSpec{extraExts: moreExtensions(27)}
		v, _ := x.check(chk)
		if !strings.Contains(v.Detail, "more than 32 extensions") {
			t.Errorf("detail %q", v.Detail)
		}
		y := k.newX509(csr)
		y.spec = certSpec{extraExts: moreExtensions(26)}
		v, _ = y.check(chk)
		if strings.Contains(v.Detail, "more than") {
			t.Errorf("detail %q for 32 extensions", v.Detail)
		}
	})
	// The standard library refuses these certificates before the profile is read, so they are malformed at check 2:
	// an extension twice, and a key identifier that is critical.
	for _, c := range []struct {
		name string
		mod  func(e []pkix.Extension) []pkix.Extension
	}{
		{"a critical subject key identifier", func(e []pkix.Extension) []pkix.Extension {
			return append(dropExt(e, oidSKI), pkix.Extension{Id: oidSKI, Critical: true, Value: e[4].Value})
		}},
		{"a critical authority key identifier", func(e []pkix.Extension) []pkix.Extension {
			return append(dropExt(e, oidAKI), pkix.Extension{Id: oidAKI, Critical: true, Value: e[5].Value})
		}},
		{"an authority key identifier twice", func(e []pkix.Extension) []pkix.Extension { return append(e, e[5]) }},
		{"a subject key identifier twice", func(e []pkix.Extension) []pkix.Extension { return append(e, e[4]) }},
		{"the basic constraints twice", func(e []pkix.Extension) []pkix.Extension { return append(e, e[0]) }},
		{"the key usage twice", func(e []pkix.Extension) []pkix.Extension { return append(e, e[1]) }},
		{"the name constraints twice", func(e []pkix.Extension) []pkix.Extension { return append(e, e[2]) }},
		{"the extended key usage twice", func(e []pkix.Extension) []pkix.Extension { return append(e, e[3]) }},
	} {
		t.Run("the standard library refuses "+c.name, func(t *testing.T) {
			x := k.newX509(csr)
			x.spec.exts = extsWith(k, csr, c.mod)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, malformedAt2)
		})
	}
	t.Run("the profile is held before the validity", func(t *testing.T) {
		x := k.newX509(csr)
		x.spec = certSpec{months: 40, exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { return dropExt(e, oidEKU) })}
		v, err := x.check(chk)
		want(t, v, err, answer.CodeProfile, st6)
	})
}

// Check 6 for a request that has the other forms that the page allows.
func TestTheProfileFollowsTheRequestsOwnExtensions(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	t.Run("a request with clientAuth only is issued as asked", func(t *testing.T) {
		csr := newCSR(t, nil, replaceExt(goodExtensions(), extEKU(false, oidClientAuth)))
		v, err := k.newX509(csr).check(chk)
		want(t, v, err, "", "ppppppppp")
	})
	t.Run("a certificate for a request with clientAuth only that holds both purposes", func(t *testing.T) {
		csr := newCSR(t, nil, replaceExt(goodExtensions(), extEKU(false, oidClientAuth)))
		x := k.newX509(csr)
		x.spec.exts = extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			return replaceExt(e, extEKU(false, oidServerAuth, oidClientAuth))
		})
		v, err := x.check(chk)
		want(t, v, err, answer.CodeProfile, st6)
	})
	t.Run("the extensions in the order of the request, not the builder's, are refused at check 8", func(t *testing.T) {
		csr := newCSR(t, nil, nil)
		x := k.newX509(csr)
		x.spec.exts = extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension { e[0], e[3] = e[3], e[0]; return e })
		v, err := x.check(chk)
		want(t, v, err, answer.CodeProfile, st8)
	})
}

// Check 7.
func TestTheValidityIsTheLengthExpectedAndHasNotEnded(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	at := func(h, m, s int) time.Time { return time.Date(2025, 10, 15, h, m, s, 0, time.UTC) }
	for _, c := range []struct {
		name string
		spec certSpec
		code answer.Code
		st   string
	}{
		{"11 months", certSpec{months: 11}, answer.CodeValidity, st7},
		{"12 months passes the length and is not the form of the page", certSpec{months: 12}, answer.CodeProfile, st8},
		{"13 months", certSpec{months: 13}, "", "ppppppppp"},
		{"14 months passes the length and is not the form of the page", certSpec{months: 14}, answer.CodeProfile, st8},
		{"15 months", certSpec{months: 15}, answer.CodeValidity, st7},
		{"36 months", certSpec{months: 36}, answer.CodeValidity, st7},
		{"13 months and a second passes the length and is not the form of the page", certSpec{notAfter: testNow.AddDate(1, 1, 0).Add(time.Second)}, answer.CodeProfile, st8},
		{"ended one second ago", certSpec{notBefore: at(11, 59, 59)}, answer.CodeValidity, st7},
		{"ends now: valid, the period is inclusive", certSpec{notBefore: at(12, 0, 0)}, "", "ppppppppp"},
		{"ends in one second", certSpec{notBefore: at(12, 0, 1)}, "", "ppppppppp"},
		{"starts in one second", certSpec{notBefore: testNow.Add(time.Second)}, answer.CodeValidity, st7},
		{"starts now", certSpec{notBefore: testNow}, "", "ppppppppp"},
		{"starts a second ago", certSpec{notBefore: testNow.Add(-time.Second)}, "", "ppppppppp"},
		{"a validity that ends before it begins", certSpec{notBefore: testNow, notAfter: testNow.Add(-time.Hour)}, answer.CodeValidity, st7},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(nil)
			x.spec = c.spec
			v, err := x.check(chk)
			want(t, v, err, c.code, c.st)
		})
	}
	t.Run("the range is the checker's: 13 to 13", func(t *testing.T) {
		exact := k.checker(func(c *answer.Config) { c.Validity.MinMonths, c.Validity.MaxMonths = 13, 13 })
		for _, months := range []int{12, 14} {
			x := k.newX509(nil)
			x.spec.months = months
			v, err := x.check(exact)
			want(t, v, err, answer.CodeValidity, st7)
		}
		v, err := k.newX509(nil).check(exact)
		want(t, v, err, "", "ppppppppp")
	})
	t.Run("the range is the checker's: 1 to 60", func(t *testing.T) {
		wide := k.checker(func(c *answer.Config) { c.Validity.MinMonths, c.Validity.MaxMonths = 1, 60 })
		x := k.newX509(nil)
		x.spec.months = 36
		v, err := x.check(wide)
		want(t, v, err, answer.CodeProfile, st8) // the length is held, and the form of the page is 13 months
	})
	t.Run("the clock moves: a certificate that is valid ends one second later", func(t *testing.T) {
		x := k.newX509(nil)
		x.spec.notBefore = at(12, 0, 0) // ends 2026-11-15T12:00:00Z
		later := k.checker(func(c *answer.Config) { c.Now = func() time.Time { return testNow.Add(time.Second) } })
		v, err := x.check(later)
		want(t, v, err, answer.CodeValidity, st7)
	})
}

// Check 8: the form of the page, which only the builder's reader holds.
func TestTheCertificateIsExactlyTheFormOfThePage(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	csr := newCSR(t, nil, nil)
	other := sha1.Sum([]byte("a key identifier of another method")) //nolint:gosec // for a test
	for _, c := range []struct {
		name string
		spec certSpec
	}{
		{"a serial of 21 bytes", certSpec{serialLen: 21}},
		{"a serial of 7 bytes: fewer than 64 bits", certSpec{serialLen: 7}},
		{"a subject key identifier of another method", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			e[4] = pkix.Extension{Id: oidSKI, Value: tlv(0x04, other[:])}
			return e
		})}},
		{"an authority key identifier of the wrong key", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			e[5] = pkix.Extension{Id: oidAKI, Value: tlv(0x30, tlv(0x80, other[:]))}
			return e
		})}},
		{"an authority key identifier that adds the issuer name", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			e[5] = pkix.Extension{Id: oidAKI, Value: akiWithIssuerName(t, k)}
			return e
		})}},
		{"the extensions in another order", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			e[2], e[3] = e[3], e[2]
			return e
		})}},
		{"the identifiers before the four", certSpec{exts: extsWith(k, csr, func(e []pkix.Extension) []pkix.Extension {
			return append([]pkix.Extension{e[4], e[5]}, e[:4]...)
		})}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(csr)
			x.spec = c.spec
			v, err := x.check(chk)
			want(t, v, err, answer.CodeProfile, st8)
		})
	}
	t.Run("an algorithm identifier with NULL parameters, which the builder never writes", func(t *testing.T) {
		x := k.newX509(csr)
		x.spec = certSpec{algNull: true}
		v, err := x.check(chk)
		want(t, v, err, answer.CodeProfile, st8)
	})
	t.Run("the certificate that the builder makes passes the same check", func(t *testing.T) {
		v, err := k.newX509(csr).check(chk)
		want(t, v, err, "", "ppppppppp")
	})
}

// Check 9.
func TestTheDigestsAndDatesOfTheResultFileMatchTheFiles(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	good64 := strings.Repeat("a", 64)
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"no artifact", func(m map[string]any) { m["artifacts"] = []any{} }},
		{"two artifacts", func(m map[string]any) {
			a := m["artifacts"].([]map[string]any)
			m["artifacts"] = append(a, map[string]any{"name": "example-answer.other.pem", "sha256": good64})
		}},
		{"another name", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "other-answer.cert.pem", "sha256": m["artifacts"].([]map[string]any)[0]["sha256"]}}
		}},
		{"the name of the result file", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.result.json", "sha256": m["artifacts"].([]map[string]any)[0]["sha256"]}}
		}},
		{"the name of the bound file", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.bound.pgp", "sha256": m["artifacts"].([]map[string]any)[0]["sha256"]}}
		}},
		{"the right name and the digest of another file", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pem", "sha256": good64}}
		}},
		{"the right name and the digest of the DER and not of the file", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pem", "sha256": sha256Hex([]byte("x"))}}
		}},
		{"valid_from one second late", func(m map[string]any) { m["valid_from"] = "2026-11-15T12:00:01Z" }},
		{"valid_from one second early", func(m map[string]any) { m["valid_from"] = "2026-11-15T11:59:59Z" }},
		{"valid_until one second late", func(m map[string]any) { m["valid_until"] = "2027-12-15T12:00:01Z" }},
		{"valid_until of another certificate", func(m map[string]any) { m["valid_until"] = "2028-01-15T12:00:00Z" }},
		{"valid_from and valid_until swapped", func(m map[string]any) { m["valid_from"], m["valid_until"] = m["valid_until"], m["valid_from"] }},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := k.newX509(nil)
			x.with(c.edit)
			v, err := x.check(chk)
			want(t, v, err, answer.CodeMalformed, st9)
		})
	}
	t.Run("the digest of the file as it is: one byte of the certificate file changed after the result was written", func(t *testing.T) {
		x := k.newX509(nil)
		v, err := x.run(chk, func(f map[string][]byte) {
			f[answer.FileCert] = append(f[answer.FileCert], '\n') // two line ends: refused as the form of the file first
		})
		want(t, v, err, answer.CodeMalformed, malformedAt2)
	})
	t.Run("the stem of the answer names the artifact", func(t *testing.T) {
		x := k.newX509(nil)
		x.stem = "another-stem"
		x.with(func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pem", "sha256": sha256Hex(certPEM(x.certDER()))}}
		})
		v, err := x.check(chk)
		want(t, v, err, answer.CodeMalformed, st9)
	})
}

// A refused answer of the certifier.
func TestAnAnswerInWhichTheCertifierRefusedIsNeitherAcceptedNorAFaultOfTheAnswer(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	refused := func(mod func(m map[string]any)) *x509Case {
		x := k.newX509(nil)
		x.with(func(m map[string]any) {
			for _, key := range []string{"artifacts", "valid_from", "valid_until", "issuer"} {
				delete(m, key)
			}
			m["outcome"] = "refused"
			m["reasons"] = []string{"unknown-primary", "policy"}
			if mod != nil {
				mod(m)
			}
		})
		return x
	}
	run := func(x *x509Case, onlyResult bool) (answer.Verdict, error) {
		return x.run(chk, func(f map[string][]byte) {
			if onlyResult {
				delete(f, answer.FileCert)
			}
		})
	}
	t.Run("the verdict", func(t *testing.T) {
		v, err := run(refused(nil), true)
		if err != nil {
			t.Fatal(err)
		}
		if v.Accepted() || v.AnswerRefused() || v.Code != "" || !v.RequestRefused() || v.Info != nil {
			t.Fatalf("accepted %v, answer refused %v, code %q, request refused %v", v.Accepted(), v.AnswerRefused(), v.Code, v.RequestRefused())
		}
		if got := statuses(v); got != "pppnnnnnn" {
			t.Errorf("statuses %s", got)
		}
		if len(v.CertifierReasons) != 2 || v.CertifierReasons[0] != "unknown-primary" || v.CertifierReasons[1] != "policy" {
			t.Errorf("reasons %v", v.CertifierReasons)
		}
		for _, c := range v.Checks[3:] {
			if c.Reason != "the certifier refused the request" {
				t.Errorf("check %d: reason %q", c.N, c.Reason)
			}
		}
	})
	t.Run("the reasons of the verdict are a copy", func(t *testing.T) {
		v, _ := run(refused(nil), true)
		v.CertifierReasons[0] = "declined"
		v2, _ := run(refused(nil), true)
		if v2.CertifierReasons[0] != "unknown-primary" {
			t.Error("a change of the reasons of one verdict changed another")
		}
	})
	t.Run("all eleven codes of the table are read", func(t *testing.T) {
		all := []string{"version-unsupported", "malformed", "request-mismatch", "unknown-primary", "algorithm-unsupported",
			"possession-invalid", "store-not-allowed", "proof-invalid", "key-mismatch", "policy", "declined"}
		for _, code := range all {
			x := refused(func(m map[string]any) { m["reasons"] = []string{code} })
			v, err := run(x, true)
			if err != nil || !v.RequestRefused() || string(v.CertifierReasons[0]) != code {
				t.Errorf("%s: %v %v", code, err, v.CertifierReasons)
			}
		}
		x := refused(func(m map[string]any) { m["reasons"] = all })
		v, err := run(x, true)
		if err != nil || len(v.CertifierReasons) != 11 {
			t.Errorf("all eleven: %v %v", err, v.CertifierReasons)
		}
	})
	t.Run("a refusal of the answer for another request", func(t *testing.T) {
		x := refused(func(m map[string]any) { m["request_sha256"] = strings.Repeat("a", 64) })
		v, err := run(x, true)
		want(t, v, err, answer.CodeRequestMismatch, "ppfnnnnnn")
		if v.RequestRefused() {
			t.Error("a refusal for another request is shown as the certifier's refusal")
		}
	})
	t.Run("a refusal of a version that is not the one sent", func(t *testing.T) {
		x := refused(func(m map[string]any) { m["handoff"] = 2 })
		v, err := run(x, true)
		want(t, v, err, answer.CodeVersionUnsupported, versionRefused)
	})
	for _, c := range []struct {
		name string
		mod  func(m map[string]any)
	}{
		{"a reason that is not in the table", func(m map[string]any) { m["reasons"] = []string{"issuer"} }},
		{"a reason of the requester's table", func(m map[string]any) { m["reasons"] = []string{"validity"} }},
		{"a reason in capitals", func(m map[string]any) { m["reasons"] = []string{"Policy"} }},
		{"two equal reasons", func(m map[string]any) { m["reasons"] = []string{"policy", "policy"} }},
		{"no reason", func(m map[string]any) { m["reasons"] = []string{} }},
		{"reasons that are not a list", func(m map[string]any) { m["reasons"] = "policy" }},
		{"a reason that is a number", func(m map[string]any) { m["reasons"] = []any{1} }},
		{"seventeen reasons", func(m map[string]any) {
			var l []string
			for i := 0; i < 17; i++ {
				l = append(l, "policy")
			}
			m["reasons"] = l
		}},
		{"an artifact", func(m map[string]any) {
			m["artifacts"] = []any{map[string]any{"name": "example-answer.cert.pem", "sha256": strings.Repeat("a", 64)}}
		}},
		{"an empty list of artifacts", func(m map[string]any) { m["artifacts"] = []any{} }},
		{"a valid_from", func(m map[string]any) { m["valid_from"] = "2026-11-15T12:00:00Z" }},
		{"a valid_until", func(m map[string]any) { m["valid_until"] = "2027-12-15T12:00:00Z" }},
		{"an issuer", func(m map[string]any) { m["issuer"] = k.a.pin }},
		{"no trust sequence", func(m map[string]any) { delete(m, "trust_sequence") }},
		{"a trust sequence of zero", func(m map[string]any) { m["trust_sequence"] = 0 }},
		{"no reasons member", func(m map[string]any) { delete(m, "reasons") }},
	} {
		t.Run("malformed: "+c.name, func(t *testing.T) {
			v, err := run(refused(c.mod), true)
			want(t, v, err, answer.CodeMalformed, malformedAt2)
			if v.RequestRefused() {
				t.Error("a malformed refusal is shown as the certifier's")
			}
		})
	}
	t.Run("a list of reasons over the bound is refused for its length and a list of equal ones for its repeat", func(t *testing.T) {
		var seventeen, sixteen []string
		for i := 0; i < 17; i++ {
			seventeen = append(seventeen, "policy")
			if i < 16 {
				sixteen = append(sixteen, "policy")
			}
		}
		v, err := run(refused(func(m map[string]any) { m["reasons"] = seventeen }), true)
		want(t, v, err, answer.CodeMalformed, malformedAt2)
		if !strings.Contains(v.Detail, "more than 16") {
			t.Errorf("detail %q", v.Detail)
		}
		v, err = run(refused(func(m map[string]any) { m["reasons"] = sixteen }), true)
		want(t, v, err, answer.CodeMalformed, malformedAt2)
		if !strings.Contains(v.Detail, "twice") {
			t.Errorf("detail %q", v.Detail)
		}
	})
	t.Run("a certificate file beside a refusal is malformed", func(t *testing.T) {
		v, err := run(refused(nil), false)
		want(t, v, err, answer.CodeMalformed, malformedAt2)
	})
	t.Run("a trust sequence above the held list's is not read as a fault of a refusal", func(t *testing.T) {
		v, err := run(refused(func(m map[string]any) { m["trust_sequence"] = 99 }), true)
		if err != nil || !v.RequestRefused() || v.AnswerRefused() {
			t.Fatalf("%v %v %q", err, v.RequestRefused(), v.Code)
		}
	})
}
