package trustset_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/trustset"
)

// Every refusal of the certificates of the keyring file is an ErrParams, is told by NewDraft before
// any key is asked, returns no draft, and carries the sentence of the reader of the keyring file (or
// the sentence of the builder, for what the reader is not asked). The text is plain printable ASCII
// and shows no byte of a hostile certificate.

// refusesCerts runs NewDraft on the input and checks the refusal. It also shows that no signer can be
// asked: there is no draft, and the nil draft refuses to sign.
func refusesCerts(t *testing.T, in trustset.Input, want ...string) {
	t.Helper()
	d, err := trustset.NewDraft(in)
	if d != nil {
		t.Fatalf("a draft came with the error %v", err)
	}
	wantOnly(t, err, trustset.ErrParams)
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the error %q does not hold %q", err, w)
		}
	}
	signers := []*scriptedSigner{counting(newRoot(t, "A", true).signer(t)), counting(newRoot(t, "B", true).signer(t))}
	set, err2 := d.Sign(asSigners(signers), nil)
	if set != nil {
		t.Error("a nil draft signed")
	}
	wantOnly(t, err2, trustset.ErrParams)
	zeroCalls(t, signers)
}

// A certificate with its tag-14 packet: a subkey, which comes with a later form.
func withSubkey(cert []byte) []byte {
	return append(slices.Clone(cert), 0xCE, 0x04, 0x04, 0x00, 0x00, 0x00)
}

func TestKeyringRefusals(t *testing.T) {
	a, b, c := newRoot(t, "A", true), newRoot(t, "B", true), newRoot(t, "C", true)
	cases := []struct {
		name   string
		mutate func(in *trustset.Input)
		want   []string
	}{
		{"a missing label", func(in *trustset.Input) { delete(in.OpenPGPCertificates, "B") },
			[]string{"there are 1 OpenPGP certificates for 2 roots"}},
		{"no certificates at all", func(in *trustset.Input) { in.OpenPGPCertificates = nil },
			[]string{"there are 0 OpenPGP certificates for 2 roots"}},
		{"an empty map", func(in *trustset.Input) { in.OpenPGPCertificates = map[string][]byte{} },
			[]string{"there are 0 OpenPGP certificates for 2 roots"}},
		{"an extra label", func(in *trustset.Input) { in.OpenPGPCertificates["C"] = c.PGP },
			[]string{"there are 3 OpenPGP certificates for 2 roots"}},
		{"a label that is not a root instead of a root", func(in *trustset.Input) {
			delete(in.OpenPGPCertificates, "B")
			in.OpenPGPCertificates["C"] = c.PGP
		}, []string{"there is no OpenPGP certificate for root B"}},
		{"a certificate of a primary that the list does not pin", func(in *trustset.Input) { in.OpenPGPCertificates["A"] = c.PGP },
			[]string{"not on the list", "certificate 1", "label A"}},
		{"a swapped pair", func(in *trustset.Input) {
			in.OpenPGPCertificates["A"], in.OpenPGPCertificates["B"] = b.PGP, a.PGP
		}, []string{"out of order", "label A"}},
		{"the same certificate for both", func(in *trustset.Input) { in.OpenPGPCertificates["B"] = a.PGP },
			[]string{"repeats"}},
		{"a certificate with a subkey", func(in *trustset.Input) { in.OpenPGPCertificates["A"] = withSubkey(a.PGP) },
			[]string{"Public-Subkey", "label A"}},
		{"a certificate with a subkey, the last one", func(in *trustset.Input) { in.OpenPGPCertificates["B"] = withSubkey(b.PGP) },
			[]string{"Public-Subkey", "label B"}},
		{"an armoured certificate", func(in *trustset.Input) {
			in.OpenPGPCertificates["A"] = []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ==\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n")
		}, []string{"armoured"}},
		{"an armoured second certificate", func(in *trustset.Input) {
			in.OpenPGPCertificates["B"] = []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ==\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n")
		}, nil},
		{"a certificate over the limit", func(in *trustset.Input) {
			in.OpenPGPCertificates["A"] = append(slices.Clone(a.PGP), make([]byte, trustset.MaxBytes)...)
		}, []string{"root A", "longer than"}},
		{"a nil certificate", func(in *trustset.Input) { in.OpenPGPCertificates["A"] = nil },
			[]string{"root A", "empty"}},
		{"an empty certificate", func(in *trustset.Input) { in.OpenPGPCertificates["B"] = []byte{} },
			[]string{"root B", "empty"}},
		{"a certificate that stops short", func(in *trustset.Input) { in.OpenPGPCertificates["B"] = b.PGP[:len(b.PGP)-1] }, nil},
		{"a certificate with a byte after it", func(in *trustset.Input) { in.OpenPGPCertificates["B"] = append(slices.Clone(b.PGP), 0) }, nil},
		{"a certificate of one byte", func(in *trustset.Input) { in.OpenPGPCertificates["A"] = []byte{0xC6} }, nil},
		{"a certificate of text", func(in *trustset.Input) { in.OpenPGPCertificates["A"] = []byte("not a certificate") }, nil},
		{"a certificate with its signature twice", func(in *trustset.Input) {
			sig := packetsOf(t, a.PGP)[2]
			in.OpenPGPCertificates["A"] = append(slices.Clone(a.PGP), sig...)
		}, []string{"repeats certification"}},
		{"a certificate with a second user ID", func(in *trustset.Input) {
			uid := packetsOf(t, a.PGP)[1]
			in.OpenPGPCertificates["A"] = slices.Concat(packetsOf(t, a.PGP)[0], uid, uid, packetsOf(t, a.PGP)[2])
		}, []string{"second user ID"}},
		{"a certificate with no certification", func(in *trustset.Input) {
			p := packetsOf(t, a.PGP)
			in.OpenPGPCertificates["A"] = slices.Concat(p[0], p[1])
		}, []string{"no certification"}},
		{"a certificate with no user ID", func(in *trustset.Input) {
			p := packetsOf(t, a.PGP)
			in.OpenPGPCertificates["A"] = slices.Concat(p[0], p[2])
		}, nil},
		{"a certification over a foreign user ID", func(in *trustset.Input) {
			// The key and the user ID of A with the certification of B: the reader checks the signature.
			p, q := packetsOf(t, a.PGP), packetsOf(t, b.PGP)
			in.OpenPGPCertificates["A"] = slices.Concat(p[0], p[1], q[2])
		}, []string{"certification 1"}},
		{"more than 256 certifications", func(in *trustset.Input) {
			sig := packetsOf(t, a.PGP)[2]
			cert := slices.Clone(a.PGP)
			for i := 0; i < 256; i++ {
				cert = append(cert, sig...)
			}
			in.OpenPGPCertificates["A"] = cert
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := keyringInput(t, "A", "B")
			tc.mutate(&in)
			refusesCerts(t, in, tc.want...)
		})
	}
}

// A map for a list whose roots have no fingerprint is refused: such a set has no keyring file.
func TestKeyringCertificatesForAListWithNoFingerprint(t *testing.T) {
	for name, certs := range map[string]map[string][]byte{
		"the right certificates": {"A": newRoot(t, "A", true).PGP, "B": newRoot(t, "B", true).PGP},
		"one certificate":        {"A": newRoot(t, "A", true).PGP},
		"a nil certificate":      {"A": nil},
		"a label of no root":     {"Z": newRoot(t, "A", true).PGP},
	} {
		t.Run(name, func(t *testing.T) {
			in := newChain(t).input(next{labels: []string{"A", "B"}, noPrint: true})
			in.OpenPGPCertificates = certs
			refusesCerts(t, in, "no root has an OpenPGP fingerprint")
		})
	}
}

// A list in which some roots have a fingerprint and some have none is refused by the list writer (the
// keyring file is never made for part of a list), whatever certificates are given.
func TestKeyringForAListWithSomeFingerprints(t *testing.T) {
	in := keyringInput(t, "A", "B")
	in.Roots[1].OpenPGPFingerprint = ""
	d, err := trustset.NewDraft(in)
	if d != nil {
		t.Fatal("a draft came for a list of which only one root has a fingerprint")
	}
	wantOnly(t, err, trustset.ErrParams)
}

// The size of one certificate is held to MaxBytes by the builder: a certificate of exactly MaxBytes
// goes on to the reader (which refuses it for its form), one byte more is the builder's own refusal.
func TestKeyringCertificateSizeLimit(t *testing.T) {
	a := newRoot(t, "A", true)
	for _, tc := range []struct {
		n    int
		mine bool
	}{{trustset.MaxBytes - 1, false}, {trustset.MaxBytes, false}, {trustset.MaxBytes + 1, true}} {
		in := keyringInput(t, "A", "B")
		cert := append(slices.Clone(a.PGP), bytes.Repeat([]byte{0}, tc.n-len(a.PGP))...)
		in.OpenPGPCertificates["A"] = cert
		d, err := trustset.NewDraft(in)
		if d != nil {
			t.Fatalf("%d bytes: a draft", tc.n)
		}
		wantOnly(t, err, trustset.ErrParams)
		if got := strings.Contains(err.Error(), "is longer than"); got != tc.mine {
			t.Errorf("%d bytes: %q (the builder's refusal is %v)", tc.n, err, tc.mine)
		}
	}
}

// The count: 26 roots with a certificate each are the most; 27 certificates are refused at the first
// check of the bounds, before anything else is read.
func TestKeyringTwentySixRoots(t *testing.T) {
	var labels []string
	for l := 'A'; l <= 'Z'; l++ {
		labels = append(labels, string(l))
	}
	in := keyringInput(t, labels...)
	d, err := trustset.NewDraft(in)
	if err != nil {
		t.Fatalf("26 roots: %v", err)
	}
	if got := readByGoCrypto(t, d.Keyring()); !slices.Equal(got, fingerprintsOf(t, labels...)) {
		t.Errorf("go-crypto reads %d primaries, or in another order", len(got))
	}
	if _, err := d.Sign(asSigners(signersFor(t, d, nil, nil)), nil); err != nil {
		t.Errorf("Sign: %v", err)
	}

	in.OpenPGPCertificates["AA"] = newRoot(t, "A", true).PGP
	in.Sequence = 0 // a fault that a later check would tell: the bounds are told first
	refusesCerts(t, in, "OpenPGP certificates are given for at most")
	short := keyringInput(t, "A", "B")
	for i := 0; i < 25; i++ {
		short.OpenPGPCertificates[string(rune('a'+i))+"x"] = newRoot(t, "A", true).PGP
	}
	short.Sequence = 0
	refusesCerts(t, short, "OpenPGP certificates are given for at most")
}

// The keyring file is made after the list and the CA bundle: a fault of the X.509 certificates is
// told before a fault of the OpenPGP certificates, and a fault of the sequence before both.
func TestKeyringIsCheckedAfterTheListAndTheBundle(t *testing.T) {
	in := keyringInput(t, "A", "B")
	delete(in.OpenPGPCertificates, "A")
	delete(in.Certificates, "B")
	refusesCerts(t, in, "there are 1 certificates for 2 roots")

	in = keyringInput(t, "A", "B")
	delete(in.OpenPGPCertificates, "A")
	in.Sequence = 0
	d, err := trustset.NewDraft(in)
	if d != nil {
		t.Fatal("a draft")
	}
	wantOnly(t, err, trustset.ErrParams)
	if strings.Contains(err.Error(), "OpenPGP") {
		t.Errorf("the sequence is not told first: %v", err)
	}
}

// A test primary and a real primary are never mixed in one file. The roots here are all test roots on
// the X.509 side; one primary has no mark. At the end, all primaries have no mark, which a file may
// hold, and which does not go with test roots.
func TestKeyringRefusesAMixOfTestAndRealPrimaries(t *testing.T) {
	for _, which := range []string{"A", "B"} {
		in := keyringInput(t, "A", "B")
		cert, print, _ := primaryOf(t, which, false)
		in.OpenPGPCertificates[which] = cert
		for i := range in.Roots {
			if in.Roots[i].Label == which {
				in.Roots[i].OpenPGPFingerprint = print
			}
		}
		refusesCerts(t, in, "mixes test and real primaries")
	}
	// All real primaries are a keyring file as well as all test ones, but they do not go with test
	// X.509 roots: the two families carry one mark (the list page: a list never mixes test roots and
	// real roots).
	in := keyringInput(t, "A", "B")
	for i, l := range []string{"A", "B"} {
		cert, print, _ := primaryOf(t, l, false)
		in.OpenPGPCertificates[l] = cert
		in.Roots[i].OpenPGPFingerprint = print
	}
	refusesCerts(t, in, "the X.509 roots are test roots and the OpenPGP primaries are not")
}

// The user ID of a certificate names the label of its entry. A primary whose user ID says another
// label is refused with the label named.
func TestKeyringRefusesAUserIDThatNamesAnotherLabel(t *testing.T) {
	in := keyringInput(t, "A", "B")
	cert, print, _ := primaryOf(t, "C", true) // a primary whose user ID says label C
	in.OpenPGPCertificates["B"] = cert
	in.Roots[1].OpenPGPFingerprint = print
	refusesCerts(t, in, "the user ID names the label C")
}

// A hostile user ID is refused and not shown: bytes that are not UTF-8, control characters, an escape
// sequence, a line break, a very long text. The error text is printable ASCII and holds none of them.
func TestKeyringHostileUserIDs(t *testing.T) {
	a := newRoot(t, "A", true)
	p := packetsOf(t, a.PGP)
	body := p[1][2:]
	for name, uid := range map[string][]byte{
		"not UTF-8":      bytes.Replace(body, []byte("root@"), []byte{0xff, 0xfe, 0xc0, 0x80, '@'}, 1),
		"an escape":      bytes.Replace(body, []byte("root@"), []byte("\x1b[31m@"), 1),
		"a line break":   bytes.Replace(body, []byte("root@"), []byte("a\nb@"), 1),
		"a zero byte":    bytes.Replace(body, []byte("root@"), []byte("a\x00b@"), 1),
		"right to left":  bytes.Replace(body, []byte("root@"), []byte("\u202eroot@"), 1),
		"no angle brace": bytes.ReplaceAll(body, []byte("<"), []byte("(")),
		"empty":          nil,
		"one byte":       []byte("A"),
		"very long":      bytes.Repeat([]byte("Example "), 400),
	} {
		t.Run(name, func(t *testing.T) {
			// The packet header is made again for the new length: one octet, two octets or five.
			hdr := []byte{0xC0 | 13}
			switch n := len(uid); {
			case n < 192:
				hdr = append(hdr, byte(n))
			case n < 8384:
				hdr = append(hdr, byte((n-192)>>8)+192, byte(n-192))
			}
			in := keyringInput(t, "A", "B")
			in.OpenPGPCertificates["A"] = slices.Concat(p[0], hdr, uid, p[2])
			d, err := trustset.NewDraft(in)
			if d != nil {
				t.Fatal("a draft")
			}
			wantOnly(t, err, trustset.ErrParams)
			for _, bad := range []string{"\x1b", "\u202e", "\xff"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("the error shows a byte of the user ID: %q", err)
				}
			}
		})
	}
}

// Every cut of a certificate, and every certificate with one byte changed, is either refused with
// ErrParams and no draft, or is a certificate that the reader accepts and the draft then holds as it
// is. Nothing panics. The text of each error is printable ASCII and short.
func TestKeyringEveryCutAndEveryChangedByte(t *testing.T) {
	a := newRoot(t, "A", true)
	accepted := 0
	check := func(label string, cert []byte) {
		in := keyringInput(t, "A", "B")
		in.OpenPGPCertificates["A"] = cert
		d, err := trustset.NewDraft(in)
		if err != nil {
			if d != nil {
				t.Fatalf("%s: a draft with the error", label)
			}
			wantOnly(t, err, trustset.ErrParams)
			return
		}
		accepted++
		if !bytes.Equal(d.Keyring(), slices.Concat(cert, newRoot(t, "B", true).PGP)) {
			t.Errorf("%s: the draft does not hold the certificate as it is", label)
		}
	}
	for n := 0; n <= len(a.PGP); n++ {
		check("cut", a.PGP[:n])
	}
	for i := range a.PGP {
		changed := slices.Clone(a.PGP)
		changed[i] ^= 0xff
		check("changed", changed)
		changed = slices.Clone(a.PGP)
		changed[i] ^= 0x01
		check("flipped", changed)
	}
	// The whole certificate and nothing else was accepted once: a change that the reader cannot see
	// would be accepted too, and the check above holds the bytes as they are.
	if accepted < 1 {
		t.Error("the whole certificate was not accepted")
	}
	t.Logf("%d of %d variants were accepted", accepted, len(a.PGP)*3+1)
}

// Bytes that are not certificates at all: random-looking data, a long run of one byte, headers that
// promise more than there is.
func TestKeyringHostileBytes(t *testing.T) {
	for name, junk := range map[string][]byte{
		"zeros":              make([]byte, 4096),
		"ones":               bytes.Repeat([]byte{0xff}, 4096),
		"key tags":           bytes.Repeat([]byte{0xC6, 0x00}, 2000),
		"a long promise":     {0xC6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3},
		"a partial length":   {0xC6, 0xE0, 1, 2, 3},
		"an indeterminate":   {0x84, 1, 2, 3},
		"the old format key": {0x99, 0x00, 0x03, 4, 5, 6},
		"a text of a page":   []byte(strings.Repeat("the keyring file of a trust set\n", 100)),
		"a json document":    []byte(`{"roots":[{"label":"A"}]}`),
		"a pem block":        []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			in := keyringInput(t, "A", "B")
			in.OpenPGPCertificates["A"] = junk
			refusesCerts(t, in)
		})
	}
}
