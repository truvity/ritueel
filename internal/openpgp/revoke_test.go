package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"testing"
	"time"

	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

var reasons = []struct {
	name string
	r    openpgp.Reason
	code byte
	text string
}{
	{"compromised", openpgp.Compromised, 2, "compromised"},
	{"superseded", openpgp.Superseded, 1, "superseded"},
	{"retired", openpgp.Retired, 3, "retired"},
	{"no reason", openpgp.NoReason, 0, "no-reason"},
}

// The table of docs/reference/revocation-material.md: the code and the word of each reason.
func TestTheFourReasonsHaveTheCodesAndTheWordsOfThePage(t *testing.T) {
	for _, c := range reasons {
		if c.r.Code != c.code || c.r.Text != c.text {
			t.Errorf("%s is {%d, %q}, the page says {%d, %q}", c.name, c.r.Code, c.r.Text, c.code, c.text)
		}
	}
}

func revoke(t testing.TB, s *privateSigner, r openpgp.Reason) []byte {
	t.Helper()
	sig, err := openpgp.RevocationSignature(rand.Reader, s.params(), r)
	if err != nil {
		t.Fatalf("RevocationSignature: %v", err)
	}
	return sig
}

func TestARevocationSignatureHasTheSubpacketsOfThePageForEachReason(t *testing.T) {
	for _, c := range reasons {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			ps := splitPackets(t, revoke(t, s, c.r))
			if len(ps) != 1 || ps[0].Tag != tagSignature {
				t.Fatalf("packet tags % d, want one signature", tags(ps))
			}
			sig := parseSig(t, ps[0].Body)
			if sig.Version != 4 || sig.Type != 0x20 || sig.Algo != 19 || sig.Hash != 9 {
				t.Errorf("version %d type %#x algorithm %d hash %d, want 4, 0x20, 19, 9", sig.Version, sig.Type, sig.Algo, sig.Hash)
			}
			if got := types(sig.Hashed); !bytes.Equal(got, []byte{2, 29, 33}) {
				t.Errorf("hashed types % d, want 2 29 33", got)
			}
			if got := types(sig.Unhashed); !bytes.Equal(got, []byte{16}) {
				t.Errorf("unhashed types % d, want 16", got)
			}
			if got := critical(sig.Hashed); len(got) != 0 {
				t.Errorf("critical hashed subpackets % d, want none", got)
			}
			fp := fingerprint(&s.key.PublicKey, created)
			if got := find(t, sig.Hashed, 2).Data; !bytes.Equal(got, u32(uint32(ceremony.Unix()))) {
				t.Errorf("creation time % x, want the ceremony time", got)
			}
			if got, want := find(t, sig.Hashed, 29).Data, append([]byte{c.code}, c.text...); !bytes.Equal(got, want) {
				t.Errorf("reason % x, want % x (the code and the word)", got, want)
			}
			if got := find(t, sig.Hashed, 33).Data; !bytes.Equal(got, append([]byte{4}, fp...)) {
				t.Errorf("issuer fingerprint % x", got)
			}
			if got := find(t, sig.Unhashed, 16).Data; !bytes.Equal(got, fp[12:]) {
				t.Errorf("issuer key ID % x", got)
			}
		})
	}
}

// The signature covers the primary's public key packet alone: not the user ID, not a subkey.
func TestARevocationSignatureCoversThePrimaryKeyPacketAlone(t *testing.T) {
	s := newSigner(t)
	ps := splitPackets(t, revoke(t, s, openpgp.Compromised))
	body := ps[0].Body
	if !verifySig(t, &s.key.PublicKey, body, hashPrefix(&s.key.PublicKey, created)) {
		t.Error("the signature does not verify over the key packet alone")
	}
	if verifySig(t, &s.key.PublicKey, body, append(hashPrefix(&s.key.PublicKey, created), 0xB4, 0, 0, 0, 1, 'x')) {
		t.Error("the signature verifies over the key and a user ID")
	}
	if verifySig(t, &genKey(t).PublicKey, body, hashPrefix(&s.key.PublicKey, created)) {
		t.Error("the signature verifies with another key")
	}
}

// A second reader takes it as a key revocation of the primary, with the reason.
func TestAnotherReaderTakesItAsAKeyRevocationWithTheReason(t *testing.T) {
	for _, c := range reasons {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			_, _, cert, _ := certOf(t, s)
			sigPkt := revoke(t, s, c.r)
			pub := readPublicKey(t, cert)
			rd := gopacket.NewReader(bytes.NewReader(sigPkt))
			p, err := rd.Next()
			if err != nil {
				t.Fatal(err)
			}
			sig, ok := p.(*gopacket.Signature)
			if !ok {
				t.Fatalf("read back as %T", p)
			}
			if err := pub.VerifyRevocationSignature(sig); err != nil {
				t.Errorf("the revocation does not verify as a key revocation: %v", err)
			}
			if sig.RevocationReason == nil || byte(*sig.RevocationReason) != c.code || sig.RevocationReasonText != c.text {
				t.Errorf("reason %v %q, want %d %q", sig.RevocationReason, sig.RevocationReasonText, c.code, c.text)
			}
		})
	}
}

func TestADifferentReasonGivesDifferentHashedData(t *testing.T) {
	s := newSigner(t)
	seen := map[string]string{}
	for _, c := range reasons {
		fields := string(parseSig(t, splitPackets(t, revoke(t, s, c.r))[0].Body).Fields)
		if other, dup := seen[fields]; dup {
			t.Errorf("%s and %s give the same hashed data", c.name, other)
		}
		seen[fields] = c.name
	}
}

// Only the four reasons of the table are made: the code and the word go together.
func TestAReasonThatIsNotOneOfTheFourIsRefused(t *testing.T) {
	cases := []struct {
		name string
		r    openpgp.Reason
	}{
		{"the zero value", openpgp.Reason{}},
		{"the code of one and the word of another", openpgp.Reason{Code: 2, Text: "superseded"}},
		{"a code that is not in the table", openpgp.Reason{Code: 32, Text: "compromised"}},
		{"a word that is not in the table", openpgp.Reason{Code: 1, Text: "lost"}},
		{"a word in capitals", openpgp.Reason{Code: 2, Text: "Compromised"}},
		{"a word with a space after it", openpgp.Reason{Code: 0, Text: "no-reason "}},
		{"the word without a hyphen", openpgp.Reason{Code: 0, Text: "no reason"}},
		{"a very long text", openpgp.Reason{Code: 1, Text: string(bytes.Repeat([]byte("a"), 300))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			assertRefused(t, "RevocationSignature", func() ([]byte, error) { return openpgp.RevocationSignature(nil, s.params(), c.r) }, openpgp.ErrParams)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

// The revocation is over the key alone, so the user ID and the expiry of the parameters play no part
// in it: the same hashed data comes with any of them.
func TestARevocationDoesNotDependOnTheUserIDOrTheExpiry(t *testing.T) {
	s := newSigner(t)
	p := s.params()
	a, err := openpgp.RevocationSignature(nil, p, openpgp.Compromised)
	if err != nil {
		t.Fatal(err)
	}
	p.UserID = ""
	p.ExpiresAt = time.Time{}
	b, err := openpgp.RevocationSignature(nil, p, openpgp.Compromised)
	if err != nil {
		t.Fatalf("a revocation with no user ID and no expiry: %v", err)
	}
	if !bytes.Equal(parseSig(t, splitPackets(t, a)[0].Body).Fields, parseSig(t, splitPackets(t, b)[0].Body).Fields) {
		t.Error("the hashed data depends on the user ID or the expiry")
	}
}

func TestARevocationOfAKeyOrTimeThatIsRefusedGivesNoBytes(t *testing.T) {
	cases := map[string]func(p *openpgp.PrimaryParams){
		"a ceremony before the key was created":         func(p *openpgp.PrimaryParams) { p.CeremonyTime = created.Add(-time.Second) },
		"a ceremony with a fraction of a second":        func(p *openpgp.PrimaryParams) { p.CeremonyTime = ceremony.Add(time.Millisecond) },
		"a creation time with a fraction of a second":   func(p *openpgp.PrimaryParams) { p.CreationTime = created.Add(time.Millisecond) },
		"a ceremony after the year 2106":                func(p *openpgp.PrimaryParams) { p.CeremonyTime = time.Unix(1<<32, 0) },
		"no key":                                        func(p *openpgp.PrimaryParams) { p.Key = nil },
		"a signer whose public key is not an ECDSA key": func(p *openpgp.PrimaryParams) { p.Key = fixedPublic{struct{}{}} },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			p := newSigner(t).params()
			mod(&p)
			assertRefused(t, "RevocationSignature", func() ([]byte, error) { return openpgp.RevocationSignature(nil, p, openpgp.Compromised) }, openpgp.ErrParams)
		})
	}
}

func TestTheRevocationSignerIsGivenTheSHA384DigestOfTheKeyPacketAndTheFields(t *testing.T) {
	s := newSigner(t)
	ps := splitPackets(t, revoke(t, s, openpgp.Superseded))
	sig := parseSig(t, ps[0].Body)
	if s.calls != 1 || s.hashes[0].HashFunc() != crypto.SHA384 {
		t.Fatalf("calls %d, hash %v", s.calls, s.hashes)
	}
	h := sha512.New384()
	h.Write(hashPrefix(&s.key.PublicKey, created))
	h.Write(sig.Fields)
	h.Write(append([]byte{4, 0xFF}, u32(uint32(len(sig.Fields)))...))
	if !bytes.Equal(s.digests[0], h.Sum(nil)) {
		t.Error("the digest the signer was given is not the SHA-384 of the key packet, the fields and the trailer")
	}
}

// ecdsaKey is the key of a signer as a plain ECDSA key.
func ecdsaKey(s *privateSigner) *ecdsa.PublicKey { return &s.key.PublicKey }

// certOf builds a certificate for s with the usual parameters.
func certOf(t testing.TB, s *privateSigner) (openpgp.PrimaryParams, *ecdsa.PublicKey, []byte, []packet) {
	t.Helper()
	p := s.params()
	cert, err := openpgp.NewPrimary(rand.Reader, p)
	if err != nil {
		t.Fatal(err)
	}
	return p, ecdsaKey(s), cert, splitPackets(t, cert)
}

// readPublicKey reads the first packet of a certificate with the other reader.
func readPublicKey(t testing.TB, cert []byte) *gopacket.PublicKey {
	t.Helper()
	p, err := gopacket.NewReader(bytes.NewReader(cert)).Next()
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := p.(*gopacket.PublicKey)
	if !ok {
		t.Fatalf("the first packet is a %T", p)
	}
	return pk
}
