package handoff_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/handoff"
)

// These tests are of the checks 2 to 9 of a request of type openpgp-subkey (docs/reference/hand-off-contract.md,
// "OpenPGP subkey"). Each expectation is what the page says. The requests are made in memory by the writer of
// pgpbuild_test.go, which shares no code with package openpgp, or are the files of the vector set.

// firstPacketOf reads the first packet of a subkey file with go-crypto, the reader of the tests.
func firstPacketOf(t testing.TB, file []byte) *gopacket.PublicKey {
	t.Helper()
	p, err := gopacket.Read(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("go-crypto cannot read the first packet: %v", err)
	}
	pk, ok := p.(*gopacket.PublicKey)
	if !ok {
		t.Fatalf("the first packet is %T", p)
	}
	return pk
}

func TestARequestForOneTwoAndTheMostPrimariesIsAcceptedAndTheVerdictHoldsTheSubkey(t *testing.T) {
	for _, n := range []int{1, 2, handoff.MaxPrimaries} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := newPGPFixture(t, n, handoff.StoreSoftware)
			v, err := f.checker(nil).Check(t.Context(), f.request())
			wantAccepted(t, v, err)
			if !v.Complete() || v.Refused() || v.Code != "" || v.Detail != "" {
				t.Errorf("complete %v, refused %v, code %q, detail %q", v.Complete(), v.Refused(), v.Code, v.Detail)
			}
			if v.Subkey == nil {
				t.Fatal("an accepted verdict of an openpgp-subkey request holds no subkey")
			}
			// The fingerprint is the one the standard gives (the test's own writer computes it), the creation
			// time is the one in the packet, and the capability is the one the proof and the delegation agree on.
			pk := firstPacketOf(t, f.fileBytes())
			if got := fmt.Sprintf("%x", pk.Fingerprint); v.Subkey.Fingerprint != got || v.Subkey.Fingerprint != f.sub.fingerprint() {
				t.Errorf("fingerprint %s, go-crypto %s, writer %s", v.Subkey.Fingerprint, got, f.sub.fingerprint())
			}
			if !v.Subkey.Created.Equal(pgpSubCreated) || !v.Subkey.Created.Equal(pk.CreationTime) || v.Subkey.Created.Location() != time.UTC {
				t.Errorf("created %v, want %v in UTC", v.Subkey.Created, pgpSubCreated)
			}
			if v.Subkey.Capability != "sign" {
				t.Errorf("capability %q", v.Subkey.Capability)
			}
			// The key of the verdict is the subkey's point, and a software key says it is unprotected.
			if !v.Key.Equal(f.sub.pub()) {
				t.Error("the key of the verdict is not the subkey's")
			}
			if v.Evidence == nil || !v.Evidence.Unprotected || v.Evidence.Key != nil {
				t.Errorf("evidence %+v", v.Evidence)
			}
			// The key is a copy: changing it does not change what the next call says.
			//nolint:staticcheck // the coordinates are the only way to change a key that the verdict gives
			v.Key.X.SetInt64(1)
			again, err := f.checker(nil).Check(t.Context(), f.request())
			wantAccepted(t, again, err)
		})
	}
}

func TestAnX509RequestAcceptedHoldsNoSubkey(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if v.Subkey != nil {
		t.Errorf("an X.509 verdict holds the subkey %+v", v.Subkey)
	}
}

func TestAnAuthenticateRequestIsAcceptedWithTheCapabilityOfTheDelegation(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware).edit(func(m map[string]any) { m["capabilities"] = []string{"authenticate"} })
	chk := f.checker(func(c *handoff.Config) { c.Delegation.Capability = "authenticate" })
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if v.Subkey.Capability != "authenticate" {
		t.Errorf("capability %q", v.Subkey.Capability)
	}
}

func TestAnOldFormatHeaderOnEveryPacketGivesTheSameAcceptance(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	plain := f.mustAccept(f.checker(nil))
	f.subPacket = pgpOldPacket(pgpTagSubkey, f.sub.body())
	f.sigs = nil
	for _, p := range f.primaries {
		f.sigs = append(f.sigs, f.backSig(p, func(s *sigSpec) { s.headerOld = true }))
	}
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if v.Subkey.Fingerprint != plain.Subkey.Fingerprint {
		t.Errorf("the fingerprint depends on the header: %s and %s", v.Subkey.Fingerprint, plain.Subkey.Fingerprint)
	}
}

// Check 2: a subkey file that is not whole packets of the profile is malformed, the digest and the primaries
// are not looked at, and the statuses say that check 2 failed.

func TestAFileThatIsNotWholePacketsOfTheProfileIsMalformedAtCheckTwoWhateverTheDigest(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	good := f.fileBytes()
	sigOf := func(i int) []byte { return f.sigs[i] }
	repeat := func(n int) []byte {
		out := slices.Clone(f.subPacket)
		for range n {
			out = append(out, sigOf(0)...)
		}
		return out
	}
	zeroTime := newPGPKey(t, time.Unix(0, 0))
	offCurve := func() []byte {
		b := f.sub.body()
		b[len(b)-1] ^= 1 // the last byte of the ordinate
		return pgpPacket(pgpTagSubkey, b)
	}()
	badMPI := func() []byte {
		b := f.sub.body()
		b[12], b[13] = 0x03, 0x04 // a bit count that the point does not have
		return pgpPacket(pgpTagSubkey, b)
	}()
	cases := map[string][]byte{
		"an empty file":                 {},
		"one byte":                      {0xCE},
		"the certificate of a primary":  append(pgpPacket(pgpTagPrimary, f.primaries[0].body()), good[len(f.subPacket):]...),
		"a user id first":               append(pgpPacket(pgpTagUserID, []byte("Example Person")), good...),
		"a signature first":             append(slices.Clone(sigOf(0)), f.subPacket...),
		"27 packets after the subkey":   repeat(27),
		"28 packets after the subkey":   repeat(28),
		"a cut subkey packet":           good[:len(f.subPacket)-3],
		"the subkey alone cut":          f.subPacket[:len(f.subPacket)-1],
		"a cut last signature":          good[:len(good)-1],
		"a stray zero byte at the end":  append(slices.Clone(good), 0),
		"a stray byte that looks right": append(slices.Clone(good), 0xC2),
		"a point not on the curve":      append(offCurve, good[len(f.subPacket):]...),
		"a bit count that is not true":  append(badMPI, good[len(f.subPacket):]...),
		"a creation time of zero":       zeroTime.subkeyPacket(),
		"a partial length":              append([]byte{0xC0 | pgpTagSubkey, 0xE0}, f.sub.body()...),
		"an indeterminate length":       append([]byte{0x80 | pgpTagSubkey<<2 | 3}, f.sub.body()...),
		"a length beyond the file":      append([]byte{0xC0 | pgpTagSubkey, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, f.sub.body()...),
		"a length of four gibibytes":    {0xC0 | pgpTagSubkey, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3},
	}
	for name, file := range cases {
		for _, digest := range []string{"", digestHex([]byte("not this file"))} {
			t.Run(name, func(t *testing.T) {
				g := newPGPFixture(t, 2, handoff.StoreSoftware)
				g.primaries, g.sub, g.subPacket, g.sigs = f.primaries, f.sub, f.subPacket, f.sigs
				g.file, g.digest = file, digest
				v, err := g.checker(nil).Check(t.Context(), g.request())
				wantRefusal(t, v, err, handoff.CodeMalformed, 2)
				if got := statuses(v); got != "pfnnnnnnn" {
					t.Errorf("statuses %s, want pfnnnnnnn", got)
				}
				if v.Detail == "" || !plain(v.Detail) {
					t.Errorf("detail %q", v.Detail)
				}
			})
		}
	}
	// The control: the whole file is accepted, and so is one with a packet other than a signature after the
	// subkey only where check 5 and not check 2 refuses it.
	f.mustAccept(f.checker(nil))
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	g.primaries, g.sub, g.subPacket = f.primaries, f.sub, f.subPacket
	g.sigs = [][]byte{pgpPacket(pgpTagUserID, []byte("Example Person")), pgpPacket(pgpTagUserID, []byte("x"))}
	v, err := g.checker(nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}

func TestAFileWithTheMostPacketsAfterTheSubkeyIsReadAndOneMoreIsNot(t *testing.T) {
	f := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	f.mustAccept(f.checker(nil))
	// One signature more than primaries: the file is whole, so check 2 passes, and check 5 refuses the count.
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	g.sigs = append(g.sigs, g.sigs[0])
	v, err := g.checker(nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if !strings.Contains(v.Detail, "3") || !strings.Contains(v.Detail, "2") {
		t.Errorf("the detail names neither count: %q", v.Detail)
	}
	h := newPGPFixture(t, handoff.MaxPrimaries, handoff.StoreSoftware)
	h.sigs = append(h.sigs, h.sigs[0])
	v, err = h.checker(nil).Check(t.Context(), h.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

func TestTheSubkeyFileIsOnlyReadAfterTheProofFileIsOfTheFormOfThePage(t *testing.T) {
	// A proof that is malformed gives malformed at check 2, and so does a subkey file that is not a file of
	// packets: both at the same check, and the proof's own fault is told first.
	f := newPGPFixture(t, 2, handoff.StoreSoftware).edit(func(m map[string]any) { m["capabilities"] = []string{"encrypt"} })
	f.file = []byte{}
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	if !strings.Contains(v.Detail, "capabilit") {
		t.Errorf("the fault of the proof file is not the one told: %q", v.Detail)
	}
}

// A checker that holds no primaries cannot judge a request of this type.

func TestAnOpenPGPRequestOnACheckerThatHoldsNoPrimariesIsNeitherAcceptedNorRefused(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, change := range map[string]func(c *handoff.Config){
		"an X.509 delegation": func(c *handoff.Config) { c.Delegation = defaultDelegation(); c.Primaries = nil },
		"an SSH delegation": func(c *handoff.Config) {
			c.Delegation = &handoff.Delegation{Name: "n", Type: handoff.TypeSSH, Root: "r"}
			c.Primaries = nil
		},
		"no delegation": func(c *handoff.Config) { c.Delegation = nil; c.Primaries = nil },
	} {
		t.Run(name, func(t *testing.T) {
			v, err := f.checker(change).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrConfig, "ppnnnnnnn")
			if err != nil && !plain(err.Error()) {
				t.Errorf("error %q", err)
			}
		})
	}
	// A request that is malformed is still refused: check 2 does not need the primaries.
	g := newPGPFixture(t, 2, handoff.StoreSoftware).edit(func(m map[string]any) { delete(m, "primaries") })
	v, err := g.checker(func(c *handoff.Config) { c.Delegation = nil; c.Primaries = nil }).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	// And a request whose subkey file is not packets.
	h := newPGPFixture(t, 2, handoff.StoreSoftware)
	h.file = []byte{1, 2, 3}
	v, err = h.checker(func(c *handoff.Config) { c.Delegation = nil; c.Primaries = nil }).Check(t.Context(), h.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

// Check 4: the key is ECDSA P-384, whatever follows the algorithm; the signatures after it are never read.

// oddSubkey is a Public-Subkey packet of a key that is not a version 4 ECDSA key on P-384.
func oddSubkey(created time.Time, body ...[]byte) []byte {
	out := []byte{4}
	out = append(out, byte(created.Unix()>>24), byte(created.Unix()>>16), byte(created.Unix()>>8), byte(created.Unix()))
	for _, b := range body {
		out = append(out, b...)
	}
	return pgpPacket(pgpTagSubkey, out)
}

// mpiOf writes an integer of the given number of bits whose bytes are random, with the top bit set.
func mpiOf(t testing.TB, bits int) []byte {
	t.Helper()
	b := make([]byte, (bits+7)/8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[0] = b[0]&(0xFF>>(8*len(b)-bits)) | 1<<((bits-1)%8)
	return append([]byte{byte(bits >> 8), byte(bits)}, b...)
}

func TestAKeyThatIsNotAVersionFourEcdsaKeyOnP384IsAlgorithmUnsupportedWhateverFollows(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	at := pgpSubCreated
	garbage := bytes.Repeat([]byte{0xA5}, 40)
	oidP256 := []byte{8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	oidP521 := []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x23}
	oidBrainpool384 := []byte{9, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}
	oidEd25519 := []byte{9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
	cases := map[string][]byte{
		"RSA":                         oddSubkey(at, []byte{1}, mpiOf(t, 2048), mpiOf(t, 17)),
		"DSA":                         oddSubkey(at, []byte{17}, mpiOf(t, 1024)),
		"ECDH on P-384":               oddSubkey(at, []byte{18, 5, 0x2B, 0x81, 0x04, 0x00, 0x22}, mpiOf(t, 771), []byte{3, 1, 9, 9}),
		"EdDSA":                       oddSubkey(at, []byte{22}, oidEd25519, mpiOf(t, 263)),
		"ECDSA on P-256":              oddSubkey(at, []byte{19}, oidP256, mpiOf(t, 515)),
		"ECDSA on P-521":              oddSubkey(at, []byte{19}, oidP521, mpiOf(t, 1059)),
		"ECDSA on brainpoolP384r1":    oddSubkey(at, []byte{19}, oidBrainpool384, mpiOf(t, 771)),
		"an algorithm that is none":   oddSubkey(at, []byte{99}, garbage),
		"ECDSA with a curve of no id": oddSubkey(at, []byte{19, 3, 1, 2, 3}, garbage),
		"a version 6 key":             pgpPacket(pgpTagSubkey, append([]byte{6, 0, 0, 0, 1, 19}, garbage...)),
		"a version 5 key":             pgpPacket(pgpTagSubkey, append([]byte{5, 0, 0, 0, 1, 19}, garbage...)),
		"a version 3 key":             pgpPacket(pgpTagSubkey, append([]byte{3, 0, 0, 0, 1, 0, 0, 19}, garbage...)),
		"a version 2 key":             pgpPacket(pgpTagSubkey, append([]byte{2, 0, 0, 0, 1, 0, 0, 19}, garbage...)),
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			// The signatures after it are wrong (they cover another subkey): they are never read.
			g := newPGPFixture(t, 2, handoff.StoreSoftware)
			g.primaries = f.primaries
			g.subPacket = packet
			var reads int
			chk := g.checker(func(c *handoff.Config) { c.Now = func() time.Time { reads++; return testNow } })
			reads = 0 // the one read of New is not a read of a call
			v, err := chk.Check(t.Context(), g.request())
			wantRefusal(t, v, err, handoff.CodeAlgorithmUnsupported, 4)
			if got := statuses(v); got != "pppfnnnnn" {
				t.Errorf("statuses %s, want pppfnnnnn", got)
			}
			if reads != 0 {
				t.Errorf("the clock was read %d times for a refusal at check 4", reads)
			}
		})
	}
	// The same file with the P-384 key is the control.
	f.mustAccept(f.checker(nil))
}

func TestACheckFourRefusalComesAfterTheDigestAndThePrimaries(t *testing.T) {
	odd := oddSubkey(pgpSubCreated, []byte{22}, bytes.Repeat([]byte{1}, 20))
	for name, tc := range map[string]struct {
		change func(f *pgpFixture)
		code   handoff.Code
		check  int
	}{
		"a wrong digest":    {func(f *pgpFixture) { f.digest = digestHex([]byte("x")) }, handoff.CodeRequestMismatch, 3},
		"a wrong primaries": {func(f *pgpFixture) { f.listed = fingerprints(2) }, handoff.CodeUnknownPrimary, 3},
		"nothing wrong":     {func(f *pgpFixture) {}, handoff.CodeAlgorithmUnsupported, 4},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			f.subPacket = odd
			tc.change(f)
			v, err := f.checker(nil).Check(t.Context(), f.request())
			wantRefusal(t, v, err, tc.code, tc.check)
		})
	}
}

// The verdict of a request that is not accepted holds no subkey.

func TestOnlyAnAcceptedVerdictHoldsTheSubkey(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StorePIV)
	good := f.goodEvidence(handoff.StorePIV)
	run := map[string]func() (handoff.Verdict, error){
		"no verifier": func() (handoff.Verdict, error) { return f.checker(nil).Check(t.Context(), f.request()) },
		"a verifier that could not decide": func() (handoff.Verdict, error) {
			return f.checker(withVerifier(handoff.StorePIV, failing(errCannotDecide))).Check(t.Context(), f.request())
		},
		"a verifier that refuses": func() (handoff.Verdict, error) {
			return f.checker(withVerifier(handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "no"}))).Check(t.Context(), f.request())
		},
		"a key that does not match": func() (handoff.Verdict, error) {
			other := *good
			other.Key = &newP384(t).PublicKey
			return f.checker(withVerifier(handoff.StorePIV, returning(&other))).Check(t.Context(), f.request())
		},
		"an old firmware": func() (handoff.Verdict, error) {
			old := *good
			old.Firmware = "5.6.9"
			return f.checker(withVerifier(handoff.StorePIV, returning(&old))).Check(t.Context(), f.request())
		},
		"a store that is not allowed": func() (handoff.Verdict, error) {
			return f.checker(func(c *handoff.Config) { c.Policy.Stores = []handoff.Store{handoff.StoreSoftware} }).Check(t.Context(), f.request())
		},
	}
	for name, fn := range run {
		t.Run(name, func(t *testing.T) {
			v, err := fn()
			if v.Subkey != nil || v.Key != nil || v.Evidence != nil || v.Accepted() {
				t.Errorf("subkey %+v, key %v, evidence %v, accepted %v, error %v", v.Subkey, v.Key, v.Evidence, v.Accepted(), err)
			}
		})
	}
	v, err := f.checker(withVerifier(handoff.StorePIV, returning(good))).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if v.Subkey == nil || v.Evidence.Firmware != "5.8.0" {
		t.Errorf("accepted verdict: subkey %+v, evidence %+v", v.Subkey, v.Evidence)
	}
}
