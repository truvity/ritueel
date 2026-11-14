package rootlist_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

// The two targets of this file build their input in the process from numbers and a few selectors,
// with the process's own keys, so that every input reaches the rule it is about whatever worker runs
// it, and each has an oracle that is a model of the rules of the page: the dates and the lowest sequence of
// the list, and the certificates of a CA bundle.

func fixedTime(unix int64) time.Time {
	// Between 1971 and 2199, to whole seconds, in UTC.
	const span = 228 * 365 * 24 * 3600
	u := unix % span
	if u < 0 {
		u = -u
	}
	return time.Unix(u+365*24*3600, 0).UTC()
}

// FuzzTheDatesAndTheSequenceOfAList signs a list with the one key that the host trusts, whose
// signing time, expiry and sequence come from the numbers, and gives the host a clock and a
// lowest sequence. The verdict must be the one that the order of the checks and the rules give:
// the dates are checked in check 5 (malformed), the lowest sequence in check 6 (rollback), the
// expiry in check 11 (expired).
func FuzzTheDatesAndTheSequenceOfAList(f *testing.F) {
	f.Add(int64(1_700_000_000), uint8(0), int32(0), int32(0), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(1), int32(1), int32(0), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(1), int32(-1), int32(0), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(2), int32(-1), int32(0), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(2), int32(1), int32(0), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(0), int32(0), int32(-1), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(0), int32(0), int32(1), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(0), int32(0), int32(40_000_000), uint32(7), uint8(0))
	f.Add(int64(1_700_000_000), uint8(0), int32(0), int32(0), uint32(6), uint8(1))
	f.Add(int64(951_782_400), uint8(0), int32(0), int32(5), uint32(1), uint8(2)) // 2000-02-29
	f.Fuzz(func(t *testing.T, signedUnix int64, expiryKind uint8, expiryDelta, clockOffset int32, seq uint32, minKind uint8) {
		k := forger(t)
		signedAt := fixedTime(signedUnix)
		right := plusMonths(signedAt, 13)
		expires := right
		switch expiryKind % 3 {
		case 1: // seconds off
			expires = right.Add(time.Duration(expiryDelta) * time.Second)
		case 2: // months off
			expires = plusMonths(signedAt, 13+int(expiryDelta%24))
		}
		clock := signedAt.Add(time.Duration(clockOffset) * time.Second)
		sequence := int64(seq%1000) + 1
		min := []int64{0, 1, 2, 7, 500, 1000}[minKind%6]
		s := listOf(int(sequence), k)
		s.signedAt = `"` + signedAt.Format(rootlist.TimeLayout) + `"`
		s.expiresAt = `"` + expires.Format(rootlist.TimeLayout) + `"`
		trust := pinsOf(t, k.pin)
		if min > 0 {
			var err error
			if trust, err = trust.WithMinSequence(min); err != nil {
				t.Fatal(err)
			}
		}
		got := rootlist.Verify(signed(t, s, k), trust, clock)
		// The model.
		var wantReason rootlist.Reason
		var wantCheck int
		switch {
		case !expires.Equal(right), signedAt.After(clock):
			wantReason, wantCheck = rootlist.Malformed, 5
		case sequence < min:
			wantReason, wantCheck = rootlist.Rollback, 6
		case !clock.Before(expires):
			wantReason, wantCheck = rootlist.Expired, 11
		}
		if wantReason == "" {
			if !got.Accepted || got.Again {
				t.Fatalf("a list of the right shape is refused: signed %s expires %s clock %s seq %d min %d: %+v", signedAt, expires, clock, sequence, min, got)
			}
			return
		}
		if got.Accepted || got.Reason != wantReason || got.Check != wantCheck {
			t.Fatalf("signed %s expires %s clock %s seq %d min %d: got %+v, want %s at check %d", signedAt, expires, clock, sequence, min, got, wantReason, wantCheck)
		}
	})
}

// FuzzTheCertificatesOfACABundle builds a bundle of three root keys in the process, makes one block
// in the way the selector says, and compares the verdict with the model of the page: the block must be
// a CA certificate that verifies with its own key and has the key of its root; the names, the dates
// and the other extensions are not judged. A byte of its DER may also be changed.
func FuzzTheCertificatesOfACABundle(f *testing.F) {
	for kind := range uint8(9) {
		f.Add(kind, uint8(kind%3), uint16(0))
	}
	f.Add(uint8(7), uint8(0), uint16(40))
	f.Add(uint8(8), uint8(1), uint16(0))
	f.Add(uint8(7), uint8(1), uint16(400))
	f.Fuzz(func(t *testing.T, kind, pos uint8, at uint16) {
		w := newWorld(t)
		keys := []*key{w.a, w.b, w.c}
		l := listFor(t, 5, keys...)
		i := int(pos) % len(keys)
		tmpl := caTemplate()
		var der []byte
		wantAccept := true
		switch kind % 9 {
		case 0: // the witness
			der, _ = certOf(t, keys[i], tmpl, nil)
		case 1: // another key signed it
			der, _ = certOf(t, keys[i], tmpl, w.z)
			wantAccept = false
		case 2: // no CA flag
			tmpl.IsCA = false
			der, _ = certOf(t, keys[i], tmpl, nil)
			wantAccept = false
		case 3: // no basic constraints
			tmpl.BasicConstraintsValid, tmpl.IsCA = false, false
			der, _ = certOf(t, keys[i], tmpl, nil)
			wantAccept = false
		case 4: // another name, other dates, other extensions
			tmpl.Subject.CommonName = "Other " + strings.Repeat("x", int(at%50))
			tmpl.NotBefore, tmpl.NotAfter = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1991, 1, 1, 0, 0, 0, 0, time.UTC)
			tmpl.PermittedDNSDomains = []string{"example.org"}
			der, _ = certOf(t, keys[i], tmpl, nil)
		case 5: // signed by another root key of the list
			der, _ = certOf(t, keys[i], tmpl, keys[(i+1)%len(keys)])
			wantAccept = false
		case 6: // the signature changed
			der, _ = certOf(t, keys[i], tmpl, nil)
			der[len(der)-1-int(at)%60] ^= 0x01
			wantAccept = false
		case 8: // self-signed with another issuer name than its subject
			parent := *tmpl
			parent.Subject.CommonName = "Another issuer " + strings.Repeat("x", int(at%50))
			var err error
			der, err = x509.CreateCertificate(rand.Reader, tmpl, &parent, &keys[i].priv.PublicKey, keys[i].priv)
			if err != nil {
				t.Fatal(err)
			}
			wantAccept = false
		case 7: // any byte of the certificate changed
			der, _ = certOf(t, keys[i], tmpl, nil)
			der[int(at)%len(der)] ^= 0x01
			cert, err := x509.ParseCertificate(der)
			wantAccept = err == nil && jwsPinOf(cert) == keys[i].pin && cert.BasicConstraintsValid && cert.IsCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
				cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
		}
		var b bytes.Buffer
		b.WriteString("# trust-sequence: 5\n")
		for j, k := range keys {
			if j == i {
				b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			} else {
				b.WriteString(k.certPEM())
			}
		}
		got := rootlist.VerifyCABundle(b.Bytes(), l)
		if got.Accepted != wantAccept {
			t.Fatalf("kind %d at block %d: accepted = %v, want %v (%s)", kind%9, i+1, got.Accepted, wantAccept, got.Detail)
		}
	})
}
