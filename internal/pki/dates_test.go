package pki_test

import (
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The date with the special meaning: RFC 5280, 4.1.2.5, "To indicate that a certificate has no well-defined expiration date,
// the notAfter SHOULD be assigned the GeneralizedTime value of 99991231235959Z." A certificate that really ends then would be
// read as one that never ends, so no builder gives that end, and no body that has it is assembled.
func TestTheEndOfTimeIsNotAnEnd(t *testing.T) {
	endOfTime := utc(9999, 12, 31, 23, 59, 59)
	key := newKey(t)
	t.Run("a root that would end at the end of time is refused, and one second less is issued", func(t *testing.T) {
		p := rootParams(&key.PublicKey)
		p.CeremonyTime = utc(9996, 12, 31, 23, 59, 59)
		tbs, err := pki.RootTBS(p)
		refusedSaying(t, err, pki.ErrParams, "no well-defined expiry")
		if tbs != nil {
			t.Error("a body came with the error")
		}
		for _, d := range []time.Duration{time.Second, 2 * time.Second, time.Hour, 24 * time.Hour * 400} {
			p.CeremonyTime = utc(9996, 12, 31, 23, 59, 59).Add(-d)
			if _, err := pki.RootTBS(p); err != nil {
				t.Errorf("a start %v earlier is refused: %v", d, err)
			}
		}
		// The same instant given in another zone.
		p.CeremonyTime = time.Date(9997, 1, 1, 1, 59, 59, 0, time.FixedZone("UTC+2", 2*3600))
		if _, err := pki.RootTBS(p); err == nil || !strings.Contains(err.Error(), "no well-defined expiry") {
			t.Errorf("the same instant in another zone: %v", err)
		}
		// The root that ends one second before is a certificate that two verifiers read and verify.
		p.CeremonyTime = utc(9996, 12, 31, 23, 59, 58)
		r := buildRoot(t, func(q *pki.RootParams) { q.CeremonyTime = p.CeremonyTime })
		if got := r.parsed.NotAfter; !got.Equal(endOfTime.Add(-time.Second)) {
			t.Errorf("NotAfter = %v", got)
		}
		if err := verifyRootEverywhere(t, r); err != nil {
			t.Error(err)
		}
	})
	t.Run("a body that ends at the end of time is not assembled, root or intermediate", func(t *testing.T) {
		f := newGuardFixture(t)
		root := rewrite(t, f.root.tbs, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(9996, 12, 31, 23, 59, 59)), timeDER(endOfTime))
		})
		inter := rewrite(t, f.inter.tbs, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(9998, 11, 30, 23, 59, 59)), timeDER(endOfTime)) // 13 months from the 30th of November 9998 is not this
		})
		for name, body := range map[string][]byte{"a root": root, "an intermediate": inter} {
			der, err := pki.Assemble(body, rawSign(t, f.root.key, body), &f.root.key.PublicKey)
			refused(t, err, pki.ErrSignature)
			if der != nil {
				t.Errorf("%s: a certificate came with the error", name)
			}
			if name == "a root" && err != nil && !strings.Contains(err.Error(), "no well-defined expiry") {
				t.Errorf("the text does not say why: %q", err.Error())
			}
		}
		// One second less is a root of 36 months from 9996-12-31 23:59:58, which is another body and is assembled.
		ok := rewrite(t, f.root.tbs, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(9996, 12, 31, 23, 59, 58)), timeDER(endOfTime.Add(-time.Second)))
		})
		if _, err := pki.Assemble(ok, rawSign(t, f.root.key, ok), &f.root.key.PublicKey); err != nil {
			t.Errorf("the body one second less is refused: %v", err)
		}
	})
	t.Run("an intermediate cannot reach it with 13 months: no start of a year does", func(t *testing.T) {
		// A start s has the end s + 13 months; the end is the end of time only when s is the 31st of November 9998 at 23:59:59,
		// which is no date. The last starts that are issued end in December 9999 before the 31st.
		root := buildRoot(t, nil)
		csr := withExtensions(t, goodExtensions()...)
		for _, start := range []time.Time{utc(9998, 11, 30, 23, 59, 59), utc(9998, 11, 29, 23, 59, 59), utc(9998, 11, 1, 0, 0, 0)} {
			p := root.interParams(csr)
			p.CeremonyTime = start
			tbs, err := intermediateTBS(t, p)
			if err != nil {
				t.Fatalf("%v: %v", start, err)
			}
			if end := parseBodyOf(t, tbs).NotAfter; end.Equal(endOfTime) {
				t.Errorf("an intermediate that starts %v ends at the end of time", start)
			}
		}
		p := root.interParams(csr)
		p.CeremonyTime = utc(9998, 12, 1, 0, 0, 0) // the end would be in January 10000
		if _, err := intermediateTBS(t, p); err == nil {
			t.Error("a start whose end is in the year 10000 is issued")
		}
	})
}

func verifyRootEverywhere(t *testing.T, r *testRoot) error {
	t.Helper()
	if err := r.parsed.CheckSignatureFrom(r.parsed); err != nil {
		return err
	}
	return verifier.OpenSSLVerify(t, r.cert, r.cert, r.parsed.NotBefore)
}
