package openpgp_test

import (
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// The revocation signatures that ReadRevocation accepts are held to the two programs that read them
// in a keyring: gpgv and sqv, each started with a keyring file of its own (internal/verifier). The
// keyring has the primary key packet, the revocation signature right after it (where gpg reads it as a
// revocation of the primary), the user ID, the self-signature, a bound subkey, and a message signed by
// the subkey. What the tools do is what docs/learn/openpgp-release-keys.md measured on 2026-11-01,
// "A revocation signature does not protect every user", and the test says that date again when it
// runs: a tool that answers otherwise is a failure that is read, and not a skipped case.
//
// The world is built so that a message can be signed before and after the revocation: the primary
// 96 hours ago, the subkey 72, the binding 48, the revocation 12, a message 24 hours ago (before the
// revocation, after the binding) and one an hour ago (after it).

const learnMeasuredOn = "2026-11-01"

type revocationWorld struct {
	w      world
	ring   func(rev []byte) []byte
	before []byte // a message signature made before the revocation
	after  []byte // a message signature made after it
	now    time.Time
}

func newRevocationWorld(t *testing.T) revocationWorld {
	t.Helper()
	now := nowSec()
	ceremony := now.Add(-48 * time.Hour)
	wt := worldTimes{
		created:    now.Add(-96 * time.Hour),
		ceremony:   ceremony,
		expires:    ceremony.AddDate(3, 0, 0),
		subAt:      now.Add(-72 * time.Hour),
		subEnd:     ceremony.AddDate(1, 1, 0),
		capability: "sign",
	}
	w := buildWorld(t, wt)
	parts, err := openpgp.SplitCertificate(w.cert)
	if err != nil {
		t.Fatalf("SplitCertificate: %v", err)
	}
	return revocationWorld{
		w: w,
		ring: func(rev []byte) []byte {
			// The revocation stands right after the primary key packet.
			out := slices.Concat(parts.Key, rev, parts.UserID)
			for _, s := range parts.Signatures {
				out = append(out, s...)
			}
			return slices.Concat(out, w.bound)
		},
		before: w.signMessage(t, now.Add(-24*time.Hour), message),
		after:  w.signMessage(t, now.Add(-1*time.Hour), message),
		now:    now,
	}
}

// revocationAt is the revocation signature of the world's primary for a reason, dated 12 hours ago.
func (rw revocationWorld) revocationAt(t *testing.T, r openpgp.Reason) []byte {
	t.Helper()
	pp := rw.w.pp
	pp.CeremonyTime = rw.now.Add(-12 * time.Hour)
	rev, err := openpgp.RevocationSignature(nil, pp, r)
	if err != nil {
		t.Fatalf("RevocationSignature: %v", err)
	}
	return rev
}

func (rw revocationWorld) primary(t *testing.T) *openpgp.PrimaryKey {
	t.Helper()
	p, err := openpgp.NewPrimaryKey(&rw.w.signer.key.PublicKey, rw.w.pp.CreationTime)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With no revocation both tools accept both messages: the control of every case below.
func TestGpgvAndSqvAcceptBothMessagesWhenThereIsNoRevocation(t *testing.T) {
	rw := newRevocationWorld(t)
	t.Logf("measured on %s (docs/learn/openpgp-release-keys.md); run on %s", learnMeasuredOn, time.Now().UTC().Format("2006-01-02"))
	for name, sig := range map[string][]byte{"before": rw.before, "after": rw.after} {
		if err := verifier.GPGVVerify(t, rw.w.keyring, sig, message, rw.w.fp(t)); err != nil {
			t.Errorf("gpgv refuses the message signed %s the revocation, with no revocation: %v", name, err)
		}
		if err := verifier.SQVVerify(t, rw.w.keyring, sig, message, rw.w.fp(t), rw.now); err != nil {
			t.Errorf("sqv refuses the message signed %s the revocation, with no revocation: %v", name, err)
		}
	}
}

// sqv, as measured: a hard reason (compromised, no reason) refuses every signature of the key, at any
// time; a soft reason (superseded, retired) refuses only the signatures made after the revocation.
func TestSqvReadsTheRevocationThatReadRevocationAcceptsAsTheLearnPageMeasured(t *testing.T) {
	rw := newRevocationWorld(t)
	t.Logf("measured on %s (docs/learn/openpgp-release-keys.md); run on %s", learnMeasuredOn, time.Now().UTC().Format("2006-01-02"))
	for _, c := range []struct {
		name       string
		r          openpgp.Reason
		hard       bool
		beforeGood bool
	}{
		{"compromised", openpgp.Compromised, true, false},
		{"no reason", openpgp.NoReason, true, false},
		{"superseded", openpgp.Superseded, false, true},
		{"retired", openpgp.Retired, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			rev := rw.revocationAt(t, c.r)
			// The packet that the tools read is one that ReadRevocation accepts, for the primary of the keyring.
			got, err := openpgp.ReadRevocation(rev, rw.primary(t))
			if err != nil || got.Reason != c.r {
				t.Fatalf("ReadRevocation = %+v, %v; want the reason %v", got, err, c.r)
			}
			ring := rw.ring(rev)
			err = verifier.SQVVerify(t, ring, rw.before, message, rw.w.fp(t), rw.now)
			if (err == nil) != c.beforeGood {
				t.Errorf("sqv accepts the message signed before a %s revocation: %v, measured %v (%v)", c.name, err == nil, c.beforeGood, err)
			}
			if err := verifier.SQVVerify(t, ring, rw.after, message, rw.w.fp(t), rw.now); err == nil {
				t.Errorf("sqv accepts the message signed after a %s revocation", c.name)
			}
		})
	}
}

// gpgv, as the page says it measured: the revocation does not make it refuse. gpgv exits with 0 and
// reports a valid signature for the message signed before and after, for every reason. That it also
// names the revocation in its status output is asserted apart, in the next test.
func TestGpgvExitsWithZeroWithTheRevocationThatReadRevocationAccepts(t *testing.T) {
	rw := newRevocationWorld(t)
	t.Logf("measured on %s (docs/learn/openpgp-release-keys.md); run on %s", learnMeasuredOn, time.Now().UTC().Format("2006-01-02"))
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			ring := rw.ring(rw.revocationAt(t, c.r))
			for name, sig := range map[string][]byte{"before": rw.before, "after": rw.after} {
				status, exit := verifier.GPGVStatus(t, ring, sig, message)
				if exit != nil {
					t.Errorf("gpgv exits with an error for the message signed %s a %s revocation: %v", name, c.name, exit)
				}
				if !hasStatus(status, "VALIDSIG") {
					t.Errorf("gpgv does not report VALIDSIG for the message signed %s a %s revocation: %q", name, c.name, status)
				}
			}
		})
	}
}

// What gpgv does with the revocation that stands right after the primary key packet: it reports a
// good signature (VALIDSIG), exits with 0, and names the revocation in its status output with a
// REVKEYSIG line, in place of GOODSIG, for the message signed before and after, for every reason. The
// verdict about a revoked key is therefore read from the status output and not from the exit status
// (record 0009, rule 20); the tests of interop_test.go hold the same fact for a compromised revocation
// built by the hand-off writers, and this one holds it for the four reasons on a keyring that is
// spliced with SplitCertificate.
func TestGpgvNamesTheRevocationInItsStatusAndStillExitsWithZero(t *testing.T) {
	rw := newRevocationWorld(t)
	t.Logf("measured on %s (docs/learn/openpgp-release-keys.md); run on %s", learnMeasuredOn, time.Now().UTC().Format("2006-01-02"))
	for _, c := range allReasons {
		t.Run(c.name, func(t *testing.T) {
			ring := rw.ring(rw.revocationAt(t, c.r))
			for name, sig := range map[string][]byte{"before": rw.before, "after": rw.after} {
				status, exit := verifier.GPGVStatus(t, ring, sig, message)
				if exit != nil {
					t.Errorf("gpgv exits with an error for the message signed %s a %s revocation: %v", name, c.name, exit)
				}
				if !hasStatus(status, "VALIDSIG") {
					t.Errorf("gpgv does not report VALIDSIG for the message signed %s a %s revocation: %q", name, c.name, status)
				}
				if !hasStatus(status, "REVKEYSIG") {
					t.Errorf("gpgv does not name the %s revocation for the message signed %s it: %q", c.name, name, status)
				}
				if hasStatus(status, "GOODSIG") {
					t.Errorf("gpgv reports GOODSIG for the message signed %s a %s revocation: %q", name, c.name, status)
				}
			}
		})
	}
}

// A revocation that was changed by one byte after signing, which ReadRevocation refuses, revokes
// nothing for sqv either: the two readers agree on what is a revocation.
func TestSqvIgnoresARevocationThatReadRevocationRefuses(t *testing.T) {
	rw := newRevocationWorld(t)
	rev := rw.revocationAt(t, openpgp.Compromised)
	bad := slices.Clone(rev)
	bad[len(bad)-1] ^= 1
	if _, err := openpgp.ReadRevocation(bad, rw.primary(t)); err == nil {
		t.Fatal("ReadRevocation accepts a changed packet")
	}
	if err := verifier.SQVVerify(t, rw.ring(bad), rw.after, message, rw.w.fp(t), rw.now); err != nil {
		t.Errorf("sqv refuses because of a revocation that does not verify: %v", err)
	}
	if err := verifier.SQVVerify(t, rw.ring(rev), rw.after, message, rw.w.fp(t), rw.now); err == nil {
		t.Error("the control: sqv accepts a message after a compromised revocation that verifies")
	}
	// A revocation of another primary is refused by ReadRevocation and changes nothing for sqv.
	other := newSigner(t)
	op := rw.w.pp
	op.Key = other
	op.CeremonyTime = rw.now.Add(-12 * time.Hour)
	foreign, err := openpgp.RevocationSignature(nil, op, openpgp.Compromised)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.ReadRevocation(foreign, rw.primary(t)); err == nil {
		t.Error("ReadRevocation accepts the revocation of another primary")
	}
	if err := verifier.SQVVerify(t, rw.ring(foreign), rw.after, message, rw.w.fp(t), rw.now); err != nil {
		t.Errorf("sqv refuses because of a revocation of another key: %v", err)
	}
}

// What the splice is made of: SplitCertificate gives the key, the user ID and the signatures that the
// keyring file needs, and the three joined are the certificate the tools read without the revocation.
func TestTheKeyringOfTheMatrixIsTheCertificateWithTheRevocationAfterItsKeyPacket(t *testing.T) {
	rw := newRevocationWorld(t)
	rev := rw.revocationAt(t, openpgp.Compromised)
	ps := splitPackets(t, rw.ring(rev))
	if got := tags(ps); len(got) < 5 || got[0] != tagPublicKey || got[1] != tagSignature || got[2] != tagUserID || got[3] != tagSignature {
		t.Errorf("the keyring has the tags % d, want a key, a signature, a user ID, a signature, then the subkey and its binding", got)
	}
	if string(ps[1].Raw) != string(rev) {
		t.Error("the second packet of the keyring is not the revocation")
	}
}
