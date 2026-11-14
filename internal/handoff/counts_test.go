package handoff_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// The page gives no number for the entries of `attestation` or of `primaries`, and the checker bounds both so
// that a file of 256 KiB does not hand a verifier tens of thousands of strings. The bounds are the package's
// own: the vectors and a real card need two certificates (a chain is two to four) and two primaries.

func TestTheBoundsOnTheListsAreLargeEnoughForTheVectorsAndACardAndSmallEnoughToBound(t *testing.T) {
	if handoff.MaxAttestation < 4 {
		t.Errorf("an attestation of 4 certificates is a real chain, and the bound is %d", handoff.MaxAttestation)
	}
	if handoff.MaxPrimaries < 2 {
		t.Errorf("the vectors have 2 primaries, and the bound is %d", handoff.MaxPrimaries)
	}
	if handoff.MaxAttestation > 64 || handoff.MaxPrimaries > 64 {
		t.Errorf("the bounds %d and %d do not bound a file of 256 KiB to a small list", handoff.MaxAttestation, handoff.MaxPrimaries)
	}
}

func certs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = b64(fmt.Sprintf("certificate %d", i))
	}
	return out
}

func TestAnAttestationUpToTheBoundIsReadAndOneOverIsMalformedAtCheckTwo(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard} {
		for _, n := range []int{2, 3, 4, handoff.MaxAttestation - 1, handoff.MaxAttestation, handoff.MaxAttestation + 1, handoff.MaxAttestation + 2, 100, 1000} {
			t.Run(fmt.Sprintf("%s/%d", store, n), func(t *testing.T) {
				f := newFixture(t, store, csrSpec{})
				f.proof["evidence"] = map[string]any{"attestation": certs(n)}
				sv := returning(f.goodEvidence(store))
				v, err := checkerWith(t, store, sv).Check(t.Context(), f.request())
				if n <= handoff.MaxAttestation {
					wantAccepted(t, v, err)
					return
				}
				wantRefusal(t, v, err, handoff.CodeMalformed, 2)
				if sv.calls.Load() != 0 {
					t.Error("a verifier was given a list over the bound")
				}
			})
		}
	}
}

func TestAnAttestationThatFillsTheWholeFileIsMalformedAndIsNotHandedToAVerifier(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	// Four characters of Base64 and a comma and two quotes make seven bytes: about 37,000 strings in 256 KiB.
	one := `"AAAA"`
	list := strings.Repeat(one+",", (handoff.MaxFileSize-400)/len(one+",")) + one
	proof := fmt.Sprintf(`{"handoff":1,"type":"x509-intermediate","request_sha256":%q,"store":"piv","evidence":{"attestation":[%s]}}`, digestHex(f.der), list)
	if len(proof) > handoff.MaxFileSize {
		t.Fatalf("test setup: %d bytes", len(proof))
	}
	sv := returning(f.goodEvidence(handoff.StorePIV))
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), withProofBytes(f, []byte(proof)))
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	if sv.calls.Load() != 0 {
		t.Error("a verifier was given the list")
	}
}

func fingerprints(n int) []string {
	out := make([]string, n)
	for i := range out {
		sum := sha256.Sum256([]byte(fmt.Sprintf("primary %d", i)))
		out[i] = hex.EncodeToString(sum[:20])
	}
	return out
}

func TestPrimariesUpToTheBoundAreReadAndOneOverIsMalformedAtCheckTwo(t *testing.T) {
	for _, n := range []int{1, 2, 3, handoff.MaxPrimaries - 1, handoff.MaxPrimaries, handoff.MaxPrimaries + 1, handoff.MaxPrimaries + 2, 100, 5000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["primaries"] = fingerprints(n) }))
			if n <= handoff.MaxPrimaries {
				if !errors.Is(err, handoff.ErrTypeNotBuilt) || v.Refused() || v.Accepted() {
					t.Fatalf("code %q, error %v", v.Code, err)
				}
				if got := statuses(v); got != "ppnnnnnnn" {
					t.Errorf("statuses %s", got)
				}
				return
			}
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
}

func TestPrimariesThatFillTheWholeFileAreMalformed(t *testing.T) {
	// 40 digits, two quotes and a comma: 43 bytes, about 6,000 of them in 256 KiB.
	n := (handoff.MaxFileSize - 500) / 43
	list := make([]string, n)
	for i := range list {
		list[i] = fmt.Sprintf("%040x", i)
	}
	r := pgpRequest(func(m map[string]any) { m["primaries"] = list })
	if len(r.Files[handoff.FileProof]) > handoff.MaxFileSize {
		t.Fatalf("test setup: %d bytes", len(r.Files[handoff.FileProof]))
	}
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

func TestAFingerprintTwiceInPrimariesIsMalformedWhereverItStands(t *testing.T) {
	fp := fingerprints(6)
	for name, list := range map[string][]string{
		"two the same":                   {fp[0], fp[0]},
		"the first and the last":         {fp[0], fp[1], fp[2], fp[0]},
		"two in the middle":              {fp[0], fp[1], fp[1], fp[2]},
		"the last two":                   {fp[0], fp[1], fp[2], fp[2]},
		"three the same":                 {fp[3], fp[3], fp[3]},
		"a pair after many":              {fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[5]},
		"a pair at the bound":            append(fingerprints(handoff.MaxPrimaries-1), fingerprints(1)[0]),
		"the same digits, other letters": {strings.Repeat("ab", 20), strings.Repeat("ab", 20)},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["primaries"] = list }))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
	// Fingerprints that differ in one digit are two, and so are the same ones in another order.
	for name, list := range map[string][]string{
		"one digit apart":    {strings.Repeat("a", 40), strings.Repeat("a", 39) + "b"},
		"in the other order": {fp[1], fp[0]},
		"at the first digit": {"0" + strings.Repeat("a", 39), "1" + strings.Repeat("a", 39)},
	} {
		v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["primaries"] = list }))
		if !errors.Is(err, handoff.ErrTypeNotBuilt) || v.Refused() {
			t.Errorf("%s: code %q, error %v", name, v.Code, err)
		}
	}
}

func TestAFingerprintIsLowerCaseHexadecimalOnly(t *testing.T) {
	lower := strings.Repeat("ab12", 10)
	for name, fp := range map[string]string{
		"one capital letter":        "AB" + lower[2:],
		"all capitals":              strings.ToUpper(lower),
		"a letter after f":          lower[:39] + "g",
		"a space":                   lower[:39] + " ",
		"39 digits":                 lower[:39],
		"41 digits":                 lower + "0",
		"a prefix 0x":               "0x" + lower[2:],
		"a letter that looks right": lower[:39] + "а",
		"a digit that is not ASCII": lower[:39] + "٣",
		"empty":                     "",
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["primaries"] = []string{fp} }))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
	v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["primaries"] = []string{lower} }))
	if !errors.Is(err, handoff.ErrTypeNotBuilt) || v.Refused() {
		t.Errorf("code %q, error %v", v.Code, err)
	}
	// The digest of the request is lower-case hexadecimal too.
	d := digestHex(subkeyBytes)
	for _, bad := range []string{strings.ToUpper(d), d[:63] + "G", d[:63], d + "0"} {
		v, err := newChecker(t).Check(t.Context(), pgpRequest(func(m map[string]any) { m["request_sha256"] = bad }))
		wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	}
}

// Empty text in the evidence is malformed.

func TestAnEmptyTextInTheEvidenceIsMalformed(t *testing.T) {
	good := b64("certificate")
	for name, tc := range map[string]struct {
		store    handoff.Store
		evidence map[string]any
	}{
		"an empty certificate first":     {handoff.StorePIV, map[string]any{"attestation": []string{"", good}}},
		"an empty certificate last":      {handoff.StorePIV, map[string]any{"attestation": []string{good, ""}}},
		"an empty certificate on a card": {handoff.StoreOpenPGPCard, map[string]any{"attestation": []string{good, good, ""}}},
		"an empty key_arn":               {handoff.StoreKMS, map[string]any{"key_arn": "", "public_key": good}},
		"an empty public_key":            {handoff.StoreKMS, map[string]any{"key_arn": "arn:aws:kms:eu-west-1:123456789012:key/x", "public_key": ""}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.store, csrSpec{})
			f.proof["evidence"] = tc.evidence
			sv := returning(f.goodEvidence(tc.store))
			v, err := checkerWith(t, tc.store, sv).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
			if sv.calls.Load() != 0 {
				t.Error("a verifier ran")
			}
		})
	}
}

// A PIV key whose evidence lacks the firmware or the PIN policy is policy.

func TestAPIVKeyWhoseEvidenceLacksTheFirmwareOrThePINPolicyIsPolicyAtCheckNine(t *testing.T) {
	for name, change := range map[string]func(ev *handoff.Evidence){
		"no firmware":                     func(ev *handoff.Evidence) { ev.Firmware = "" },
		"no PIN policy":                   func(ev *handoff.Evidence) { ev.PINPolicy = "" },
		"neither":                         func(ev *handoff.Evidence) { ev.Firmware, ev.PINPolicy = "", "" },
		"a firmware that is not numbers":  func(ev *handoff.Evidence) { ev.Firmware = "latest" },
		"a PIN policy that is not a word": func(ev *handoff.Evidence) { ev.PINPolicy = "maybe" },
	} {
		t.Run(name, func(t *testing.T) {
			v, err := pivVerdict(t, change)
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestTheClockIsReadOnceForACallAndOnlyForAVerifier(t *testing.T) {
	// A call that reaches no verifier does not read the clock; one that reaches a verifier reads it once.
	var reads int
	clock := func(c *handoff.Config) { c.Now = func() time.Time { reads++; return testNow } }
	soft := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v, err := newCheckerWith(t, clock).Check(t.Context(), soft.request())
	wantAccepted(t, v, err)
	if reads != 0 {
		t.Errorf("the clock was read %d times for a software key", reads)
	}
	piv := newFixture(t, handoff.StorePIV, csrSpec{})
	v, err = checkerWithCfg(t, handoff.StorePIV, returning(piv.goodEvidence(handoff.StorePIV)), clock).Check(t.Context(), piv.request())
	wantAccepted(t, v, err)
	if reads != 1 {
		t.Errorf("the clock was read %d times for one verifier", reads)
	}
}
