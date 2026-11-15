package answer_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
)

// The requester reads the subkey file of its own request with the same bound as the certifier: as many
// back-signatures as the checks take primaries (the size of a root list), and no more.

func pgpKeys(t testing.TB, n int) []*pgpKey {
	t.Helper()
	out := make([]*pgpKey, n)
	for i := range out {
		out[i] = newPGPKey(t, pgpSubCreated)
	}
	return out
}

func TestARequestForTheMostPrimariesIsReadByTheRequesterAndForOneMoreIsNot(t *testing.T) {
	for _, n := range []int{2, 16, 17, 20, handoff.MaxPrimaries} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := newPGPRequest(t, pgpKeys(t, n), "sign")
			a, err := answer.AskedFromRequest(r.request())
			if err != nil || a == nil {
				t.Fatalf("AskedFromRequest = (%v, %v)", a, err)
			}
		})
	}
	over := newPGPRequest(t, pgpKeys(t, handoff.MaxPrimaries+1), "sign")
	a, err := answer.AskedFromRequest(over.request())
	if a != nil || !errors.Is(err, answer.ErrConfig) || !strings.Contains(err.Error(), fmt.Sprintf("more than %d fingerprints", handoff.MaxPrimaries)) {
		t.Errorf("%d primaries: (%v, %v), want ErrConfig that names the bound of the proof", handoff.MaxPrimaries+1, a, err)
	}
}

// A subkey file with more packets than the bound is refused when it is split, whatever the proof lists: the proof
// here lists the most primaries, the file holds more back-signatures. It is the file that is refused, with the
// words of reading the subkey file.
func TestASubkeyFileWithMoreBackSignaturesThanTheBoundIsRefusedWhenItIsRead(t *testing.T) {
	keys := pgpKeys(t, handoff.MaxPrimaries)
	r := newPGPRequest(t, keys, "sign")
	if _, err := answer.AskedFromRequest(r.request()); err != nil {
		t.Fatalf("the file at the bound: %v", err)
	}
	for _, extra := range []int{1, 2, 100} {
		long := newPGPRequest(t, keys, "sign")
		long.sub, long.subPacket, long.sigs = r.sub, r.subPacket, slices.Clone(r.sigs)
		for range extra {
			long.sigs = append(long.sigs, r.sigs[0])
		}
		req := long.request() // the proof lists the most primaries, the file holds more back-signatures
		a, err := answer.AskedFromRequest(req)
		if a != nil || !errors.Is(err, answer.ErrConfig) || !strings.Contains(err.Error(), "reading the subkey file") {
			t.Errorf("%d packets after the subkey: (%v, %v), want ErrConfig from reading the subkey file", handoff.MaxPrimaries+extra, a, err)
		}
	}
}

// With fewer back-signatures than the proof lists the count is the fault, as before.
func TestASubkeyFileWithFewerBackSignaturesThanTheProofListsIsRefused(t *testing.T) {
	keys := pgpKeys(t, handoff.MaxPrimaries)
	r := newPGPRequest(t, keys, "sign")
	short := newPGPRequest(t, keys, "sign")
	short.sub, short.subPacket, short.sigs = r.sub, r.subPacket, r.sigs[:handoff.MaxPrimaries-1]
	short.proofEdit = func(m map[string]any) { m["primaries"] = r.fingerprints() }
	a, err := answer.AskedFromRequest(short.request())
	if a != nil || !errors.Is(err, answer.ErrConfig) || !strings.Contains(err.Error(), "one back-signature for each primary") {
		t.Errorf("(%v, %v), want ErrConfig that says one back-signature for each primary", a, err)
	}
}
