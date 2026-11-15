package trustset_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/trustset"
)

// One Draft serves 16 goroutines that start behind a closed channel and are joined with a wait group.
// Each calls Sign with its own signers: every set verifies and every counter is 1. Run under the race
// detector, this shows that a Draft is read and never written after NewDraft.
func TestOneDraftSignedBySixteenGoroutines(t *testing.T) {
	c, d := addDraft(t)
	previous := c.last().ListJSON()
	const n = 16
	sets := make([]*trustset.Set, n)
	errs := make([]error, n)
	signers := make([][]*scriptedSigner, n)
	for i := range signers {
		signers[i] = signersFor(t, d, nil, nil)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sets[i], errs[i] = d.Sign(asSigners(signers[i]), func(trustset.Signed) error { return nil })
			// The accessors are read at the same time.
			_ = d.ListJSON()
			_ = d.CABundle()
			_ = d.Required()
			_, _ = d.SigningInputSHA256(newRootForGoroutine(i).Cert)
		}()
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		mustAccept(t, sets[i], previous, firstCeremony.Add(time.Hour))
		for j, k := range calls(signers[i]) {
			if k != 1 {
				t.Errorf("goroutine %d: signer %d was asked %d times", i, j, k)
			}
		}
	}
}

// newRootForGoroutine picks one of the three roots without writing the shared map from two goroutines
// at once: the roots exist already.
func newRootForGoroutine(i int) *testRoot {
	rootsMu.Lock()
	defer rootsMu.Unlock()
	return roots[[]string{"A-test", "B-test", "C-test"}[i%3]]
}

// ListJSON called in parallel gives equal copies, and changing one changes none of the others.
func TestAccessorsInParallelGiveEqualCopies(t *testing.T) {
	_, d := addDraft(t)
	const n = 16
	got := make([][]byte, n)
	bundles := make([][]byte, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got[i] = d.ListJSON()
			bundles[i] = d.CABundle()
			for j := range got[i] {
				got[i][j] = byte(i) // each goroutine scribbles on its own copy
			}
		}()
	}
	close(start)
	wg.Wait()
	want := d.ListJSON()
	if !bytes.HasPrefix(want, []byte(`{"expires_at"`)) {
		t.Fatalf("the draft changed: %.40s", want)
	}
	for i := range bundles {
		if !bytes.Equal(bundles[i], d.CABundle()) {
			t.Errorf("copy %d of the CA bundle differs", i)
		}
	}
}
