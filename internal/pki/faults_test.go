package pki_test

import (
	"fmt"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// A ceremony time before the year 1 is not a date that a certificate holds: the years are 1 to 9999.
// Once the builders let such a time through and wrote a date that no parser reads (the year -1 prints
// as "-001..."), so that the error came late, from Assemble, as ErrSignature. Both builders refuse it as
// ErrParams, as they do the year 10000.
func TestCeremonyBeforeTheYear1IsRefused(t *testing.T) {
	root := buildRoot(t, nil)
	csr := withExtensions(t, goodExtensions()...)
	for _, year := range []int{0, -1, -5, -9999} {
		at := time.Date(year, time.March, 4, 5, 6, 7, 0, time.UTC)
		t.Run(fmt.Sprint("a root in the year ", year), func(t *testing.T) {
			p := rootParams(&root.key.PublicKey)
			p.CeremonyTime = at
			tbs, err := pki.RootTBS(p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body came with the error")
			}
		})
		t.Run(fmt.Sprint("an intermediate in the year ", year), func(t *testing.T) {
			p := root.interParams(csr)
			p.CeremonyTime = at
			tbs, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body came with the error")
			}
		})
	}
}
