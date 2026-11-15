package bundle_test

import (
	"slices"
	"strings"
	"testing"
)

// The files of a ceremony that made keys of two kinds (a root.json with an OpenPGP fingerprint and
// revocations, a record that lists the revocations, a journal with two births for one label) sit in
// the bundle beside the trust set. The bundle reads the newest trust set and the settings, and none
// of those files: they change neither what it reads nor what it refuses.

func TestTheFilesOfAKeyOfTwoKindsDoNotChangeWhatTheBundleReads(t *testing.T) {
	plain, _ := bundleWith(t, trustAB(t, 7))
	wantRoots, wantSet, err := plain.Roots()
	if err != nil {
		t.Fatal(err)
	}
	wantPrimaries, _, err := plain.Primaries()
	if err != nil {
		t.Fatal(err)
	}

	rootJSON := `{"created_at":"2026-11-20T10:00:00Z","label":"A","openpgp_created":"2026-11-20T09:00:00Z",` +
		`"openpgp_fingerprint":"` + strings.Repeat("c", 40) + `","removal_sha256":"` + strings.Repeat("1", 64) + `",` +
		`"revocations":{"compromised":"` + strings.Repeat("2", 64) + `","superseded":"` + strings.Repeat("3", 64) + `"},` +
		`"store":"software","test":true,"version":1,"x509_spki_sha256":"` + strings.Repeat("a", 64) + `"}`
	folder := "history/20261120T100000Z-apply/"
	extra := tree{
		"roots/A/root.json":     []byte(rootJSON),
		folder + "record.json":  []byte(`{"revocations":[{"label":"A","reason":"compromised","sha256":"` + strings.Repeat("2", 64) + `"}]}`),
		folder + "births.jsonl": []byte(`{"label":"A","purpose":"x509-root"}` + "\n" + `{"label":"A","purpose":"openpgp-primary"}` + "\n"),
	}
	b, _ := bundleWith(t, merge(trustAB(t, 7), extra))
	roots, set, err := b.Roots()
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if set != wantSet || len(roots) != len(wantRoots) {
		t.Errorf("Roots = %d keys of %+v, want %d of %+v", len(roots), set, len(wantRoots), wantSet)
	}
	primaries, _, err := b.Primaries()
	if err != nil {
		t.Fatalf("Primaries: %v", err)
	}
	if !slices.Equal(fingerprintsOf(primaries), fingerprintsOf(wantPrimaries)) {
		t.Errorf("Primaries = %v, want %v", fingerprintsOf(primaries), fingerprintsOf(wantPrimaries))
	}
}
