// Package attesttest is the test support of the evidence verifiers of piv and openpgp-card: the pinned
// bundle and the proofs of the vectors of testdata/hand-off/v1, and a made-up maker ([Maker]) that builds
// chains of attestation certificates in memory, with the faults that a test needs to show a verifier
// refuses. It imports "testing" and is for test files only; no shipped code imports it.
//
// Everything here is made up: the hierarchy of the vectors is the "Example Test" hierarchy of the
// generator, and the maker's keys are made in memory and never written to a file. The vectors are read
// through internal/testrepo.
package attesttest

import (
	"encoding/json"
	"path"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/testrepo"
)

const vectorsDir = "testdata/hand-off/v1"

// The two intermediates of the vector hierarchy, by file name. The manifest has one list of them.
const (
	vectorPIVIntermediate     = "pki/test-attestation-intermediate.pem"
	vectorOpenPGPIntermediate = "pki/test-opgp-attestation-intermediate.pem"
)

// manifest is the part of manifest.json that this package reads.
type manifest struct {
	Pinned struct {
		AttestationRoots         []string `json:"attestation_roots"`
		AttestationIntermediates []string `json:"attestation_intermediates"`
	} `json:"pinned"`
	Requests []struct {
		ID    string   `json:"id"`
		Files []string `json:"files"`
	} `json:"requests"`
}

func readManifest(t testing.TB) manifest {
	t.Helper()
	var m manifest
	if err := json.Unmarshal(testrepo.Read(t, vectorsDir, "manifest.json"), &m); err != nil {
		t.Fatalf("attesttest: the manifest does not parse: %v", err)
	}
	return m
}

// certOfFile returns the DER of the one certificate in a PEM file of the vectors.
func certOfFile(t testing.TB, name string) []byte {
	t.Helper()
	ders, err := attest.CertificatesFromPEM(testrepo.Read(t, vectorsDir, name))
	if err != nil || len(ders) != 1 {
		t.Fatalf("attesttest: %s does not hold exactly one certificate: %v", name, err)
	}
	return ders[0]
}

// VectorBundle builds a Bundle from pinned.attestation_roots and pinned.attestation_intermediates of
// testdata/hand-off/v1/manifest.json. The manifest has one list of intermediates, so the helper tells them
// apart by file name: "test-attestation-intermediate.pem" is piv and "test-opgp-attestation-intermediate.pem"
// is openpgp, and any other name fails the test. The version is "example-test".
func VectorBundle(t testing.TB) *attest.Bundle {
	t.Helper()
	m := readManifest(t)
	spec := attest.BundleSpec{Version: "example-test"}
	for _, f := range m.Pinned.AttestationRoots {
		spec.Roots = append(spec.Roots, certOfFile(t, f))
	}
	for _, f := range m.Pinned.AttestationIntermediates {
		switch f {
		case vectorPIVIntermediate:
			spec.PIVIntermediates = append(spec.PIVIntermediates, certOfFile(t, f))
		case vectorOpenPGPIntermediate:
			spec.OpenPGPIntermediates = append(spec.OpenPGPIntermediates, certOfFile(t, f))
		default:
			t.Fatalf("attesttest: the manifest pins the intermediate %s, which this helper cannot place in a group", f)
		}
	}
	b, err := attest.NewBundle(spec)
	if err != nil {
		t.Fatalf("attesttest: the vector bundle is refused: %v", err)
	}
	return b
}

// wireProof is the part of a proof file that a verifier reads.
type wireProof struct {
	Handoff       int             `json:"handoff"`
	Type          string          `json:"type"`
	RequestSHA256 string          `json:"request_sha256"`
	Store         string          `json:"store"`
	Evidence      json.RawMessage `json:"evidence"`
}

// VectorProof returns the proof of a request case of the set as a *handoff.Proof (Handoff, Type,
// RequestSHA256, Store and Evidence), read with encoding/json: a test may, the shipped code uses the
// strict reader. stem is the stem of the proof file, `<stem>.proof.json` in requests/.
func VectorProof(t testing.TB, stem string) *handoff.Proof {
	t.Helper()
	var w wireProof
	if err := json.Unmarshal(testrepo.Read(t, vectorsDir, "requests", stem+"."+handoff.FileProof), &w); err != nil {
		t.Fatalf("attesttest: the proof %s does not parse: %v", stem, err)
	}
	return &handoff.Proof{
		Handoff:       w.Handoff,
		Type:          handoff.Type(w.Type),
		RequestSHA256: w.RequestSHA256,
		Store:         handoff.Store(w.Store),
		Evidence:      w.Evidence,
	}
}

// VectorEvidenceStems lists, sorted and once each, the stems of the proof files of every request case of
// the set whose store is piv or openpgp-card. It fails the test when there is none.
func VectorEvidenceStems(t testing.TB) []string {
	t.Helper()
	var stems []string
	for _, c := range readManifest(t).Requests {
		for _, f := range c.Files {
			stem, ok := strings.CutSuffix(path.Base(f), "."+handoff.FileProof)
			if !ok || slices.Contains(stems, stem) {
				continue
			}
			if s := VectorProof(t, stem).Store; s == handoff.StorePIV || s == handoff.StoreOpenPGPCard {
				stems = append(stems, stem)
			}
		}
	}
	if len(stems) == 0 {
		t.Fatal("attesttest: no request case of the set has a piv or openpgp-card proof")
	}
	slices.Sort(stems)
	return stems
}
