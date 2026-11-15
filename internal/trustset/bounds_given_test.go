package trustset_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/trustset"
)

// The bounds of NewDraft name the number that was given, not the limit twice: "a list holds at most
// 26 root keys and 27 OpenPGP certificates are given". The first sentences say whether the root
// keys or the certificates are over the limit. The kind is ErrParams, and the bounds are checked
// before any entry is read.

// manyRoots is n entries that are not read: the bounds come first.
func manyRoots(n int) []trustset.Root {
	out := make([]trustset.Root, n)
	for i := range out {
		out[i] = trustset.Root{Label: "bad label " + strconv.Itoa(i), X509SPKISHA256: "x"}
	}
	return out
}

// manyCerts is a map of n entries whose labels and bytes are not read.
func manyCerts(n int) map[string][]byte {
	out := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		out["label "+strconv.Itoa(i)] = nil
	}
	return out
}

// boundsError asks NewDraft and returns the text of its refusal after the kind of the package.
func boundsError(t *testing.T, in trustset.Input) string {
	t.Helper()
	d, err := trustset.NewDraft(in)
	if d != nil {
		t.Fatalf("a draft came with the error %v", err)
	}
	wantOnly(t, err, trustset.ErrParams)
	text, ok := strings.CutPrefix(err.Error(), trustset.ErrParams.Error()+": ")
	if !ok {
		t.Fatalf("the error %q does not start with the kind", err)
	}
	return text
}

// Each sentence holds the number given and the limit, for 27 and for other numbers over the limit.
func TestTheBoundsSentencesHoldTheNumberGiven(t *testing.T) {
	for _, n := range []int{27, 28, 40, 100, 1000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			base := newChain(t).input(next{labels: []string{"A", "B"}})

			in := base
			in.Roots = manyRoots(n)
			if got, want := boundsError(t, in), fmt.Sprintf("a list holds at most 26 root keys and %d root keys are given", n); got != want {
				t.Errorf("roots: %q, want %q", got, want)
			}
			in = base
			in.Certificates = manyCerts(n)
			if got, want := boundsError(t, in), fmt.Sprintf("a list holds at most 26 root keys and %d certificates are given", n); got != want {
				t.Errorf("certificates: %q, want %q", got, want)
			}
			in = base
			in.OpenPGPCertificates = manyCerts(n)
			if got, want := boundsError(t, in), fmt.Sprintf("a list holds at most 26 root keys and %d OpenPGP certificates are given", n); got != want {
				t.Errorf("OpenPGP certificates: %q, want %q", got, want)
			}
		})
	}
}

// 27 of each: the case of the sentence that was wrong (27 OpenPGP certificates were told as 26).
func TestTwentySevenOfEachIsToldAsTwentySeven(t *testing.T) {
	base := newChain(t).input(next{labels: []string{"A", "B"}})
	in := base
	in.OpenPGPCertificates = manyCerts(27)
	text := boundsError(t, in)
	if !strings.Contains(text, "27 OpenPGP certificates") || strings.Contains(text, "26 OpenPGP") {
		t.Errorf("27 OpenPGP certificates: %q", text)
	}
	in = base
	in.Roots = manyRoots(27)
	if text := boundsError(t, in); !strings.Contains(text, "27 root keys are given") {
		t.Errorf("27 roots: %q", text)
	}
	in = base
	in.Certificates = manyCerts(27)
	if text := boundsError(t, in); !strings.Contains(text, "27 certificates are given") {
		t.Errorf("27 certificates: %q", text)
	}
}

// The count is the length of the list or of the map as it is given: a map of 40 entries is 40, and
// the limit is the limit of the package.
func TestTheBoundsSentencesHoldTheLimitOfThePackage(t *testing.T) {
	base := newChain(t).input(next{labels: []string{"A"}})
	in := base
	in.OpenPGPCertificates = manyCerts(trustset.MaxRoots + 1)
	want := fmt.Sprintf("a list holds at most %d root keys and %d OpenPGP certificates are given", trustset.MaxRoots, trustset.MaxRoots+1)
	if got := boundsError(t, in); got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

// The three checks are made in the order roots, certificates, OpenPGP certificates, and each is
// made before anything else is read (a sequence of 0 is told after all three).
func TestTheBoundsAreCheckedInTheirOrderBeforeAnythingElse(t *testing.T) {
	base := newChain(t).input(next{labels: []string{"A", "B"}})
	base.Sequence = 0
	in := base
	in.Roots, in.Certificates, in.OpenPGPCertificates = manyRoots(27), manyCerts(28), manyCerts(29)
	if text := boundsError(t, in); !strings.HasSuffix(text, "and 27 root keys are given") {
		t.Errorf("all three over: %q", text)
	}
	in = base
	in.Certificates, in.OpenPGPCertificates = manyCerts(28), manyCerts(29)
	if text := boundsError(t, in); !strings.HasSuffix(text, "and 28 certificates are given") {
		t.Errorf("certificates and OpenPGP certificates over: %q", text)
	}
	in = base
	in.OpenPGPCertificates = manyCerts(29)
	if text := boundsError(t, in); !strings.HasSuffix(text, "and 29 OpenPGP certificates are given") {
		t.Errorf("OpenPGP certificates over: %q", text)
	}
	// Only one over, the others at the limit: the sentence names the one that is over.
	in = base
	in.Roots, in.Certificates, in.OpenPGPCertificates = manyRoots(26), manyCerts(27), manyCerts(26)
	if text := boundsError(t, in); !strings.HasSuffix(text, "and 27 certificates are given") {
		t.Errorf("one over: %q", text)
	}
	// Under the limit the sequence is told, so the bounds did not take its place.
	in = base
	_, err := trustset.NewDraft(in)
	wantOnly(t, err, trustset.ErrParams)
	if strings.Contains(err.Error(), "are given") {
		t.Errorf("the bounds are told for an input within them: %v", err)
	}
}

// The limit itself is within the bounds: 26 roots, 26 certificates and 26 OpenPGP certificates are
// not told as too many, and a list of 26 is made.
func TestTheLimitItselfIsNotTooMany(t *testing.T) {
	d, err := trustset.NewDraft(keyringInput(t, labelsTo(26)...))
	if err != nil {
		t.Fatalf("26 roots: %v", err)
	}
	if len(d.Keyring()) == 0 {
		t.Error("no keyring file")
	}
	in := keyringInput(t, labelsTo(26)...)
	in.OpenPGPCertificates["AA"] = nil
	text := boundsError(t, in)
	if text != "a list holds at most 26 root keys and 27 OpenPGP certificates are given" {
		t.Errorf("one more than the limit: %q", text)
	}
}
