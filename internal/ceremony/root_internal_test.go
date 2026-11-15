package ceremony

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/wanted"
)

// The limit of the copies is half of what Record reads in all: the copies can never leave Record
// without room for the plan, the attempt, the journals, the transcript and the artifacts.
func TestTheLimitOfTheCopiesIsHalfOfTheLimitOfRecord(t *testing.T) {
	if maxCopiesBytes != 128<<20 {
		t.Errorf("maxCopiesBytes is %d, not 128 MiB", maxCopiesBytes)
	}
	if maxFolderBytes != 256<<20 {
		t.Errorf("maxFolderBytes is %d, not 256 MiB", maxFolderBytes)
	}
	if maxCopiesBytes*2 != maxFolderBytes {
		t.Errorf("the limit of the copies, %d, is not half of the limit of Record, %d", maxCopiesBytes, maxFolderBytes)
	}
}

// The stores that a root can live in are the stores that the reader of the wanted files accepts for
// a policy: the list of this package and the policy of the reader agree on these words and on the
// near misses of them. The reader keeps its list to itself, so it is asked through ritueel.yaml.
func TestTheStoresOfARootAreTheStoresThatTheWantedReaderAccepts(t *testing.T) {
	policy := func(store string) error {
		text := "version: 1\nname: Example\nrelease_address: release@example.org\npolicy:\n  stores: [" + store + "]\n" +
			"  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: 13\n"
		_, err := wanted.ParseSettings("ritueel.yaml", []byte(text))
		return err
	}
	if err := policy("piv"); err != nil {
		t.Fatalf("the reader refuses its own store word: %v", err)
	}
	for _, s := range rootStores {
		if err := policy(s); err != nil {
			t.Errorf("the store %q is in the list of the root and the reader refuses it: %v", s, err)
		}
	}
	others := []string{
		"card", "Software", "SOFTWARE", "piv2", "pgp", "kms", "aws", "hsm", "tpm", "file", "yubikey", "openpgp", "openpgp_card",
		"aws_kms", "software-key", "cloud", "ssh", "passkey", "fido2", "pkcs11", "none", "x509", "test",
	}
	for _, s := range others {
		if slices.Contains(rootStores, s) {
			t.Errorf("the list of the stores of a root holds %q", s)
		}
		if err := policy(s); err == nil {
			t.Errorf("the reader accepts the store %q and the list of the root does not hold it", s)
		}
	}
	if len(rootStores) != 4 {
		t.Errorf("the list of the stores of a root holds %d words: %v", len(rootStores), rootStores)
	}
}

// The label of a root is the label of a line of the birth journal: the one rule, asked of the
// reader of the journal for each ASCII character and for the shapes that are near it.
func TestTheLabelOfARootIsTheLabelOfABirthLine(t *testing.T) {
	accepted := func(label string) bool {
		m := map[string]any{
			"at": "2026-11-14T10:00:00Z", "label": label, "purpose": "x509-root", "store": "software",
			"place": "A.x509.key.pem", "public_key_sha256": strings.Repeat("a", 64),
		}
		b, err := canonjson.Marshal(m)
		if err != nil {
			t.Fatalf("canonjson: %v", err)
		}
		_, err = files.ReadBirthLine(b)
		return err == nil
	}
	if !accepted("A") {
		t.Fatal("the reader refuses the label A")
	}
	var labels []string
	for c := 0; c < 0x80; c++ {
		labels = append(labels, string(rune(c)))
	}
	labels = append(labels, "", "AB", "A ", " A", "É", "Α", "Ａ", "A\n", "AA", strings.Repeat("A", 100))
	for _, l := range labels {
		if got, want := isRootLabel(l), accepted(l); got != want {
			t.Errorf("label %q: the root judges %v, the journal judges %v", l, got, want)
		}
	}
}

var (
	rootX509Form    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootOpenPGPForm = regexp.MustCompile(`^[0-9a-f]{40}$`)
	rootLabelForm   = regexp.MustCompile(`^[A-Z]$`)
)

// FuzzRecordRoot feeds the whole judgement of the root that Record is given: the forms of its
// members, and then the plan's root and the pin of the birth of its label. The laws, written here
// from the page and not from the code: it never panics; a root with a member that is not of its form
// is refused, with kind ErrInvalidInput; a root of the right forms is accepted exactly when the plan
// has a root, the label, the store and the two fingerprints that the plan's root gives are the
// root's, test and copyable are the plan's, and the X.509 fingerprint is the pin of the birth of
// the label when there is a pin and the fingerprint is not empty; no root is accepted exactly when
// the plan names none; every refusal is of kind ErrInvalidInput and its text is printable ASCII.
func FuzzRecordRoot(f *testing.F) {
	h64, h40 := strings.Repeat("a", 64), strings.Repeat("b", 40)
	// label, store, x509, openpgp, test, copyable; plan: has a root, label, store, test, copyable; pin: label, pin;
	// plan root: x509, openpgp; no root given
	f.Add("A", "software", h64, h40, true, true, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("A", "software", "", "", true, true, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("B", "software", h64, "", true, true, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("A", "piv", h64, "", true, true, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("A", "software", h64, "", false, true, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("A", "software", h64, "", true, false, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("A", "software", strings.Repeat("c", 64), "", true, true, true, "A", "software", true, true, "A", h64, "", "", false)
	f.Add("A", "software", h64, "", true, true, false, "", "", false, false, "", "", "", "", false)
	f.Add("A", "software", h64, "", true, true, true, "", "", true, true, "A", h64, "", "", false)
	f.Add("", "", "", "", false, false, true, "", "", false, false, "", "", "", "", false)
	f.Add("A", "software", h64, h40, true, true, true, "A", "software", true, true, "A", h64, h64, h40, false)
	f.Add("A", "software", "", h40, true, true, true, "A", "software", true, true, "", "", h64, h40, false)
	f.Add("A", "software", h64, "", true, true, true, "A", "software", true, true, "", "", h64, h40, false)
	f.Add("A", "software", strings.Repeat("c", 64), h40, true, true, true, "A", "software", true, true, "", "", h64, h40, false)
	f.Add("A", "software", h64, strings.Repeat("c", 40), true, true, true, "A", "software", true, true, "", "", h64, h40, false)
	f.Add("", "", "", "", false, false, true, "A", "software", true, true, "A", h64, "", "", true)
	f.Add("", "", "", "", false, false, false, "", "", false, false, "", "", "", "", true)
	f.Add("AB", "card", "", "", false, false, true, "AB", "card", false, false, "", "", "", "", false)
	f.Add("\x1b", "soft ware", "", "", false, false, true, "\x1b", "soft ware", false, false, "", "", "", "", false)
	f.Fuzz(func(t *testing.T, label, store, x509, openpgp string, test, copyable, hasPlanRoot bool, pLabel, pStore string, pTest, pCopyable bool, pinLabel, pin, pX509, pOpenPGP string, noRoot bool) {
		in := &files.PlanRoot{Label: label, Store: store, X509: x509, OpenPGP: openpgp, Test: test, Copyable: copyable}
		if noRoot {
			in = nil
		}
		var plan files.Plan
		if hasPlanRoot {
			plan.Root = &files.PlanRoot{Label: pLabel, Store: pStore, X509: pX509, OpenPGP: pOpenPGP, Test: pTest, Copyable: pCopyable}
		}
		formOK := noRoot || ((label == "" || rootLabelForm.MatchString(label)) &&
			(store == "" || slices.Contains([]string{"piv", "openpgp-card", "aws-kms", "software"}, store)) &&
			(x509 == "" || rootX509Form.MatchString(x509)) &&
			(openpgp == "" || rootOpenPGPForm.MatchString(openpgp)))
		check := func(err error, what string) {
			t.Helper()
			if err == nil {
				return
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("%s: a refusal of the wrong kind: %v", what, err)
			}
			text := err.Error()
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] > 0x7e {
					t.Fatalf("%s: the text holds the byte %#x: %.80q", what, text[i], text)
				}
			}
		}
		err := checkRecordIn("record", RecordIn{Command: files.CommandApply, Outcome: files.OutcomeCompleted, Root: in})
		check(err, "the form")
		if (err == nil) != formOK {
			t.Fatalf("root %+v: form error %v, want accepted: %v", in, err, formOK)
		}
		if err != nil {
			return
		}
		r := &recordReader{op: "record", pins: map[string]string{}}
		if pinLabel != "" {
			r.pins[pinLabel] = pin
		}
		got := r.root(in, &plan)
		check(got, "the plan")
		var want bool
		switch {
		case noRoot:
			// The record has no root exactly when the plan names none.
			want = !hasPlanRoot
		default:
			want = hasPlanRoot &&
				(pLabel == "" || label == pLabel) &&
				(pStore == "" || store == pStore) &&
				test == pTest && copyable == pCopyable &&
				(pX509 == "" || x509 == pX509) &&
				(pOpenPGP == "" || openpgp == pOpenPGP)
			if want {
				if p, born := r.pins[label]; born && x509 != "" && x509 != p {
					want = false
				}
			}
		}
		if (got == nil) != want {
			t.Fatalf("root %+v, plan root %+v (has %v), pin %q for %q: error %v, want accepted: %v", in, plan.Root, hasPlanRoot, pin, pinLabel, got, want)
		}
	})
}
