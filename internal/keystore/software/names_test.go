package software

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func TestTheNamesOfTheKeyFilesOfEachModeAreThePagesNames(t *testing.T) {
	cases := []struct {
		mode   Mode
		kind   FileKind
		reason string
		want   string
	}{
		{ModeTest, FileX509, "", "A.x509.key.pem"},
		{ModeTest, FileOpenPGP, "", "A.openpgp.key.asc"},
		{ModeTest, FileRevocation, "compromised", "A.revocation.compromised.asc"},
		{ModeTest, FileRevocation, "superseded", "A.revocation.superseded.asc"},
		{ModeTest, FileRevocation, "retired", "A.revocation.retired.asc"},
		{ModeTest, FileRevocation, "no-reason", "A.revocation.no-reason.asc"},
		{ModeTest, FileRemoval, "", "A.removal.jws"},
		{ModePassphrase, FileX509, "", "A.x509.key.age"},
		{ModePassphrase, FileOpenPGP, "", "A.openpgp.key.age"},
		{ModePassphrase, FileRevocation, "compromised", "A.revocation.compromised.pgp.age"},
		{ModePassphrase, FileRevocation, "no-reason", "A.revocation.no-reason.pgp.age"},
		{ModePassphrase, FileRemoval, "", "A.removal.jws.age"},
	}
	for _, c := range cases {
		got := fileName(c.mode, "A", c.kind, c.reason)
		if got != c.want {
			t.Errorf("%v %s %s: %q, want %q", c.mode, c.kind, c.reason, got, c.want)
		}
		if err := fsx.CheckName(got); err != nil {
			t.Errorf("%q is not a valid name: %v", got, err)
		}
		if m, ok := isKeyFileName(got); !ok || m != c.mode {
			t.Errorf("%q is read as mode %v (%v), want %v", got, m, ok, c.mode)
		}
		if lower := strings.ToLower(got); lower != got {
			if _, ok := isKeyFileName(lower); ok {
				t.Errorf("%q is a key file name", lower)
			}
		}
	}
	for _, kind := range []FileKind{"", "x", "X509", "pgp"} {
		if got := fileName(ModeTest, "A", kind, ""); got != "" {
			t.Errorf("the kind %q gives the name %q", kind, got)
		}
	}
	if len(cases) != 12 {
		t.Errorf("the table holds %d names", len(cases))
	}
}

func TestEveryLabelAndEveryReasonMakesAValidDistinctName(t *testing.T) {
	seen := map[string]bool{}
	for c := 'A'; c <= 'Z'; c++ {
		for _, m := range []Mode{ModeTest, ModePassphrase} {
			for _, k := range []FileKind{FileX509, FileOpenPGP, FileRemoval} {
				n := fileName(m, string(c), k, "")
				if seen[n] || fsx.CheckName(n) != nil {
					t.Errorf("%q repeats or is invalid", n)
				}
				seen[n] = true
			}
			for _, r := range reasons {
				n := fileName(m, string(c), FileRevocation, r.Text)
				if seen[n] || fsx.CheckName(n) != nil {
					t.Errorf("%q repeats or is invalid", n)
				}
				seen[n] = true
			}
		}
	}
	if len(seen) != 26*2*7 {
		t.Errorf("%d names, want %d", len(seen), 26*2*7)
	}
}

func TestOnlyTheFourReasonsOfThePageAreReasonsAndTheirWordsAreFixed(t *testing.T) {
	var got []string
	for _, r := range reasons {
		got = append(got, fmt.Sprintf("%s:%d", r.Text, r.Code))
	}
	if want := "compromised:2 superseded:1 retired:3 no-reason:0"; strings.Join(got, " ") != want {
		t.Errorf("the reasons are %q, want %q", strings.Join(got, " "), want)
	}
	for _, ok := range []string{"compromised", "superseded", "retired", "no-reason"} {
		if !reasonOK(ok) {
			t.Errorf("%q is refused", ok)
		}
	}
	for _, bad := range []string{"", "Compromised", "no_reason", "noreason", "unknown", "compromised\x00", "retired ", "superseded.asc"} {
		if reasonOK(bad) {
			t.Errorf("%q is accepted", bad)
		}
	}
}

func TestTheFileKindsAndTheLimitsAreTheDocumentedWords(t *testing.T) {
	if FileX509 != "x509" || FileOpenPGP != "openpgp" || FileRevocation != "revocation" || FileRemoval != "removal" {
		t.Error("a kind of file has another word")
	}
	if MaxKeyFileSize != 65536 || maxRevocationSize != 1024 || maxRemovalSize != 4096 || keyFilePerm != 0o600 {
		t.Errorf("limits: %d %d %d %o", MaxKeyFileSize, maxRevocationSize, maxRemovalSize, keyFilePerm)
	}
	if ModeTest == 0 || ModePassphrase == 0 || ModeTest == ModePassphrase {
		t.Error("a Mode is zero or the two are equal: the zero value must be refused")
	}
	if got := (Purpose{Label: "A", File: FileX509}); got.Label != "A" || got.File != "x509" {
		t.Errorf("Purpose: %+v", got)
	}
}

func TestEveryCodeHasOneSentinelAndAnErrorThatWrapsNoneHasNoCode(t *testing.T) {
	want := map[error]string{
		ErrKeyDir: "key-dir", ErrKeyExists: "key-exists", ErrKeyFile: "key-file", ErrWrongMode: "key-file-mode",
		ErrPassphrase: "passphrase", ErrWrongPassphrase: "passphrase-wrong", ErrNotBuilt: "not-built",
	}
	seen := map[string]bool{}
	for err, code := range want {
		if got := Code(err); got != code {
			t.Errorf("Code(%v) is %q, want %q", err, got, code)
		}
		if got := Code(fmt.Errorf("a: %w", fmt.Errorf("b: %w", err))); got != code {
			t.Errorf("a wrapped %q gives %q", code, got)
		}
		if got := Code(errors.Join(errors.New("x"), err)); got != code {
			t.Errorf("a joined %q gives %q", code, got)
		}
		if seen[code] {
			t.Errorf("the code %q is used twice", code)
		}
		seen[code] = true
	}
	if len(codes) != len(want) {
		t.Errorf("the table holds %d codes, the test knows %d", len(codes), len(want))
	}
	for name, err := range map[string]error{"nil": nil, "ErrParams": ErrParams, "wrapped ErrParams": refuse(ErrParams, "x"), "another error": errors.New("software: x"), "errSignature": errSignature} {
		if got := Code(err); got != "" {
			t.Errorf("%s has the code %q", name, got)
		}
	}
	// ErrKeyFile and ErrNotExist together: the code is the one of the sentinel.
	if got := Code(fmt.Errorf("%w: x: %w", ErrKeyFile, errors.New("y"))); got != "key-file" {
		t.Errorf("%q", got)
	}
	// An error that wraps two sentinels is told by the first row of the table, in a fixed order.
	both := errors.Join(ErrWrongMode, ErrKeyFile)
	if first, second := Code(both), Code(errors.Join(ErrKeyFile, ErrWrongMode)); first != second {
		t.Errorf("the code depends on the order of the wrapped errors: %q and %q", first, second)
	}
}

func TestEverySentinelTextIsFixedWordsWithNoPathAndNoPercent(t *testing.T) {
	for _, err := range []error{ErrParams, ErrKeyDir, ErrKeyExists, ErrKeyFile, ErrWrongMode, ErrPassphrase, ErrWrongPassphrase, ErrNotBuilt, errSignature, errLabel} {
		text := err.Error()
		if !strings.HasPrefix(text, "software: ") || strings.ContainsAny(text, "/\\%") {
			t.Errorf("%q", text)
		}
	}
}

func TestAnErrorFromRefuseWrapsItsKindAndSaysWhy(t *testing.T) {
	err := refuse(ErrKeyFile, "the number is %d", 7)
	if !errors.Is(err, ErrKeyFile) || !strings.HasSuffix(err.Error(), ": the number is 7") {
		t.Errorf("%v", err)
	}
}

func TestPlainFormatRefusesAKindOfFileThatDoesNotExist(t *testing.T) {
	for _, kind := range []FileKind{"", "x", "pgp"} {
		if _, err := (plainFormat{}).wrap(kind, []byte("x")); !errors.Is(err, ErrParams) {
			t.Errorf("wrap %q: %v", kind, err)
		}
		if _, err := (plainFormat{}).unwrap(kind, []byte("x")); !errors.Is(err, ErrParams) {
			t.Errorf("unwrap %q: %v", kind, err)
		}
	}
}

func TestPlainFormatWrapThenUnwrapGivesThePayloadForEveryKind(t *testing.T) {
	k := mustGenerate(t)
	cert := certFor(t, k)
	payloads := map[FileKind][]byte{
		FileX509:       pemOf(t, k),
		FileOpenPGP:    secretOf(t, k, cert),
		FileRevocation: revocationFor(t, k, allReasons[0]),
		FileRemoval:    jwsOf("a", "b", "c"),
	}
	for kind, payload := range payloads {
		file, err := (plainFormat{}).wrap(kind, payload)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		back, err := (plainFormat{}).unwrap(kind, file)
		if err != nil || string(back) != string(payload) {
			t.Errorf("%s: %v", kind, err)
		}
		// wrap makes a new slice: changing the payload afterwards does not change the file
		file2 := string(file)
		payload[0] ^= 1
		if string(file) != file2 {
			t.Errorf("%s: the file shares memory with the payload", kind)
		}
		payload[0] ^= 1
	}
}
