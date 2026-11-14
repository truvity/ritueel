package verifier_test

import (
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/verifier"
)

const (
	// certLine is the line on which sqv, with --verbose, names the certificate that made a valid
	// signature: 40 upper-case hexadecimal digits.
	certLine  = "0123456789ABCDEF0123456789ABCDEF01234567\n"
	validText = "Verified 1 signature(s)\n" + certLine + "1 of 1 signatures are valid (threshold is: 1).\n"
	// validNoCert is the text of a valid signature without the line of the certificate.
	validNoCert = "Verified 1 signature(s)\n1 of 1 signatures are valid (threshold is: 1).\n"
)

func TestSQVVerifyAcceptsOnlyAnExitOfZeroAndTheTextOfOneValidSignature(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		stderr string
		exit   int
		ok     bool
	}{
		{"one valid signature on the output", validText, "", 0, true},
		{"one valid signature on the error stream", "", validText, 0, true},
		{"the text and an exit of 1", validText, "", 1, false},
		{"the text without the line of the certificate", validNoCert, "", 0, false},
		{"the line of the certificate with spaces around it", "Verified 1 signature(s)\n   " + certLine + "1 of 1 signatures are valid (threshold is: 1).\n", "", 0, true},
		{"the line of the certificate on the error stream and the text on the output", validNoCert, certLine, 0, true},
		{"the line of another certificate", strings.Replace(validText, "0123456789ABCDEF0123456789ABCDEF01234567", "FEDCBA9876543210FEDCBA9876543210FEDCBA98", 1), "", 0, false},
		{"the lines of the certificate and of another one", validText + "FEDCBA9876543210FEDCBA9876543210FEDCBA98\n", "", 0, false},
		{"the line of the certificate twice", validText + certLine, "", 0, false},
		{"the fingerprint in lower case", "Verified 1 signature(s)\n" + strings.ToLower(certLine) + "1 of 1 signatures are valid (threshold is: 1).\n", "", 0, false},
		{"the fingerprint inside a longer line", "Verified 1 signature(s)\nCertificate 0123456789ABCDEF0123456789ABCDEF01234567 made it\n1 of 1 signatures are valid (threshold is: 1).\n", "", 0, false},
		// A line of 40 characters that is not 40 upper-case digits names no certificate: it is not counted.
		{"another line of 40 characters with a G", validText + "0123456789ABCDEF0123456789ABCDEF0123456G\n", "", 0, true},
		{"another line of 40 characters with an at sign", validText + "0123456789ABCDEF0123456789ABCDEF0123456@\n", "", 0, true},
		{"another line of 40 characters with a slash", validText + "0123456789ABCDEF0123456789ABCDEF0123456/\n", "", 0, true},
		{"another line of 40 characters with a colon", validText + "0123456789ABCDEF0123456789ABCDEF0123456:\n", "", 0, true},
		{"another line of 40 lower-case digits", validText + "fedcba9876543210fedcba9876543210fedcba98\n", "", 0, true},
		{"another line of 41 upper-case digits", validText + "FEDCBA9876543210FEDCBA9876543210FEDCBA980\n", "", 0, true},
		{"another line of 39 upper-case digits", validText + "FEDCBA9876543210FEDCBA9876543210FEDCBA9\n", "", 0, true},
		{"the fingerprint of 39 digits", "Verified 1 signature(s)\n0123456789ABCDEF0123456789ABCDEF0123456\n1 of 1 signatures are valid (threshold is: 1).\n", "", 0, false},
		{"the fingerprint of 41 digits", "Verified 1 signature(s)\n0123456789ABCDEF0123456789ABCDEF012345670\n1 of 1 signatures are valid (threshold is: 1).\n", "", 0, false},
		{"the fingerprint with a letter after F", "Verified 1 signature(s)\n0123456789ABCDEF0123456789ABCDEF0123456G\n1 of 1 signatures are valid (threshold is: 1).\n", "", 0, false},
		{"an exit of 0 and no text", "", "", 0, false},
		{"an exit of 0 and the text of no valid signature", "0 of 1 signatures are valid (threshold is: 1).\n", "", 0, false},
		{"an exit of 0 and the text of one signature of two", "1 of 2 signatures are valid (threshold is: 1).\n", "", 0, false},
		{"an exit of 0 and other words", "Verified 1 signature(s)\nthe signature is good\n", "", 0, false},
		{"the text in other case", strings.ToUpper(validText), "", 0, false},
		{"an exit of 2 and nothing else", "", "", 2, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			(&fakeTool{name: "sqv", stdout: c.stdout, stderr: c.stderr, exit: c.exit}).install(t)
			err := verifier.SQVVerify(t, []byte("ring\n"), []byte("sig\n"), []byte("data\n"), wantFP, time.Unix(1794744000, 0))
			if c.ok && err != nil {
				t.Errorf("SQVVerify = %v, want nil", err)
			}
			if !c.ok && err == nil {
				t.Error("SQVVerify = nil, want an error")
			}
		})
	}
}

func TestSQVVerifyRunsSqvAtTheTimeGivenOnFilesOfTheTestWithASmallEnvironment(t *testing.T) {
	t.Setenv("RITUEEL_CANARY", "leaked")
	f := &fakeTool{name: "sqv", stdout: validText}
	f.install(t)
	// 2026-11-15 12:00:00 UTC, given in another zone: sqv is told the instant in UTC.
	at := time.Date(2026, 11, 15, 21, 0, 0, 0, time.FixedZone("UTC+9", 9*3600))
	if err := verifier.SQVVerify(t, []byte("the keyring\n"), []byte("the signature\n"), []byte("the data\n"), wantFP, at); err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(f.read(t, "args")), "\n")
	if len(args) != 8 || args[0] != "--time" || args[1] != "2026-11-15T12:00:00Z" || args[2] != "--verbose" ||
		args[3] != "--keyring" || args[5] != "--signature-file" {
		t.Fatalf("arguments %q, want --time T --verbose --keyring K --signature-file S DATA", args)
	}
	if !strings.HasSuffix(args[4], "keyring.pgp") || !strings.HasSuffix(args[6], "message.sig") || !strings.HasSuffix(args[7], "message") {
		t.Errorf("the files are %q %q %q", args[4], args[6], args[7])
	}
	for name, want := range map[string]string{"file-keyring.pgp": "the keyring\n", "file-message.sig": "the signature\n", "file-message": "the data\n"} {
		if got := f.read(t, name); got != want {
			t.Errorf("%s holds %q, want %q", name, got, want)
		}
	}
	env := f.read(t, "env")
	if !strings.Contains(env, "CANARY=unset") || !strings.Contains(env, "LC_ALL=C") || !strings.Contains(env, "TZ=UTC") {
		t.Errorf("the environment of sqv is not the small one:\n%s", env)
	}
	home := ""
	for _, l := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(l, "HOME="); ok {
			home = v
		}
	}
	if home == "" || home == os.Getenv("HOME") || !strings.HasPrefix(home, os.TempDir()) {
		t.Errorf("sqv runs with the home %q, want a folder of the test", home)
	}
	// The machine's policy does not decide: sqv is pointed at a policy file of the test.
	if strings.Contains(env, "POLICY=unset") || !strings.Contains(env, "POLICY=/") {
		t.Errorf("sqv is not given its own policy file:\n%s", env)
	}
}

func TestSQVVerifyShowsWhatSqvPrintedWithEveryOddCharacterEscaped(t *testing.T) {
	(&fakeTool{name: "sqv", stdout: "Missing key \x1b[31m\u202e\n", stderr: "bad \xff\n", exit: 1}).install(t)
	err := verifier.SQVVerify(t, []byte("r\n"), []byte("s\n"), []byte("d\n"), wantFP, time.Unix(1794744000, 0))
	if err == nil {
		t.Fatal("no error")
	}
	for i := 0; i < len(err.Error()); i++ {
		if c := err.Error()[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("the error holds the byte %#x: %q", c, err.Error())
		}
	}
	if !strings.Contains(err.Error(), "Missing key") {
		t.Errorf("the error does not show the output: %v", err)
	}
}

// A fingerprint that is not 40 lower-case hexadecimal digits is refused before the tool is run.
func TestSQVVerifyRefusesAFingerprintOfTheWrongFormBeforeRunningSqv(t *testing.T) {
	for _, c := range badFingerprints {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeTool{name: "sqv", stdout: validText}
			f.install(t)
			err := verifier.SQVVerify(t, []byte("ring\n"), []byte("sig\n"), []byte("data\n"), c.fp, time.Unix(1794744000, 0))
			if err == nil || !strings.Contains(err.Error(), "40 lower-case hexadecimal digits") {
				t.Fatalf("SQVVerify = %v, want an error about the fingerprint", err)
			}
			if !printable(err.Error()) {
				t.Errorf("the error holds a byte that is not printable ASCII: %q", err.Error())
			}
			if _, statErr := os.Stat(f.capture + "/args"); statErr == nil {
				t.Error("sqv was run")
			}
		})
	}
}

func TestSQVVerifyNeedsSqv(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv(verifier.RequireToolsEnv, "")
	fake := runFake(t, func(tb testing.TB) { _ = verifier.SQVVerify(tb, nil, nil, nil, wantFP, time.Now()) })
	if !fake.skipped || fake.failed || !strings.Contains(fake.message, "sqv") {
		t.Errorf("skipped = %v, failed = %v: %s", fake.skipped, fake.failed, fake.message)
	}
	t.Setenv(verifier.RequireToolsEnv, "1")
	fake = runFake(t, func(tb testing.TB) { _ = verifier.SQVVerify(tb, nil, nil, nil, wantFP, time.Now()) })
	if !fake.failed || fake.skipped {
		t.Errorf("skipped = %v, failed = %v, want a failure", fake.skipped, fake.failed)
	}
}

// The real sqv, with a key that go-crypto made.

func TestSQVVerifyAcceptsAGoodSignatureAtATimeWhenTheKeyLivesAndRefusesItBefore(t *testing.T) {
	verifier.Require(t, "sqv")
	now := nowSecond()
	e := entity(t, now.Add(-72*time.Hour))
	ring := publicOf(t, e)
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.SQVVerify(t, ring, sig, pgpMessage, fingerprintOf(e), now); err != nil {
		t.Fatalf("SQVVerify = %v", err)
	}
	// The time given reaches sqv: before the key existed the same signature is refused.
	if err := verifier.SQVVerify(t, ring, sig, pgpMessage, fingerprintOf(e), now.Add(-96*time.Hour)); err == nil {
		t.Error("SQVVerify accepts a signature at a time before the key was created")
	}
}

func TestSQVVerifyRefusesAChangedMessageAnUnrelatedKeyAndARevokedKey(t *testing.T) {
	verifier.Require(t, "sqv")
	now := nowSecond()
	e := entity(t, now.Add(-72*time.Hour))
	other := entity(t, now.Add(-72*time.Hour))
	ring := publicOf(t, e)
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.SQVVerify(t, ring, sig, pgpMessage, fingerprintOf(e), now); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	if err := verifier.SQVVerify(t, ring, sig, append([]byte("x"), pgpMessage...), fingerprintOf(e), now); err == nil {
		t.Error("SQVVerify accepts a changed message")
	}
	if err := verifier.SQVVerify(t, publicOf(t, other), sig, pgpMessage, fingerprintOf(e), now); err == nil {
		t.Error("SQVVerify accepts an unrelated key")
	}
	if err := verifier.SQVVerify(t, nil, sig, pgpMessage, fingerprintOf(e), now); err == nil {
		t.Error("SQVVerify accepts an empty keyring")
	}
	if err := e.RevokeKey(packet.KeyCompromised, "compromised", pgpConfig(now.Add(-30*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := verifier.SQVVerify(t, publicOf(t, e), sig, pgpMessage, fingerprintOf(e), now); err == nil {
		t.Error("SQVVerify accepts a signature by a key with a compromised revocation")
	}
	if err := verifier.SQVVerify(t, ring, []byte("not a signature"), pgpMessage, fingerprintOf(e), now); err == nil {
		t.Error("SQVVerify accepts bytes that are not a signature")
	}
}

// The machine holds real cards and key daemons: the helpers of this package name no tool but gpgv and
// sqv, and never gpg itself.
func TestTheHelpersNameNoToolButGpgvAndSqv(t *testing.T) {
	re := regexp.MustCompile(`Require\(t, "([^"]*)"\)`)
	for file, want := range map[string]string{"gpg.go": "gpgv", "sqv.go": "sqv"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		found := re.FindAllStringSubmatch(string(src), -1)
		if len(found) == 0 {
			t.Fatalf("%s names no tool at all", file)
		}
		for _, m := range found {
			if m[1] != want {
				t.Errorf("%s asks for the tool %q, want only %q", file, m[1], want)
			}
		}
		for _, bad := range []string{`"gpg"`, `"gpgconf"`, `"scdaemon"`, `"ykman"`} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s names %s", file, bad)
			}
		}
	}
}

// A keyring of two certificates: the signature of the second passes only with the fingerprint of the
// second, and is refused with the fingerprint of the first.
func TestSQVVerifyTakesTheSignatureOfACertificateOfTheKeyringOnlyForThatCertificate(t *testing.T) {
	verifier.Require(t, "sqv")
	now := nowSecond()
	a := entity(t, now.Add(-72*time.Hour))
	b := entity(t, now.Add(-72*time.Hour))
	ring := append(publicOf(t, a), publicOf(t, b)...)
	sigA := detach(t, a, pgpMessage, now.Add(-time.Hour))
	sigB := detach(t, b, pgpMessage, now.Add(-time.Hour))
	for _, c := range []struct {
		name string
		sig  []byte
		fp   string
		ok   bool
	}{
		{"the first by the first", sigA, fingerprintOf(a), true},
		{"the second by the second", sigB, fingerprintOf(b), true},
		{"the second by the first", sigB, fingerprintOf(a), false},
		{"the first by the second", sigA, fingerprintOf(b), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := verifier.SQVVerify(t, ring, c.sig, pgpMessage, c.fp, now)
			if c.ok && err != nil {
				t.Fatalf("SQVVerify = %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "one certificate that made the signature")) {
				t.Fatalf("SQVVerify = %v, want an error that says which certificate made it", err)
			}
		})
	}
}

// The certificate is named by its primary: a signature by a subkey passes with the fingerprint of
// the primary, and not with the fingerprint of the subkey.
func TestSQVVerifyWantsTheFingerprintOfThePrimaryAndNotOfTheKeyThatSigned(t *testing.T) {
	verifier.Require(t, "sqv")
	now := nowSecond()
	e := signingSubkeyEntity(t, now.Add(-72*time.Hour))
	ring := publicOf(t, e)
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.SQVVerify(t, ring, sig, pgpMessage, fingerprintOf(e), now); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	sub := hex.EncodeToString(e.Subkeys[len(e.Subkeys)-1].PublicKey.Fingerprint)
	if err := verifier.SQVVerify(t, ring, sig, pgpMessage, sub, now); err == nil {
		t.Error("SQVVerify takes the fingerprint of the subkey that signed for the fingerprint of the certificate")
	}
}
