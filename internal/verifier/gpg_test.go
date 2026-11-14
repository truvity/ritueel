package verifier_test

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/verifier"
)

const (
	// wantFP is the fingerprint of the certificate that the canned output is about; gpgv writes it
	// in upper case.
	wantFP    = "0123456789abcdef0123456789abcdef01234567"
	otherFP   = "fedcba9876543210fedcba9876543210fedcba98"
	goodLine  = "[GNUPG:] GOODSIG 0123456789ABCDEF Example Test <release@example.org>\n"
	validLine = "[GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567 2026-11-14 1794665337 0 4 0 19 9 00 0123456789ABCDEF0123456789ABCDEF01234567\n"
	// validSub is a signature by a subkey: its own fingerprint first, the primary last.
	validSub = "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-11-14 1794665337 0 4 0 19 9 00 0123456789ABCDEF0123456789ABCDEF01234567\n"
	// validShort is the line of gpgv when it names no primary: ten fields, the first is the primary.
	validShort = "[GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567 2026-11-14 1794665337 0 4 0 19 9 00\n"
)

var statusCases = []struct {
	name   string
	stdout string
	stderr string
	exit   int
	ok     bool
	reason string // a word the error holds
}{
	{"a good signature with a good exit", "[GNUPG:] NEWSIG\n" + goodLine + validLine, "", 0, true, ""},
	{"a good signature by a subkey of the certificate that is meant", goodLine + validSub, "", 0, true, ""},
	{"a good signature whose line names no primary, the signing key is the one meant", goodLine + validShort, "", 0, true, ""},
	{"a good signature by a key of another certificate", goodLine + strings.ReplaceAll(validSub, "0123456789ABCDEF0123456789ABCDEF01234567\n", "FEDCBA9876543210FEDCBA9876543210FEDCBA98\n"), "", 0, false, "another certificate"},
	{"a good signature by another primary", goodLine + strings.ReplaceAll(validLine, "0123456789ABCDEF0123456789ABCDEF01234567", "FEDCBA9876543210FEDCBA9876543210FEDCBA98"), "", 0, false, "another certificate"},
	{"a signature by a subkey whose own fingerprint is the one meant but whose primary is another", goodLine + "[GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567 2026-11-14 1794665337 0 4 0 19 9 00 FEDCBA9876543210FEDCBA9876543210FEDCBA98\n", "", 0, false, "another certificate"},
	{"a short line whose signing key is another", goodLine + strings.ReplaceAll(validShort, "0123456789ABCDEF0123456789ABCDEF01234567", "FEDCBA9876543210FEDCBA9876543210FEDCBA98"), "", 0, false, "another certificate"},
	{"two VALIDSIG lines, both of the certificate", goodLine + validLine + validSub, "", 0, false, "another certificate"},
	{"two VALIDSIG lines, the second of another certificate", goodLine + validLine + strings.ReplaceAll(validLine, "0123456789ABCDEF0123456789ABCDEF01234567", "FEDCBA9876543210FEDCBA9876543210FEDCBA98"), "", 0, false, "another certificate"},
	{"a VALIDSIG line with a field too many", goodLine + strings.TrimSuffix(validLine, "\n") + " 00\n", "", 0, false, "another certificate"},
	{"a VALIDSIG line with a fingerprint and nothing else", goodLine + "[GNUPG:] VALIDSIG 0123456789ABCDEF0123456789ABCDEF01234567\n", "", 0, false, "another certificate"},
	{"a VALIDSIG line with no fingerprint", goodLine + "[GNUPG:] VALIDSIG\n", "", 0, false, "another certificate"},
	{"a VALIDSIG line in lower case", goodLine + strings.ToLower(validLine), "", 0, false, "GOODSIG and VALIDSIG"},
	{"a good signature whose name holds the word BADSIG", "[GNUPG:] GOODSIG 0123456789ABCDEF BADSIG ERRSIG <a@example.org>\n" + validLine, "", 0, true, ""},
	{"GOODSIG without VALIDSIG", goodLine, "", 0, false, "GOODSIG and VALIDSIG"},
	{"VALIDSIG without GOODSIG", validLine, "", 0, false, "GOODSIG and VALIDSIG"},
	{"no status at all", "", "", 0, false, "GOODSIG and VALIDSIG"},
	{"a good signature and an exit of 1", goodLine + validLine, "", 1, false, "exit status 1"},
	{"a good signature and an exit of 2", goodLine + validLine, "", 2, false, "exit status 2"},
	{"a good signature, REVKEYSIG too, exit 0", goodLine + validLine + "[GNUPG:] REVKEYSIG 0123456789ABCDEF name\n", "", 0, false, "REVKEYSIG"},
	{"a good signature, EXPKEYSIG too, exit 0", goodLine + validLine + "[GNUPG:] EXPKEYSIG 0123456789ABCDEF name\n", "", 0, false, "EXPKEYSIG"},
	{"a good signature, EXPSIG too, exit 0", goodLine + validLine + "[GNUPG:] EXPSIG 0123456789ABCDEF name\n", "", 0, false, "EXPSIG"},
	{"a good signature, BADSIG too, exit 0", goodLine + validLine + "[GNUPG:] BADSIG 0123456789ABCDEF name\n", "", 0, false, "BADSIG"},
	{"a good signature, ERRSIG too, exit 0", goodLine + validLine + "[GNUPG:] ERRSIG 0123456789ABCDEF 19 9 00 1 9 FPR\n", "", 0, false, "ERRSIG"},
	{"a good signature, NO_PUBKEY too, exit 0", goodLine + validLine + "[GNUPG:] NO_PUBKEY 0123456789ABCDEF\n", "", 0, false, "NO_PUBKEY"},
	{"a good signature, ERROR too, exit 0", goodLine + validLine + "[GNUPG:] ERROR check_sig 9\n", "", 0, false, "ERROR"},
	{"a bad word first and the good lines after", "[GNUPG:] BADSIG 0123456789ABCDEF name\n" + goodLine + validLine, "", 0, false, "BADSIG"},
	{"a bad word on a line with no text after it", goodLine + validLine + "[GNUPG:] ERROR\n", "", 0, false, "ERROR"},
	{"the good lines on the error stream only", "", goodLine + validLine, 0, false, "GOODSIG and VALIDSIG"},
	{"the good lines without the prefix", strings.ReplaceAll(goodLine+validLine, "[GNUPG:] ", ""), "", 0, false, "GOODSIG and VALIDSIG"},
	{"the good lines with the prefix not at the start", " " + goodLine + " " + validLine, "", 0, false, "GOODSIG and VALIDSIG"},
	{"the good words in lower case", strings.ToLower(goodLine + validLine), "", 0, false, "GOODSIG and VALIDSIG"},
	{"words that only start like the good ones", "[GNUPG:] GOODSIGX 01\n[GNUPG:] VALIDSIGX 01\n", "", 0, false, "GOODSIG and VALIDSIG"},
	{"the prefix without a space before the word", "[GNUPG:]GOODSIG 01\n[GNUPG:]VALIDSIG 01\n", "", 0, false, "GOODSIG and VALIDSIG"},
}

func TestGPGVVerifyReadsTheVerdictFromTheStatusLinesAndTheExit(t *testing.T) {
	for _, c := range statusCases {
		t.Run(c.name, func(t *testing.T) {
			(&fakeTool{name: "gpgv", stdout: c.stdout, stderr: c.stderr, exit: c.exit}).install(t)
			err := verifier.GPGVVerify(t, []byte("ring\n"), []byte("sig\n"), []byte("data\n"), wantFP)
			switch {
			case c.ok && err != nil:
				t.Errorf("GPGVVerify = %v, want nil", err)
			case !c.ok && err == nil:
				t.Errorf("GPGVVerify = nil, want an error")
			case !c.ok && c.reason != "" && !strings.Contains(err.Error(), c.reason):
				t.Errorf("GPGVVerify = %v, want an error that holds %q", err, c.reason)
			}
		})
	}
}

func TestGPGVStatusReturnsTheStatusLinesWithoutThePrefixAndTheExitApart(t *testing.T) {
	out := "gpgv: some text\n[GNUPG:] NEWSIG\n[GNUPG:] REVKEYSIG 0123456789ABCDEF name\n\n[GNUPG:] VALIDSIG 0123\nnot status\n"
	(&fakeTool{name: "gpgv", stdout: out, stderr: "[GNUPG:] GOODSIG 01 from the error stream\n", exit: 0}).install(t)
	status, exit := verifier.GPGVStatus(t, []byte("ring\n"), []byte("sig\n"), []byte("data\n"))
	want := []string{"NEWSIG", "REVKEYSIG 0123456789ABCDEF name", "VALIDSIG 0123"}
	if strings.Join(status, "|") != strings.Join(want, "|") {
		t.Errorf("status = %q, want %q", status, want)
	}
	if exit != nil {
		t.Errorf("exit = %v, want nil for an exit of 0", exit)
	}
	(&fakeTool{name: "gpgv", stdout: out, exit: 2}).install(t)
	_, exit = verifier.GPGVStatus(t, []byte("ring\n"), []byte("sig\n"), []byte("data\n"))
	if exit == nil || !strings.Contains(exit.Error(), "exit status 2") {
		t.Errorf("exit = %v, want the error of an exit of 2", exit)
	}
}

func TestGPGVVerifyRunsGpgvOnFilesOfTheTestWithASmallEnvironment(t *testing.T) {
	t.Setenv("RITUEEL_CANARY", "leaked")
	f := &fakeTool{name: "gpgv", stdout: goodLine + validLine}
	f.install(t)
	if err := verifier.GPGVVerify(t, []byte("the keyring\n"), []byte("the signature\n"), []byte("the data\n"), wantFP); err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(f.read(t, "args")), "\n")
	if len(args) != 6 || args[0] != "--status-fd" || args[1] != "1" || args[2] != "--keyring" {
		t.Fatalf("arguments %q, want --status-fd 1 --keyring KEYRING SIG DATA", args)
	}
	if got := f.read(t, "file-keyring.pgp"); got != "the keyring\n" {
		t.Errorf("the keyring file holds %q", got)
	}
	if got := f.read(t, "file-message.sig"); got != "the signature\n" {
		t.Errorf("the signature file holds %q", got)
	}
	if got := f.read(t, "file-message"); got != "the data\n" {
		t.Errorf("the data file holds %q", got)
	}
	if args[4] == args[5] || !strings.HasSuffix(args[4], "message.sig") || !strings.HasSuffix(args[5], "message") || !strings.HasSuffix(args[3], "keyring.pgp") {
		t.Errorf("the keyring, the signature and the data are %q, %q and %q", args[3], args[4], args[5])
	}
	env := f.read(t, "env")
	for _, want := range []string{"LC_ALL=C", "TZ=UTC", "CANARY=unset"} {
		if !strings.Contains(env, want) {
			t.Errorf("the environment of gpgv lacks %q:\n%s", want, env)
		}
	}
	home := ""
	for _, l := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(l, "HOME="); ok {
			home = v
		}
	}
	if home == "" || home == os.Getenv("HOME") || !strings.HasPrefix(home, os.TempDir()) {
		t.Errorf("gpgv runs with the home %q, want a folder of the test", home)
	}
	if !strings.Contains(env, "GNUPGHOME="+home) {
		t.Errorf("GNUPGHOME is not the home of the test:\n%s", env)
	}
}

// What gpgv printed is shown in the error, with every character that is not printable ASCII escaped.
func TestGPGVVerifyEscapesWhatGpgvPrinted(t *testing.T) {
	(&fakeTool{name: "gpgv", stdout: "[GNUPG:] BADSIG 01 name \x1b[31m\u202e\n", stderr: "bad \xff\n", exit: 1}).install(t)
	err := verifier.GPGVVerify(t, []byte("r\n"), []byte("s\n"), []byte("d\n"), wantFP)
	if err == nil {
		t.Fatal("no error")
	}
	for i := 0; i < len(err.Error()); i++ {
		if c := err.Error()[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("the error holds the byte %#x: %q", c, err.Error())
		}
	}
	if !strings.Contains(err.Error(), "BADSIG") {
		t.Errorf("the error does not show the output: %v", err)
	}
}

// A fingerprint that is not 40 lower-case hexadecimal digits is refused before the tool is run.
func TestGPGVVerifyRefusesAFingerprintOfTheWrongFormBeforeRunningGpgv(t *testing.T) {
	for _, c := range badFingerprints {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeTool{name: "gpgv", stdout: goodLine + validLine}
			f.install(t)
			err := verifier.GPGVVerify(t, []byte("ring\n"), []byte("sig\n"), []byte("data\n"), c.fp)
			if err == nil || !strings.Contains(err.Error(), "40 lower-case hexadecimal digits") {
				t.Fatalf("GPGVVerify = %v, want an error about the fingerprint", err)
			}
			if !printable(err.Error()) {
				t.Errorf("the error holds a byte that is not printable ASCII: %q", err.Error())
			}
			if _, statErr := os.Stat(f.capture + "/args"); statErr == nil {
				t.Error("gpgv was run")
			}
		})
	}
}

func TestGPGVVerifyNeedsGpgv(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv(verifier.RequireToolsEnv, "")
	fake := runFake(t, func(tb testing.TB) { _ = verifier.GPGVVerify(tb, nil, nil, nil, wantFP) })
	if !fake.skipped || fake.failed || !strings.Contains(fake.message, "gpgv") {
		t.Errorf("skipped = %v, failed = %v: %s", fake.skipped, fake.failed, fake.message)
	}
	t.Setenv(verifier.RequireToolsEnv, "1")
	fake = runFake(t, func(tb testing.TB) { _, _ = verifier.GPGVStatus(tb, nil, nil, nil) })
	if !fake.failed || fake.skipped {
		t.Errorf("skipped = %v, failed = %v, want a failure", fake.skipped, fake.failed)
	}
}

// badFingerprints are the texts that no helper takes for the fingerprint of a version 4 key.
var badFingerprints = []struct{ name, fp string }{
	{"empty", ""},
	{"39 digits", wantFP[:39]},
	{"41 digits", wantFP + "0"},
	{"upper case", strings.ToUpper(wantFP)},
	{"one upper-case digit", wantFP[:39] + "A"},
	{"a letter after f", wantFP[:39] + "g"},
	{"a slash, the sign before 0", wantFP[:39] + "/"},
	{"a colon, the sign after 9", wantFP[:39] + ":"},
	{"a backtick, the sign before a", wantFP[:39] + "`"},
	{"an upper-case G", wantFP[:39] + "G"},
	{"an at sign, the sign before A", wantFP[:39] + "@"},
	{"a space inside", wantFP[:20] + " " + wantFP[21:]},
	{"a prefix of 0x", "0x" + wantFP[:38]},
	{"a line feed at the end", wantFP[:39] + "\n"},
	{"a control character and a non-ASCII byte", wantFP[:36] + "\x1b\u202e"},
	{"the 40 digits twice", wantFP + wantFP},
}

// The real gpgv, with a key that go-crypto made.

func requireGPGV(t *testing.T) { t.Helper(); verifier.Require(t, "gpgv") }

func TestGPGVVerifyAcceptsAGoodSignatureByAKeyOfTheKeyring(t *testing.T) {
	requireGPGV(t)
	now := nowSecond()
	e := entity(t, now.Add(-72*time.Hour))
	ring := publicOf(t, e)
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.GPGVVerify(t, ring, sig, pgpMessage, fingerprintOf(e)); err != nil {
		t.Fatalf("GPGVVerify = %v", err)
	}
	status, exit := verifier.GPGVStatus(t, ring, sig, pgpMessage)
	if exit != nil || !statusHas(status, "GOODSIG") || !statusHas(status, "VALIDSIG") {
		t.Errorf("status %q, exit %v, want GOODSIG and VALIDSIG and an exit of 0", status, exit)
	}
}

func TestGPGVVerifyRefusesAChangedMessageAnUnrelatedKeyAndNoKeyring(t *testing.T) {
	requireGPGV(t)
	now := nowSecond()
	e := entity(t, now.Add(-72*time.Hour))
	other := entity(t, now.Add(-72*time.Hour))
	ring := publicOf(t, e)
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.GPGVVerify(t, ring, sig, pgpMessage, fingerprintOf(e)); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	cases := []struct {
		name          string
		ring, sig, in []byte
		word          string
	}{
		{"a changed message", ring, sig, append([]byte("x"), pgpMessage...), "BADSIG"},
		{"an unrelated key", publicOf(t, other), sig, pgpMessage, "NO_PUBKEY"},
		{"an empty keyring", nil, sig, pgpMessage, ""},
		{"a signature that is not one", ring, []byte("not a signature"), pgpMessage, ""},
		{"an empty signature", ring, nil, pgpMessage, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifier.GPGVVerify(t, c.ring, c.sig, c.in, fingerprintOf(e))
			if err == nil {
				t.Fatal("GPGVVerify accepts it")
			}
			if c.word != "" && !strings.Contains(err.Error(), c.word) {
				t.Errorf("the error %v does not name %s", err, c.word)
			}
		})
	}
}

// gpgv exits 0 for a signature by a revoked key. The helper does not take that for an acceptance.
func TestGPGVVerifyRefusesARevokedKeyWhateverTheExitStatusIs(t *testing.T) {
	requireGPGV(t)
	now := nowSecond()
	e := entity(t, now.Add(-72*time.Hour))
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.GPGVVerify(t, publicOf(t, e), sig, pgpMessage, fingerprintOf(e)); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	if err := e.RevokeKey(packet.KeyCompromised, "compromised", pgpConfig(now.Add(-30*time.Minute))); err != nil {
		t.Fatal(err)
	}
	ring := publicOf(t, e)
	status, exit := verifier.GPGVStatus(t, ring, sig, pgpMessage)
	if !statusHas(status, "REVKEYSIG") {
		t.Fatalf("status %q, want REVKEYSIG", status)
	}
	if exit != nil {
		t.Logf("gpgv exits with %v for a revoked key on this version", exit)
	}
	err := verifier.GPGVVerify(t, ring, sig, pgpMessage, fingerprintOf(e))
	if err == nil || !strings.Contains(err.Error(), "REVKEYSIG") {
		t.Errorf("GPGVVerify = %v, want an error that names REVKEYSIG", err)
	}
}

func TestGPGVVerifyRefusesAnExpiredKey(t *testing.T) {
	requireGPGV(t)
	now := nowSecond()
	cfg := pgpConfig(now.Add(-72 * time.Hour))
	cfg.KeyLifetimeSecs = 24 * 3600 // ended 48 hours ago
	e, err := pgp.NewEntity("Example Test", "", "release@example.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	sig := detach(t, e, pgpMessage, now.Add(-60*time.Hour))
	err = verifier.GPGVVerify(t, publicOf(t, e), sig, pgpMessage, fingerprintOf(e))
	if err == nil {
		t.Fatal("GPGVVerify accepts a signature by a key that expired")
	}
	if !strings.Contains(err.Error(), "EXPKEYSIG") {
		t.Logf("refused for another word: %v", err)
	}
}

func statusHas(status []string, word string) bool {
	for _, l := range status {
		if w, _, _ := strings.Cut(l, " "); w == word {
			return true
		}
	}
	return false
}

// A keyring of two certificates: the signature of the second passes only with the fingerprint of the
// second, and is refused with the fingerprint of the first.
func TestGPGVVerifyTakesTheSignatureOfACertificateOfTheKeyringOnlyForThatCertificate(t *testing.T) {
	requireGPGV(t)
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
			err := verifier.GPGVVerify(t, ring, c.sig, pgpMessage, c.fp)
			if c.ok && err != nil {
				t.Fatalf("GPGVVerify = %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "another certificate")) {
				t.Fatalf("GPGVVerify = %v, want an error that says the key is of another certificate", err)
			}
		})
	}
}

// The fingerprint of a key that is not the primary is not the fingerprint of the certificate: gpgv
// names the primary last, and that is the one that is compared.
func TestGPGVVerifyWantsTheFingerprintOfThePrimaryAndNotOfTheKeyThatSigned(t *testing.T) {
	requireGPGV(t)
	now := nowSecond()
	e := signingSubkeyEntity(t, now.Add(-72*time.Hour))
	ring := publicOf(t, e)
	sig := detach(t, e, pgpMessage, now.Add(-time.Hour))
	if err := verifier.GPGVVerify(t, ring, sig, pgpMessage, fingerprintOf(e)); err != nil {
		t.Fatalf("the control does not start from an acceptance: %v", err)
	}
	sub := hex.EncodeToString(e.Subkeys[len(e.Subkeys)-1].PublicKey.Fingerprint)
	if err := verifier.GPGVVerify(t, ring, sig, pgpMessage, sub); err == nil {
		t.Error("GPGVVerify takes the fingerprint of the subkey that signed for the fingerprint of the certificate")
	}
}
