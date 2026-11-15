package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
	"ritueel.id/ritueel/internal/wanted"
)

// The seams of Primaries and Checker that a test in the package drives: the files that one run reads (a recording
// file system), the text of an error of the keyring file, and the entries of a root list.

// recFS records the reads of a folder: every ReadDir and every ReadFile, with the path from the root of the bundle.
type recFS struct {
	inner fsx.FS
	at    string
	log   *[]string
}

func (r *recFS) OpenDir(name string) (fsx.FS, error) {
	child, err := r.inner.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &recFS{inner: child, at: r.at + name + "/", log: r.log}, nil
}
func (r *recFS) Mkdir(name string, perm fs.FileMode) error { return r.inner.Mkdir(name, perm) }
func (r *recFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	return r.inner.CreateExcl(name, perm)
}
func (r *recFS) RenameNoReplace(a, b string) error { return r.inner.RenameNoReplace(a, b) }
func (r *recFS) Sync() error                       { return r.inner.Sync() }
func (r *recFS) ReadFile(name string) ([]byte, error) {
	*r.log = append(*r.log, "ReadFile "+r.at+name)
	return r.inner.ReadFile(name)
}
func (r *recFS) ReadDir() ([]fs.DirEntry, error) {
	*r.log = append(*r.log, "ReadDir "+r.at)
	return r.inner.ReadDir()
}
func (r *recFS) Close() error { return r.inner.Close() }

func vec(t testing.TB, rel ...string) []byte {
	t.Helper()
	return testrepo.Read(t, append([]string{"testdata"}, rel...)...)
}

// writeRecBundle writes a bundle folder: the settings, one root and one delegation of each type, and a trust set
// 7-3fa9c1d2 of the vectors with the keyring file as given (nil: none) and the list as given (nil: the list of the
// vectors). It returns the bundle, whose reads are recorded, and the record.
func writeRecBundle(t testing.TB, list, keyring []byte) (*Bundle, *[]string) {
	t.Helper()
	dir := t.TempDir()
	put := func(rel string, data []byte) {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if list == nil {
		list = vec(t, "root-list", "v1", "lists", "seq7-a.json")
	}
	put("ritueel.yaml", []byte("version: 1\nname: Example\nrelease_address: release@example.org\npolicy:\n  stores: [software]\n  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: 13\n"))
	put("want/roots/x.yaml", []byte("version: 1\nkind: x509\ntest: true\n"))
	put("want/roots/p.yaml", []byte("version: 1\nkind: openpgp\ntest: true\n"))
	put("want/roots/s.yaml", []byte("version: 1\nkind: ssh\ntest: true\n"))
	put("want/delegations/x509d.yaml", []byte("version: 1\ntype: x509-intermediate\nroot: x\npermitted_uri_hosts: [example.org]\n"))
	put("want/delegations/pgpd.yaml", []byte("version: 1\ntype: openpgp-subkey\nroot: p\ncapability: sign\n"))
	put("want/delegations/sshd.yaml", []byte("version: 1\ntype: ssh-ca-key\nroot: s\nuse: user\n"))
	put("trust/7-3fa9c1d2/root-list.json", list)
	put("trust/7-3fa9c1d2/ca-bundle.pem", vec(t, "root-list", "v1", "bundles", "ca-bundle-7.pem"))
	if keyring != nil {
		put("trust/7-3fa9c1d2/keyring.gpg", keyring)
	}
	real, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := wanted.LoadSettings(real)
	if err != nil {
		_ = real.Close()
		t.Fatal(err)
	}
	var log []string
	b := &Bundle{fsys: &recFS{inner: real, log: &log}, settings: s}
	t.Cleanup(func() { _ = b.Close() })
	return b, &log
}

func goodKeyring(t testing.TB) []byte {
	t.Helper()
	return append(vec(t, "root-list", "v1", "pki", "test-primary-a.pgp"), vec(t, "root-list", "v1", "pki", "test-primary-b.pgp")...)
}

func countOf(log []string, entry string) int {
	n := 0
	for _, l := range log {
		if l == entry {
			n++
		}
	}
	return n
}

const (
	readTrust   = "ReadDir trust/"
	readList    = "ReadFile trust/7-3fa9c1d2/root-list.json"
	readCA      = "ReadFile trust/7-3fa9c1d2/ca-bundle.pem"
	readKeyring = "ReadFile trust/7-3fa9c1d2/keyring.gpg"
)

// noFingerprints is the list of the vectors with the members openpgp_fingerprint cut as text.
func noFingerprints(t testing.TB) []byte {
	t.Helper()
	list := string(vec(t, "root-list", "v1", "lists", "seq7-a.json"))
	list = strings.ReplaceAll(list, `"openpgp_fingerprint":"6df387de63525c9dc0ec1174bd138d2c4889b79b",`, "")
	list = strings.ReplaceAll(list, `"openpgp_fingerprint":"c4288657012230588b51fa66e0831b9c6e084f39",`, "")
	if strings.Contains(list, "openpgp_fingerprint") {
		t.Fatal("the fingerprints were not cut")
	}
	return []byte(list)
}

// The newest set is read once for a checker: one listing of trust/, one read of the list and one of the CA bundle,
// and one read of the keyring file when the checker is given the primaries and none when it is not.
func TestOneRunReadsTheNewestSetOnceAndTheKeyringFileOnlyWhenItGivesPrimaries(t *testing.T) {
	type counts struct{ trust, list, ca, keyring int }
	for _, tc := range []struct {
		name    string
		list    []byte
		keyring []byte
		run     func(b *Bundle) error
		want    counts
	}{
		{"Roots", nil, goodKeyring(t), func(b *Bundle) error { _, _, err := b.Roots(); return err }, counts{1, 1, 1, 0}},
		{"Primaries", nil, goodKeyring(t), func(b *Bundle) error { _, _, err := b.Primaries(); return err }, counts{1, 1, 1, 1}},
		{"Checker with no delegation", nil, goodKeyring(t), func(b *Bundle) error { _, _, err := b.Checker("", time0, nil); return err }, counts{1, 1, 1, 1}},
		{"Checker with an openpgp-subkey delegation", nil, goodKeyring(t), func(b *Bundle) error { _, _, err := b.Checker("pgpd", time0, nil); return err }, counts{1, 1, 1, 1}},
		{"Checker with an x509-intermediate delegation", nil, goodKeyring(t), func(b *Bundle) error { _, _, err := b.Checker("x509d", time0, nil); return err }, counts{1, 1, 1, 0}},
		{"Checker with an ssh-ca-key delegation", nil, goodKeyring(t), func(b *Bundle) error { _, _, err := b.Checker("sshd", time0, nil); return err }, counts{1, 1, 1, 0}},
		{"Checker, a bad keyring and an x509 delegation", nil, []byte("garbage"), func(b *Bundle) error { _, _, err := b.Checker("x509d", time0, nil); return err }, counts{1, 1, 1, 0}},
		{"Checker, a list that pins none, no delegation", noFingerprints(t), nil, func(b *Bundle) error { _, _, err := b.Checker("", time0, nil); return err }, counts{1, 1, 1, 0}},
		{"Checker, a list that pins none, a delegation of the type openpgp-subkey", noFingerprints(t), nil, func(b *Bundle) error {
			_, _, err := b.Checker("pgpd", time0, nil)
			return wantErr(err, handoff.ErrNoPrimaries)
		}, counts{1, 1, 1, 0}},
		{"Primaries, a list that pins none and no file", noFingerprints(t), nil, func(b *Bundle) error { _, _, err := b.Primaries(); return err }, counts{1, 1, 1, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, log := writeRecBundle(t, tc.list, tc.keyring)
			if err := tc.run(b); err != nil {
				t.Fatal(err)
			}
			got := counts{countOf(*log, readTrust), countOf(*log, readList), countOf(*log, readCA), countOf(*log, readKeyring)}
			if got != tc.want {
				t.Errorf("reads (listings of trust, list, CA bundle, keyring) = %+v, want %+v\nlog %q", got, tc.want, *log)
			}
		})
	}
}

// wantErr is nil when err wraps the target, and an error that says so otherwise.
func wantErr(err, target error) error {
	if errors.Is(err, target) {
		return nil
	}
	return errors.New("the error does not wrap the expected one: " + errText(err))
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// More pinned primaries than the checks take are refused before the file is read: not one read of the keyring file.
// No root list that the reader accepts holds so many (a list has at most 26 entries, one for each label A to Z), so
// the entries are those of a hand-made reading of the newest set: this is the second guard, held on its own.
func TestMoreThanTheBoundOfPrimariesAreRefusedBeforeTheFileIsRead(t *testing.T) {
	// The entries are those of a hand-made reading of the newest set, so no CA bundle has to match them; the test
	// shows that the count is judged before the keyring file is read.
	var roots []rootlist.Root
	for i := range handoff.MaxPrimaries + 1 {
		roots = append(roots, rootlist.Root{Label: string(rune('A' + i)), OpenPGPFingerprint: fmt.Sprintf("%040x", i+1)})
	}
	b, log := writeRecBundle(t, nil, goodKeyring(t))
	n := &newestSet{set: TrustSet{Name: "7-3fa9c1d2", Number: 7}, list: &rootlist.List{Roots: roots}}
	refs, err := b.primariesOf(n, true)
	want := fmt.Sprintf("the root list of the newest trust set 7-3fa9c1d2 pins %d OpenPGP primaries, and the checks take at most %d", handoff.MaxPrimaries+1, handoff.MaxPrimaries)
	if refs != nil || err == nil || err.Error() != want || !errors.Is(err, ErrPrimaries) {
		t.Fatalf("primariesOf = (%v, %v), want %q of the kind ErrPrimaries", refs, err, want)
	}
	if countOf(*log, readKeyring) != 0 {
		t.Errorf("the keyring file was read: %q", *log)
	}
	// The same list with the most entries is read (and the file, a file of two certificates, is refused as a count of
	// certificates, which proves the read happened).
	n.list = &rootlist.List{Roots: roots[:handoff.MaxPrimaries]}
	if _, err := b.primariesOf(n, true); !errors.Is(err, openpgp.ErrKeyringPrimaries) || countOf(*log, readKeyring) != 1 {
		t.Errorf("%d entries: error %v, reads %d", handoff.MaxPrimaries, err, countOf(*log, readKeyring))
	}
}

func TestPinnedEntriesAreTheEntriesWithAFingerprintInTheOrderOfTheList(t *testing.T) {
	fp := func(c string) string { return strings.Repeat(c, 40) }
	n := &newestSet{list: &rootlist.List{Roots: []rootlist.Root{
		{Label: "C", OpenPGPFingerprint: fp("c")},
		{Label: "A"},
		{Label: "B", OpenPGPFingerprint: fp("b")},
		{Label: "D"},
	}}}
	got := pinnedEntries(n)
	want := []openpgp.KeyringEntry{{Label: "C", Fingerprint: fp("c")}, {Label: "B", Fingerprint: fp("b")}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("pinnedEntries = %v, want %v", got, want)
	}
	if got := pinnedEntries(&newestSet{list: &rootlist.List{Roots: []rootlist.Root{{Label: "A"}}}}); len(got) != 0 {
		t.Errorf("a list with no fingerprint gives %v", got)
	}
}

type panickyError struct{}

func (panickyError) Error() string { panic("an error that panics when its text is asked") }

type nilReceiverError struct{ inner *struct{ s string } }

func (e *nilReceiverError) Error() string { return e.inner.s }

func TestTheTextOfACauseIsTakenOnceEscapedAndCut(t *testing.T) {
	if got := causeText(nil); got != "no cause" {
		t.Errorf("a nil cause: %q", got)
	}
	if got := causeText(panickyError{}); got != "the cause cannot be shown" {
		t.Errorf("an error that panics: %q", got)
	}
	if got := causeText(&nilReceiverError{}); got != "the cause cannot be shown" {
		t.Errorf("an error with a nil field: %q", got)
	}
	if got := causeText(errors.New("a\x1b[31m\nb\u202e c\xffd\u00e9")); !onlyPrintableASCII(got) || strings.ContainsAny(got, "\x1b\n\u202e") || !strings.Contains(got, `\u001b`) || !strings.Contains(got, `\ufffd`) {
		t.Errorf("a hostile cause: %q", got)
	}
	// The cut is at 240 characters (a bound that no page names: a change of it is deliberate, so the number is written here).
	if maxCauseText != 240 {
		t.Errorf("maxCauseText = %d, want 240", maxCauseText)
	}
	// Exactly at the limit: not cut. One over: cut, with three dots.
	atLimit := strings.Repeat("a", maxCauseText)
	if got := causeText(errors.New(atLimit)); got != atLimit {
		t.Errorf("a cause of %d characters was changed: %q", maxCauseText, got)
	}
	over := strings.Repeat("a", maxCauseText+1)
	if got := causeText(errors.New(over)); got != atLimit+"..." {
		t.Errorf("a cause of %d characters: %q", maxCauseText+1, got)
	}
	// The cut is of characters of the escaped text, so it never leaves half of an escape's character: the text stays
	// printable, and valid UTF-8.
	long := strings.Repeat("\u00e9", 1000)
	got := causeText(errors.New(long))
	if !onlyPrintableASCII(got) || !utf8.ValidString(got) || len([]rune(got)) > maxCauseText+3 {
		t.Errorf("a long cause of two-byte characters: %d runes %q", len([]rune(got)), got)
	}
}

func onlyPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func TestTheErrorsOfTheKeyringFileAreSentencesThatKeepTheirCauses(t *testing.T) {
	set := TrustSet{Name: "7-3fa9c1d2", Number: 7}
	readErr := fs.ErrNotExist
	err := noKeyring(set, readErr)
	if err.Error() != "the newest trust set 7-3fa9c1d2 pins OpenPGP primaries and holds no keyring.gpg" {
		t.Errorf("noKeyring text = %q", err.Error())
	}
	if !errors.Is(err, ErrNoKeyring) || !errors.Is(err, fs.ErrNotExist) || errors.Is(err, openpgp.ErrKeyring) {
		t.Errorf("noKeyring does not wrap what it should: %v", err)
	}
	cause := errors.Join(openpgp.ErrKeyringForm)
	err = refusedKeyring(set, cause)
	if !strings.HasPrefix(err.Error(), "keyring.gpg of the newest trust set 7-3fa9c1d2 is refused: ") || !errors.Is(err, openpgp.ErrKeyringForm) || !errors.Is(err, openpgp.ErrKeyring) {
		t.Errorf("refusedKeyring: %v", err)
	}
	// A cause that holds hostile text and is longer than the cut: the sentence is printable and short, and the cause
	// is still reachable as it was.
	evil := &evilCause{text: "x\x1b[2J" + strings.Repeat("y", 5000)}
	err = refusedKeyring(set, evil)
	if !onlyPrintableASCII(err.Error()) || len(err.Error()) > 400 {
		t.Errorf("a hostile cause gives %d bytes: %q", len(err.Error()), err.Error())
	}
	var got *evilCause
	if !errors.As(err, &got) || got != evil {
		t.Errorf("the cause is not reachable with errors.As")
	}
	// The text of the sentence is made once: a cause that changes its text afterwards changes nothing.
	evil.text = "changed"
	if strings.Contains(err.Error(), "changed") {
		t.Errorf("the text of the error follows its cause: %q", err.Error())
	}
	// A set name goes through the exact escape (a name of a trust set cannot hold such bytes, but the sentence does not rely on it).
	hostile := TrustSet{Name: "7-\x1b\u202e", Number: 7}
	if txt := noKeyring(hostile, readErr).Error(); !onlyPrintableASCII(txt) {
		t.Errorf("a hostile set name reaches the text: %q", txt)
	}
	if txt := refusedKeyring(hostile, cause).Error(); !onlyPrintableASCII(txt) {
		t.Errorf("a hostile set name reaches the text: %q", txt)
	}
}

type evilCause struct{ text string }

func (e *evilCause) Error() string { return e.text }

// The keyring file is named in one place: the sentences hold the name, and it is the name of the file that is read.
func TestTheNameOfTheKeyringFileIsTheOneThatTheSentencesAndTheReadUse(t *testing.T) {
	if keyringFile != "keyring.gpg" {
		t.Errorf("the keyring file is named %q", keyringFile)
	}
	b, log := writeRecBundle(t, nil, goodKeyring(t))
	if _, _, err := b.Primaries(); err != nil {
		t.Fatal(err)
	}
	if countOf(*log, "ReadFile trust/7-3fa9c1d2/"+keyringFile) != 1 {
		t.Errorf("the file read is not %s: %q", keyringFile, *log)
	}
}

// time0 is the clock of the hand-off vectors.
func time0() time.Time { return time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC) }
