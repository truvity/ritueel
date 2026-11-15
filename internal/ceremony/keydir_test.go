//go:build linux || darwin

package ceremony_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// CheckKeyDir is every refusal about the key directory of a software root that needs no key
// (docs/reference/cli.md, "--key-dir"; record 0005, "Key files inside the bundle"): the directory
// must exist, must not be the bundle or inside it, must not be inside the work tree of a repository
// that holds the bundle, and must hold no key file. A refusal is a *BackendError (exit code 4).

// pfKeyDirCase makes a bundle folder and a place for keys beside it.
func pfKeyDirCase(t *testing.T) (root, bundle string) {
	t.Helper()
	root = t.TempDir()
	bundle = filepath.Join(root, "ca")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, bundle
}

func pfWantBackend(t *testing.T, err error, reason string) {
	t.Helper()
	var b *ceremony.BackendError
	if !errors.As(err, &b) {
		t.Fatalf("the error is %T (%v), want *BackendError (exit code 4)", err, err)
	}
	if !slices.Equal(b.Reasons, []string{reason}) {
		t.Errorf("reasons = %q, want %q", b.Reasons, reason)
	}
	if !strings.Contains(err.Error(), "nothing was written") || !pfPrintable(err.Error()) {
		t.Errorf("the text %+q must say that nothing was written, in printable ASCII", err.Error())
	}
}

func TestAKeyDirectoryBesideTheBundleIsAccepted(t *testing.T) {
	root, bundle := pfKeyDirCase(t)
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	before := tree(t, root)
	if err := ceremony.CheckKeyDir(keys, bundle); err != nil {
		t.Fatalf("CheckKeyDir: %v", err)
	}
	sameTree(t, "CheckKeyDir", before, tree(t, root))
}

func TestAKeyDirectoryThatIsAParentOfTheBundleIsAccepted(t *testing.T) {
	root, bundle := pfKeyDirCase(t)
	if err := ceremony.CheckKeyDir(root, bundle); err != nil {
		t.Fatalf("CheckKeyDir: %v", err)
	}
}

func TestAKeyDirectoryThatBreaksTheRulesIsABackendRefusalWithTheReasonKeyDir(t *testing.T) {
	cases := map[string]func(t *testing.T, root, bundle string) string{
		"missing": func(t *testing.T, root, bundle string) string { return filepath.Join(root, "nothing") },
		"empty":   func(t *testing.T, root, bundle string) string { return "" },
		"a file": func(t *testing.T, root, bundle string) string {
			p := filepath.Join(root, "file")
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"the bundle itself":                func(t *testing.T, root, bundle string) string { return bundle },
		"the bundle with a trailing slash": func(t *testing.T, root, bundle string) string { return bundle + "/" },
		"the bundle spelled with a dot":    func(t *testing.T, root, bundle string) string { return filepath.Join(bundle, ".") },
		"a folder inside the bundle": func(t *testing.T, root, bundle string) string {
			p := filepath.Join(bundle, "keys")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"a folder deep inside the bundle": func(t *testing.T, root, bundle string) string {
			p := filepath.Join(bundle, "history", "a", "b")
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"a link to the bundle": func(t *testing.T, root, bundle string) string {
			p := filepath.Join(root, "link")
			if err := os.Symlink(bundle, p); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"a link to a folder inside the bundle": func(t *testing.T, root, bundle string) string {
			if err := os.Mkdir(filepath.Join(bundle, "keys"), 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(root, "link")
			if err := os.Symlink(filepath.Join(bundle, "keys"), p); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"a path that reaches the bundle through dot dot": func(t *testing.T, root, bundle string) string {
			if err := os.Mkdir(filepath.Join(root, "other"), 0o700); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "other", "..", "ca")
		},
		"a dangling link": func(t *testing.T, root, bundle string) string {
			p := filepath.Join(root, "link")
			if err := os.Symlink(filepath.Join(root, "gone"), p); err != nil {
				t.Fatal(err)
			}
			return p
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			root, bundle := pfKeyDirCase(t)
			keyDir := mk(t, root, bundle)
			before := tree(t, root)
			err := ceremony.CheckKeyDir(keyDir, bundle)
			if err == nil {
				t.Fatal("CheckKeyDir accepted the directory")
			}
			pfWantBackend(t, err, "key-dir")
			sameTree(t, "CheckKeyDir", before, tree(t, root))
		})
	}
}

func TestAKeyDirectoryInsideTheWorkTreeOfARepositoryIsRefused(t *testing.T) {
	for name, mark := range map[string]func(t *testing.T, repo string){
		"a .git folder": func(t *testing.T, repo string) {
			if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a .git file of a linked work tree": func(t *testing.T, repo string) {
			if err := os.WriteFile(filepath.Join(repo, ".git"), []byte("gitdir: /nowhere\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo := t.TempDir()
			mark(t, repo)
			bundle := filepath.Join(repo, "bundles", "ca")
			keys := filepath.Join(repo, "keys")
			for _, d := range []string{bundle, keys} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			pfWantBackend(t, ceremony.CheckKeyDir(keys, bundle), "key-dir")
		})
	}
}

func TestAKeyDirectoryThatHoldsAKeyFileIsRefusedWithTheReasonKeyExists(t *testing.T) {
	for _, name := range []string{"A.x509.key.pem", "B.x509.key.pem", "Z.x509.key.pem", "A.openpgp.key.asc"} {
		t.Run(name, func(t *testing.T) {
			root, bundle := pfKeyDirCase(t)
			keys := filepath.Join(root, "keys")
			if err := os.Mkdir(keys, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(keys, name), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := tree(t, root)
			pfWantBackend(t, ceremony.CheckKeyDir(keys, bundle), "key-exists")
			sameTree(t, "CheckKeyDir", before, tree(t, root))
		})
	}
}

func TestAFolderOrALinkWithTheNameOfAKeyFileIsNotAKeyFile(t *testing.T) {
	root, bundle := pfKeyDirCase(t)
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(keys, "A.x509.key.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("A.x509.key.pem", filepath.Join(keys, "B.x509.key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := ceremony.CheckKeyDir(keys, bundle); err != nil {
		t.Errorf("CheckKeyDir: %v", err)
	}
}

func TestOtherFilesInTheKeyDirectoryAreNotKeyFiles(t *testing.T) {
	root, bundle := pfKeyDirCase(t)
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"README", "A.removal.jws.bak", "notes.txt", ".hidden"} {
		if err := os.WriteFile(filepath.Join(keys, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ceremony.CheckKeyDir(keys, bundle); err != nil {
		t.Errorf("CheckKeyDir refused a folder that holds no key file: %v", err)
	}
}

func TestAnEmptyBundleFolderIsAFailureAndNotABackendRefusal(t *testing.T) {
	root, _ := pfKeyDirCase(t)
	err := ceremony.CheckKeyDir(root, "")
	if err == nil {
		t.Fatal("CheckKeyDir accepted an empty bundle folder")
	}
	var b *ceremony.BackendError
	if errors.As(err, &b) {
		t.Errorf("a fault of the caller was told as a refusal of the key store: %v", err)
	}
	// The text of a joined error holds a line feed between its two parts; the command writes it
	// through the escape of the program. No other control character and nothing but ASCII.
	if !pfPrintable(strings.ReplaceAll(err.Error(), "\n", " ")) {
		t.Errorf("the text %+q is not ASCII", err.Error())
	}
}

func TestACheckOfTheKeyDirectoryLeavesTheFolderForTheNextRun(t *testing.T) {
	root, bundle := pfKeyDirCase(t)
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := ceremony.CheckKeyDir(keys, bundle); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(keys)
	if err != nil || len(ents) != 0 {
		t.Errorf("the key directory holds %d entries after the check: %v", len(ents), err)
	}
}

func TestTheErrorsOfTheEngineSayWhatTheyAre(t *testing.T) {
	if got := (&ceremony.UsageError{Msg: "x"}).Error(); got != "x" {
		t.Errorf("UsageError = %q", got)
	}
	if got := (&ceremony.RefusedError{Reasons: []string{"a", "b"}, Msg: "text"}).Error(); got != "text" {
		t.Errorf("RefusedError with a text = %q", got)
	}
	if got := (&ceremony.RefusedError{Reasons: []string{"a", "b"}}).Error(); got != "refused: a, b" {
		t.Errorf("RefusedError with no text = %q", got)
	}
	if got := (&ceremony.BackendError{Reasons: []string{"key-dir"}, Msg: "text"}).Error(); got != "text" {
		t.Errorf("BackendError with a text = %q", got)
	}
	if got := (&ceremony.BackendError{Reasons: []string{"key-dir"}}).Error(); got != "refused by the key store: key-dir" {
		t.Errorf("BackendError with no text = %q", got)
	}
	for _, e := range []error{ceremony.ErrNotConfirmed, ceremony.ErrNotBuilt, ceremony.ErrNotFirst} {
		if e.Error() == "" || !pfPrintable(e.Error()) {
			t.Errorf("the text of %v", e)
		}
	}
	if errors.Is(ceremony.ErrNotBuilt, ceremony.ErrNotFirst) || errors.Is(ceremony.ErrNotFirst, ceremony.ErrNotBuilt) {
		t.Error("the two kinds of refusal are one")
	}
	if ceremony.ReasonUnfinishedCeremony != "unfinished-ceremony" {
		t.Errorf("ReasonUnfinishedCeremony = %q", ceremony.ReasonUnfinishedCeremony)
	}
}
