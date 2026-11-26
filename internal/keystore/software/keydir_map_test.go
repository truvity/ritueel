package software

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/keydir"
)

// An error of internal/keydir that is not a refusal fails closed: it is the store's refusal of the
// key directory, with the code key-dir and fixed words, and its own text, which may hold a path, is
// not repeated.
func TestAnErrorOfTheKeyDirectoryCheckThatIsNotARefusalFailsClosedAsErrKeyDir(t *testing.T) {
	const secret = "/home/someone/secret-place"
	cases := map[string]error{
		"a plain error":                errors.New("a recognisable text " + secret),
		"a permission error":           fmt.Errorf("stat %s: %w", secret, fs.ErrPermission),
		"a path error that is wrapped": fmt.Errorf("context %s: %w", secret, &fs.PathError{Op: "stat", Path: secret, Err: fs.ErrNotExist}),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			err := fromKeyDir(in)
			if !errors.Is(err, ErrKeyDir) || errors.Is(err, ErrParams) || errors.Is(err, ErrKeyExists) {
				t.Fatalf("not refused as ErrKeyDir alone: %v", err)
			}
			if Code(err) != "key-dir" {
				t.Errorf("the code is %q, want key-dir", Code(err))
			}
			for _, banned := range []string{"recognisable", secret, "permission denied", "stat ", "context"} {
				if strings.Contains(err.Error(), banned) {
					t.Errorf("the error repeats %q: %v", banned, err)
				}
			}
			if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the error still wraps the unknown error: %v", err)
			}
		})
	}
}

// A nil error stays nil through the check, and a refusal of each kind maps to the store's error of
// that kind with the same reason. TestCheckKeyDirRefusesAFolderThatIsMissingNotAFolderOrEmptyAndABundleThatIsMissingOrEmpty
// holds the kinds through CheckKeyDir (ErrKeyDir with the code key-dir, ErrParams); it does not hold
// the words, nor the mapping on its own.
func TestARefusalOfTheKeyDirectoryCheckMapsToTheKindOfTheStoreWithTheSameWords(t *testing.T) {
	f := newFolders(t)
	if err := CheckKeyDir(f.keys, f.bundle); err != nil {
		t.Fatalf("a good folder is refused: %v", err)
	}
	dir, err := checkKeyDir(os.Stat, f.keys, f.bundle)
	if err != nil || dir == "" {
		t.Fatalf("a good folder gives %q, %v", dir, err)
	}
	for _, c := range []struct {
		kind, is error
		not      error
		reason   string
	}{
		{keydir.ErrKeyDir, ErrKeyDir, ErrParams, "the key directory is the bundle folder or inside it"},
		{keydir.ErrParams, ErrParams, ErrKeyDir, "the bundle folder is empty"},
	} {
		in := error(&keydir.Refusal{Kind: c.kind, Reason: c.reason})
		err := fromKeyDir(fmt.Errorf("wrapped: %w", in))
		if !errors.Is(err, c.is) || errors.Is(err, c.not) {
			t.Errorf("a refusal of %v maps to %v", c.kind, err)
		}
		if !strings.HasSuffix(err.Error(), ": "+c.reason) {
			t.Errorf("the words are not kept: %v", err)
		}
		if got, want := Code(err), map[error]string{keydir.ErrKeyDir: "key-dir", keydir.ErrParams: Code(refuse(ErrParams, "x"))}[c.kind]; got != want {
			t.Errorf("the code is %q, want %q", got, want)
		}
	}
}
