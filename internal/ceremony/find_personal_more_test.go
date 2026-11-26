//go:build linux || darwin

package ceremony_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
)

// More of Find on a personal bundle: the clock is read once and only when the files get as far as the keys, the
// file of user IDs is a file and nothing else, and a bundle with a history is judged as the other bundles are.
// The names of this file start with pm.

// pmClock counts the reads of the clock.
type pmClock struct {
	reads atomic.Int32
	at    time.Time
}

func (c *pmClock) now() time.Time { c.reads.Add(1); return c.at }

func TestPersonalFindReadsTheClockOnceAndOnlyWhenTheFilesReachTheKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		reads int32
	}{
		"files that pass":                      {pnFiles(), 1},
		"files that pass, with user IDs":       {pnWith(map[string]string{"want/openpgp.yaml": "version: 1\nuser_ids: []\n"}), 1},
		"a root that is refused by its reader": {pnWith(map[string]string{"want/roots/openpgp.yaml": "version: 1\nkind: openpgp\nkeys: 1\n"}), 0},
		"a delegation that is refused":         {pnWith(map[string]string{"want/delegations/daily.yaml": "version: 1\n"}), 0},
		"user IDs that are refused":            {pnWith(map[string]string{"want/openpgp.yaml": "version: 2\n"}), 0},
		"a placeholder":                        {pnWith(map[string]string{"want/roots/openpgp.yaml": strings.Replace(pnRoot, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", strings.Repeat("0", 40), 1)}), 0},
		"a company bundle":                     {map[string]string{"ritueel.yaml": pfSettings, "want/roots/x509.yaml": pfX509Test}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			c := &pmClock{at: pnNow}
			dir := pfWrite(t, tc.files)
			_, _ = pnFind(t, dir, c.now)
			if got := c.reads.Load(); got != tc.reads {
				t.Errorf("the clock was read %d times, want %d", got, tc.reads)
			}
		})
	}
}

func TestPersonalFindWithAClockThatPanicsOrIsOutsideTheYearsIsRefusedWithNothingWritten(t *testing.T) {
	for name, now := range map[string]func() time.Time{
		"a clock that panics":     func() time.Time { panic("no clock") },
		"a time before the years": func() time.Time { return time.Date(0, 1, 1, 0, 0, 1, 0, time.UTC).AddDate(-1, 0, 0) },
		"a time after the years":  func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"a time of half a second": func() time.Time { return time.Time{}.Add(500 * time.Millisecond) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, pnFiles())
			before := tree(t, dir)
			f, err := pnFind(t, dir, now)
			if f != nil || err == nil || errors.Is(err, ceremony.ErrNotBuilt) || !pfPrintable(err.Error()) {
				t.Errorf("Find = %+v, %v", f, err)
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}

// want/openpgp.yaml is optional, and that means the file that is not there: a link, a folder, a pipe, a file that
// cannot be opened and a file whose folder is a link are each a refusal and are never taken for "not there".
func TestPersonalFindTakesNothingButAMissingUserIDsFileForAMissingOne(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, dir string){
		"a link to a good file": func(t *testing.T, dir string) {
			good := filepath.Join(dir, "good.yaml")
			if err := os.WriteFile(good, []byte("version: 1\nuser_ids: []\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(good, filepath.Join(dir, "want", "openpgp.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a link to nothing": func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "nothing.yaml"), filepath.Join(dir, "want", "openpgp.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "want", "openpgp.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a pipe": func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, "want", "openpgp.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a file that cannot be opened": func(t *testing.T, dir string) {
			if os.Geteuid() == 0 {
				t.Skip("root opens every file")
			}
			p := filepath.Join(dir, "want", "openpgp.yaml")
			if err := os.WriteFile(p, []byte("version: 1\nuser_ids: []\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
		},
		"a file that is too long": func(t *testing.T, dir string) {
			text := "version: 1\n# " + strings.Repeat("x", 300<<10) + "\n"
			if err := os.WriteFile(filepath.Join(dir, "want", "openpgp.yaml"), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"an empty file": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "want", "openpgp.yaml"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, pnFiles())
			setup(t, dir)
			var before map[string]string
			if name != "a file that cannot be opened" { // tree reads every file
				before = tree(t, dir)
			}
			f, err := pnFind(t, dir, func() time.Time { return pnNow })
			if f != nil || err == nil || errors.Is(err, ceremony.ErrNotBuilt) || !strings.Contains(err.Error(), "want/openpgp.yaml") || !pfPrintable(err.Error()) {
				t.Errorf("Find = %+v, %v", f, err)
			}
			if before != nil {
				sameTree(t, "Find", before, tree(t, dir))
			}
		})
	}
	// And the file that is not there is no fault: the bundle is not built, as before.
	dir := pfWrite(t, pnFiles())
	if _, err := pnFind(t, dir, func() time.Time { return pnNow }); !errors.Is(err, ceremony.ErrNotBuilt) {
		t.Errorf("no user IDs file: %v", err)
	}
}

// The wanted files that a personal bundle does not use are still read and refused, so that nothing in the folder is
// a surprise at the day it is built: a card file, a delegation and the settings are each judged.
func TestPersonalFindReadsEveryWantedFileItHas(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"a card file that is not valid":     pnWith(map[string]string{"want/cards/other.yaml": "version: 1\n"}),
		"a delegation that is not valid":    pnWith(map[string]string{"want/delegations/other.yaml": "version: 1\n"}),
		"a second card for the same serial": pnWith(map[string]string{"want/cards/twin.yaml": pnCard}),
		"an entry that is no file":          pnWith(nil),
	} {
		t.Run(name, func(t *testing.T) {
			dir := pfWrite(t, files)
			if name == "an entry that is no file" {
				if err := os.Mkdir(filepath.Join(dir, "want", "roots", "x.yaml"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			before := tree(t, dir)
			f, err := pnFind(t, dir, func() time.Time { return pnNow })
			if f != nil || err == nil || errors.Is(err, ceremony.ErrNotBuilt) || !pfPrintable(err.Error()) {
				t.Errorf("Find = %+v, %v (%s)", f, err, pfKind(err))
			}
			sameTree(t, "Find", before, tree(t, dir))
		})
	}
}
