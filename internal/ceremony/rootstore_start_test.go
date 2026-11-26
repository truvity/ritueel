//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// RootStore.Start: the key store starts after the person confirmed, with the labels of the plan, and not before; a
// Birth before it is an error. The names of this file start with rs.

func rsEntries(t *testing.T, dir string) []string {
	t.Helper()
	return mkNames(t, dir)
}

func TestABirthBeforeStartIsAnErrorThatMakesNothing(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	k, err := s.Birth(ctx, "A")
	if k != nil || err == nil {
		t.Fatalf("Birth before Start = %v, %v; want an error and no key", k, err)
	}
	if !strings.Contains(err.Error(), "not started") {
		t.Errorf("the error does not say that the store was not started: %v", err)
	}
	if mkBackendReason(err) != "" {
		t.Errorf("a Birth before Start is a fault of the caller and not a refusal of the store: %v", err)
	}
	if got := rsEntries(t, keys); len(got) != 0 {
		t.Errorf("a Birth before Start made %q in the key directory", got)
	}
	// The removal authorisation does not need the key store, but no key is made by it either.
	mkStart(t, s, "A", "B")
	if got := rsEntries(t, filepath.Join(keys, "test-only-keys")); len(got) != 0 {
		t.Errorf("Start made a key: %q", got)
	}
	k, err = s.Birth(ctx, "A")
	if err != nil {
		t.Fatalf("Birth after Start: %v", err)
	}
	_ = k.Close()
}

func TestStartMakesTheFolderAndNoKeyAndNeedsTheLabelsOfThePlan(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()

	// Before Refuse: an error, and no folder.
	if err := s.Start(ctx, []string{"A", "B"}); err == nil {
		t.Error("Start before Refuse: no error")
	}
	if got := rsEntries(t, keys); len(got) != 0 {
		t.Fatalf("a Start that must fail made %q", got)
	}
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	for name, c := range map[string]struct {
		ctx    context.Context
		labels []string
	}{
		"a nil context":     {nil, []string{"A"}}, //nolint:staticcheck // the nil context is the case
		"a done context":    {done, []string{"A"}},
		"no label":          {ctx, nil},
		"an empty list":     {ctx, []string{}},
		"a lower-case one":  {ctx, []string{"a"}},
		"a long one":        {ctx, []string{"AB"}},
		"an empty one":      {ctx, []string{""}},
		"a digit":           {ctx, []string{"1"}},
		"a label twice":     {ctx, []string{"A", "A"}},
		"a label and a bad": {ctx, []string{"A", "b"}},
	} {
		if err := s.Start(c.ctx, c.labels); err == nil {
			t.Errorf("Start with %s: no error", name)
		}
	}
	if got := rsEntries(t, keys); len(got) != 0 {
		t.Fatalf("a Start that must fail made %q", got)
	}

	if err := s.Start(ctx, []string{"A", "B"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st, err := os.Lstat(filepath.Join(keys, "test-only-keys"))
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Errorf("the folder is %v, %v; want a folder of the mode 0700", st, err)
	}
	if got := rsEntries(t, keys); !slices.Equal(got, []string{"test-only-keys"}) {
		t.Errorf("the key directory holds %q after Start", got)
	}
	if got := rsEntries(t, filepath.Join(keys, "test-only-keys")); len(got) != 0 {
		t.Errorf("Start made a key: %q", got)
	}
	// A second Start with the same labels does nothing; with other labels it is an error and changes nothing.
	if err := s.Start(ctx, []string{"A", "B"}); err != nil {
		t.Errorf("a second Start with the same labels: %v", err)
	}
	for _, other := range [][]string{{"A"}, {"B", "A"}, {"A", "B", "C"}} {
		if err := s.Start(ctx, other); err == nil {
			t.Errorf("Start with the labels %v after Start with A and B: no error", other)
		}
	}
	// The driver declared A and B and nothing else: a label that was not started has no key.
	if k, err := s.Birth(ctx, "C"); k != nil || err == nil {
		t.Errorf("Birth of C = %v, %v; want an error", k, err)
	}
	if got := rsEntries(t, filepath.Join(keys, "test-only-keys")); len(got) != 0 {
		t.Errorf("a Birth of a label that was not started made %q", got)
	}
	// A closed store starts nothing.
	other := mkOpenStore(t, keys, bundle)
	_ = other.Close()
	if err := other.Start(ctx, []string{"A"}); err == nil {
		t.Error("Start of a closed store: no error")
	}
}

// A folder that appears or changes between Refuse and Start is refused by Start, with the reason of the refusal of the
// key directory, and nothing that stands there is changed.
func TestStartRefusesAFolderThatChangedAfterRefuseAndChangesNothing(t *testing.T) {
	cases := []struct {
		name   string
		make   func(t *testing.T, keys string)
		reason string
	}{
		{"a folder with a key", func(t *testing.T, keys string) {
			p := filepath.Join(keys, "test-only-keys")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "x509-root-a.p8"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "key-exists"},
		{"a file", func(t *testing.T, keys string) {
			if err := os.WriteFile(filepath.Join(keys, "test-only-keys"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "key-exists"},
		{"a link", func(t *testing.T, keys string) {
			if err := os.Symlink(filepath.Join(keys, "nowhere"), filepath.Join(keys, "test-only-keys")); err != nil {
				t.Fatal(err)
			}
		}, "key-exists"},
		{"an empty folder of the mode 0755", func(t *testing.T, keys string) {
			p := filepath.Join(keys, "test-only-keys")
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "key-dir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, bundle, keys := mkStoreCase(t)
			s := mkOpenStore(t, keys, bundle)
			ctx := context.Background()
			if err := s.Refuse(ctx); err != nil {
				t.Fatal(err)
			}
			c.make(t, keys)
			before := tree(t, keys)
			err := s.Start(ctx, []string{"A", "B"})
			if got := mkBackendReason(err); got != c.reason {
				t.Fatalf("Start = %v (reason %q), want the reason %q", err, got, c.reason)
			}
			if strings.Contains(err.Error(), keys) {
				t.Errorf("the text holds a path: %v", err)
			}
			sameTree(t, "a Start that refused", before, tree(t, keys))
			if k, err := s.Birth(ctx, "A"); k != nil || err == nil {
				t.Errorf("a key was born after a Start that refused: %v, %v", k, err)
			}
			var be *ceremony.BackendError
			if !errors.As(err, &be) {
				t.Errorf("the refusal is %T", err)
			}
		})
	}
}

// A start of the key store that is refused after the folder test-only-keys stood or was made says that the folder may
// stand; the refusal for a folder that stood already and was not fit does not say it, because that folder is
// someone else's and not a leftover of this run. A direct apply adds what it wrote.
func TestARefusedStartSaysThatTheFolderMayStandOnlyWhenTheFolderWasThisRunsToLeave(t *testing.T) {
	const may = "the folder test-only-keys may stand in the key directory"
	cases := []struct {
		name   string
		plant  func(t *testing.T, keys string)
		reason string
		may    bool
	}{
		{"an empty folder that the driver refuses (the mode 0755)", func(t *testing.T, keys string) {
			p := filepath.Join(keys, "test-only-keys")
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "key-dir", true},
		{"a folder with a key", func(t *testing.T, keys string) {
			p := filepath.Join(keys, "test-only-keys")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "x509-root-a.p8"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "key-exists", false},
		{"a file", func(t *testing.T, keys string) {
			if err := os.WriteFile(filepath.Join(keys, "test-only-keys"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "key-exists", false},
	}
	for _, c := range cases {
		for _, saved := range []bool{false, true} {
			name := c.name + ", direct"
			if saved {
				name = c.name + ", saved plan"
			}
			t.Run(name, func(t *testing.T) {
				r := rtNew(t)
				var planted map[string]string
				r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
					inner, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
					if err != nil {
						return nil, err
					}
					w := &mkStore{log: &mkLog{}, inner: inner}
					calls := 0
					return rtRefuseHook{mkStore: w, after: func() {
						if calls++; calls == 1 { // the judgement before the confirmation
							c.plant(t, keyDir)
							planted = tree(t, keyDir)
						}
					}}, nil
				}
				var in ceremony.RunIn
				var p *ceremony.PlanOut
				if saved {
					p = r.savePlan()
					in = r.savedIn(p, rtFlag(p))
				} else {
					var f *ceremony.Found
					p, f = r.plan()
					in = r.in(p, f, rtFlag(p))
				}
				done, err := ceremony.Run(context.Background(), in)
				if done != nil || mkBackendReason(err) != c.reason {
					t.Fatalf("Run = %v, %v; want a refusal with the reason %s", done, err, c.reason)
				}
				if _, stopped := rtStopped(err); stopped {
					t.Errorf("a refusal of the store is no stop: %v", err)
				}
				msg := err.Error()
				if got := strings.Contains(msg, may); got != c.may {
					t.Errorf("the line says that the folder may stand = %v, want %v: %s", got, c.may, msg)
				}
				wrote := "this run wrote the plan folder history/" + p.Name + " before it found this, and wrote no attempt and made no key"
				if got := strings.Contains(msg, wrote); got == saved {
					t.Errorf("the line says what a direct apply wrote = %v, want %v: %s", got, !saved, msg)
				}
				if strings.Contains(msg, r.keyDir) || strings.Contains(msg, r.root) {
					t.Errorf("the line holds a path: %s", msg)
				}
				if fxExists(r, "history", p.Name, "attempt.json") {
					t.Error("an attempt was written")
				}
				sameTree(t, "the refused start in the key directory", planted, r.keyTree())
				if !saved && strings.Contains(msg, "nothing was written") {
					t.Errorf("a direct apply says that nothing was written although it wrote the plan folder: %s", msg)
				}
			})
		}
	}
}

// rsFailStart is a store whose Start fails with err, after or before the real Start made the folder.
type rsFailStart struct {
	ceremony.RootStore
	err      error
	startToo bool
}

func (s *rsFailStart) Start(ctx context.Context, labels []string) error {
	if s.startToo {
		if err := s.RootStore.Start(ctx, labels); err != nil {
			return err
		}
	}
	return s.err
}

// A start that fails for a reason that is not a refusal is a stop at the step key-store: the plan folder is written,
// no attempt, no key; the line says that the empty folder may stand.
func TestAStartOfTheKeyStoreThatFailsIsAStopAtTheStepKeyStoreWithNoAttemptAndNoKey(t *testing.T) {
	boom := errors.New("test: the driver cannot start")
	for _, folderMade := range []bool{false, true} {
		name := "before the folder was made"
		if folderMade {
			name = "after the folder was made"
		}
		for _, saved := range []bool{false, true} {
			label := name + ", direct"
			if saved {
				label = name + ", saved plan"
			}
			t.Run(label, func(t *testing.T) {
				r := rtNew(t)
				r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
					inner, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
					if err != nil {
						return nil, err
					}
					return &rsFailStart{RootStore: inner, err: boom, startToo: folderMade}, nil
				}
				var in ceremony.RunIn
				var p *ceremony.PlanOut
				if saved {
					p = r.savePlan()
					in = r.savedIn(p, rtFlag(p))
				} else {
					var f *ceremony.Found
					p, f = r.plan()
					in = r.in(p, f, rtFlag(p))
				}
				done, err := ceremony.Run(context.Background(), in)
				s, ok := rtStopped(err)
				if done != nil || !ok || s.Step != "key-store" || s.Attempt {
					t.Fatalf("Run = %v, %v; want a stop at key-store with no open attempt", done, err)
				}
				if !errors.Is(err, boom) {
					t.Errorf("the cause is not reachable: %v", err)
				}
				if rtKind(err) != "stopped" {
					t.Errorf("a stop is exit code 1, the kind is %s", rtKind(err))
				}
				msg := err.Error()
				for _, want := range []string{
					"the ceremony history/" + p.Name + " stopped at key-store: ",
					"the plan folder may hold some of its files, no attempt was written, and no key was made",
					stopEmptyClause,
					"nothing was retried, and ritueel deleted nothing",
				} {
					if !strings.Contains(msg, want) {
						t.Errorf("the line does not say %q: %s", want, msg)
					}
				}
				if !pfPrintable(msg) || strings.Contains(msg, r.keyDir) {
					t.Errorf("the line is not one line of printable text without a path: %+q", msg)
				}
				for _, not := range []string{"close, which closes", "an attempt is open", ".tmp-", "removal authorisation"} {
					if strings.Contains(msg, not) {
						t.Errorf("the line says %q: %s", not, msg)
					}
				}
				if fxExists(r, "history", p.Name, "attempt.json") || fxExists(r, "history", p.Name, "births.jsonl") {
					t.Error("an attempt or a journal was written")
				}
				fxNoKeys(t, r)
				if !folderMade {
					fxNoKeyDirEntries(t, r)
				}
			})
		}
	}
}
