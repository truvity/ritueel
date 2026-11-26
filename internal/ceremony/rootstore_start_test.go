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
