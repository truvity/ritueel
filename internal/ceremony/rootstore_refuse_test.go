//go:build linux || darwin

package ceremony_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Only the last answer of Refuse counts: a call that refuses, for any reason, leaves the store
// refusing every Birth and SaveRemoval until a later call returns nil.

func TestARefuseThatRefusesLeavesTheStoreRefusingWhateverTheReasonUntilALaterRefuseReturnsNil(t *testing.T) {
	removalText := []byte("eyJhbGciOiJFUzM4NCJ9.eyJ2IjoxfQ.c2ln")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var nilCtx context.Context //nolint:staticcheck
	cases := []struct {
		name string
		// fail makes the next Refuse refuse and says how to call it; undo makes it accept again.
		fail func(t *testing.T, keys string) context.Context
		undo func(t *testing.T, keys string)
	}{
		{"a context that is done", func(*testing.T, string) context.Context { return cancelled }, func(*testing.T, string) {}},
		{"no context", func(*testing.T, string) context.Context { return nilCtx }, func(*testing.T, string) {}},
		{"a key file that appeared", func(t *testing.T, keys string) context.Context {
			if err := os.WriteFile(filepath.Join(keys, "C.x509.key.pem"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return context.Background()
		}, func(t *testing.T, keys string) {
			if err := os.Remove(filepath.Join(keys, "C.x509.key.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a key folder that was taken away", func(t *testing.T, keys string) context.Context {
			if err := os.Rename(keys, keys+".away"); err != nil {
				t.Fatal(err)
			}
			return context.Background()
		}, func(t *testing.T, keys string) {
			if err := os.Rename(keys+".away", keys); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, bundle, keys := mkStoreCase(t)
			s := mkOpenStore(t, keys, bundle)
			ctx := context.Background()
			// A first Refuse accepts, and the store may make a key.
			if err := s.Refuse(ctx); err != nil {
				t.Fatal(err)
			}
			// A second one refuses, and so the store makes nothing and stores nothing.
			bad := tc.fail(t, keys)
			if err := s.Refuse(bad); err == nil {
				t.Fatal("the second Refuse accepted")
			}
			if k, err := s.Birth(ctx, "A"); err == nil || k != nil {
				if k != nil {
					_ = k.Close()
				}
				t.Fatalf("Birth after a Refuse that refused gives %v, %v", k, err)
			}
			if err := s.SaveRemoval("A", removalText); err == nil {
				t.Fatal("SaveRemoval after a Refuse that refused was accepted")
			}
			// A third that refuses again changes nothing.
			if err := s.Refuse(bad); err == nil {
				t.Fatal("the third Refuse accepted")
			}
			if k, err := s.Birth(ctx, "B"); err == nil || k != nil {
				t.Fatalf("Birth after two refusals gives %v, %v", k, err)
			}
			tc.undo(t, keys)
			if ents, _ := os.ReadDir(keys); len(ents) != 0 {
				t.Fatalf("a file was written in the key folder while the store refused: %v", ents)
			}
			// A later nil answer opens the store again.
			if err := s.Refuse(ctx); err != nil {
				t.Fatalf("Refuse after the cause was gone: %v", err)
			}
			mkStart(t, s, "A", "B")
			k, err := s.Birth(ctx, "A")
			if err != nil {
				t.Fatalf("Birth after a Refuse that accepted: %v", err)
			}
			defer func() { _ = k.Close() }()
			if err := s.SaveRemoval("A", removalText); err != nil {
				t.Fatalf("SaveRemoval after a Refuse that accepted: %v", err)
			}
		})
	}
}

func TestARefuseThatRefusesAfterTheKeyWasMadeStopsTheNextKeyAndTheNextRemoval(t *testing.T) {
	// A key stands in the folder already, and the answer is withdrawn: the second key is not made.
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	mkStart(t, s, "A", "B")
	a, err := s.Birth(ctx, "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Refuse(done); err == nil {
		t.Fatal("Refuse with a context that is done accepted")
	}
	if k, err := s.Birth(ctx, "B"); err == nil || k != nil {
		t.Fatalf("Birth of B after a withdrawn answer gives %v, %v", k, err)
	}
	if err := s.SaveRemoval("A", []byte("a.b.c")); err == nil {
		t.Fatal("SaveRemoval after a withdrawn answer was accepted")
	}
	if _, err := os.Stat(filepath.Join(keys, "B.x509.key.pem")); err == nil {
		t.Fatal("the key file of B was made")
	}
	if _, err := os.Stat(filepath.Join(keys, "A.removal.jws")); err == nil {
		t.Fatal("the removal file was made")
	}
}

func TestARefuseOfAClosedStoreRefusesAndStaysRefusing(t *testing.T) {
	_, bundle, keys := mkStoreCase(t)
	s := mkOpenStore(t, keys, bundle)
	ctx := context.Background()
	if err := s.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Refuse(ctx); err == nil {
			t.Fatalf("Refuse %d of a closed store accepted", i+1)
		}
		if k, err := s.Birth(ctx, "A"); err == nil || k != nil {
			t.Fatalf("Birth of a closed store gives %v, %v", k, err)
		}
		if err := s.SaveRemoval("A", []byte("a.b.c")); err == nil {
			t.Fatal("SaveRemoval of a closed store was accepted")
		}
	}
}
