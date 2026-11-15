package ceremony

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/trustset"
)

// The seven checks that MakeRoots makes of what it made are a second reading of the artifacts by code
// that did not make them. A fault in what the builders made cannot be made to happen from outside,
// because each builder reads its own output. These tests run the stages of one maker by hand, change
// what a stage left, and run the checks, so that each check is seen to be called and to refuse.

// stageJournal is a journal in memory.
type stageJournal struct {
	mu    sync.Mutex
	lines [][]byte
}

func (j *stageJournal) Append(line []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lines = append(j.lines, append([]byte(nil), line...))
	return nil
}

type stageTrace struct{ b, s *stageJournal }

func (t stageTrace) Births() Journal     { return t.b }
func (t stageTrace) Signatures() Journal { return t.s }

// stageRand is a source of bytes that count.
type stageRand struct{ n int }

func (r *stageRand) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = byte(r.n%251) + 1
	}
	return len(p), nil
}

// stagedMaker runs the stages up to the signatures, and stops before the checks.
func stagedMaker(t *testing.T) *x509Maker {
	t.Helper()
	root := t.TempDir()
	bundleDir, keyDir := filepath.Join(root, "ca"), filepath.Join(root, "keys")
	for _, d := range []string{bundleDir, keyDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	clock := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	n := 0
	env := Env{
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			n++
			return clock.Add(time.Duration(n) * time.Second)
		},
		Rand: &stageRand{},
		Self: func() (buildinfo.Program, error) {
			return buildinfo.Program{Version: "v0.0.0-test", OSArch: "linux/amd64", SHA256: strings.Repeat("ab", 32)}, nil
		},
		Out: NewConsole(io.Discard, io.Discard),
	}
	f := piFound(t)
	env.Now = func() time.Time { return clock }
	plan, err := MakePlan(f, env)
	if err != nil {
		t.Fatal(err)
	}
	env.Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return clock.Add(time.Duration(n) * time.Second)
	}
	store, err := NewSoftwareStore(keyDir, bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	m := &x509Maker{in: MakeIn{
		Env: env, Store: store, Plan: plan, Settings: f.Settings, Root: f.Root,
		Trace: stageTrace{b: &stageJournal{}, s: &stageJournal{}},
	}}
	t.Cleanup(m.closeKeys)
	ctx := context.Background()
	if err := m.checkInput(ctx); err != nil {
		t.Fatalf("checkInput: %v", err)
	}
	if err := store.Refuse(ctx); err != nil {
		t.Fatal(err)
	}
	m.pubs, m.pins = map[string]*ecdsa.PublicKey{}, map[string]string{}
	m.certs, m.removal = map[string][]byte{}, map[string]string{}
	m.signers = map[string]trustset.Signer{}
	if err := m.birth(ctx); err != nil {
		t.Fatalf("birth: %v", err)
	}
	m.show()
	if err := m.sign(ctx); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return m
}

func TestTheStagesOfAMakerGiveACheckedResult(t *testing.T) {
	m := stagedMaker(t)
	made, err := m.check(context.Background())
	if err != nil || made == nil || len(made.Checked) != 7 {
		t.Fatalf("check = %+v, %v", made, err)
	}
}

func TestEachCheckOfTheRunIsCalledAndRefusesWhatItIsGiven(t *testing.T) {
	other := stagedMaker(t)
	cases := []struct {
		name     string
		tamper   func(m *x509Maker)
		artifact string
	}{
		{"the certificate of A is the certificate of another key", func(m *x509Maker) { m.certs["A"] = other.certs["A"] }, "root certificate A"},
		{"the certificate of B is a byte short", func(m *x509Maker) { m.certs["B"] = m.certs["B"][:len(m.certs["B"])-1] }, "root certificate B"},
		{"the removal authorisation of A is that of B", func(m *x509Maker) { m.removal["A"] = m.removal["B"] }, "removal authorisation A"},
		{"the removal authorisation of B is empty", func(m *x509Maker) { m.removal["B"] = "" }, "removal authorisation B"},
		{"the set is the set of another ceremony", func(m *x509Maker) { m.set = other.set }, "root list"},
		{"the set is not there", func(m *x509Maker) { m.set = nil }, "root list"},
		{"one signature that was made is not remembered", func(m *x509Maker) { m.made = m.made[:4] }, "plan against the keys"},
		{"a key that was born is remembered in another place", func(m *x509Maker) { m.born[1].Place = "B.x509.key.pem.old" }, "plan against the keys"},
		{"the first line of the births is missing", func(m *x509Maker) { m.tap.births.lines = m.tap.births.lines[1:] }, "journals"},
		{"a line of the signatures is another line", func(m *x509Maker) {
			m.tap.signatures.lines[0] = other.tap.signatures.lines[1]
		}, "journals"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := stagedMaker(t)
			tc.tamper(m)
			made, err := m.check(context.Background())
			if made != nil {
				t.Fatal("a result comes with a fault")
			}
			var ae *ArtifactError
			if !errors.As(err, &ae) || !strings.HasPrefix(ae.Artifact, tc.artifact) {
				t.Fatalf("the error is %v, want an *ArtifactError of %s", err, tc.artifact)
			}
		})
	}
}

func TestACancelledContextStopsEveryStageAndTheChecks(t *testing.T) {
	m := stagedMaker(t)
	done, cancel := context.WithCancel(context.Background())
	cancel()
	signs := len(m.made)
	// A second pass of signatures with a context that is done signs nothing.
	if err := m.sign(done); !errors.Is(err, context.Canceled) {
		t.Errorf("sign = %v", err)
	}
	if len(m.made) != signs {
		t.Errorf("a signature was made with a context that is done")
	}
	if made, err := m.check(done); made != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("check = %v, %v", made, err)
	}
	if err := m.signList(done); !errors.Is(err, context.Canceled) {
		t.Errorf("signList = %v", err)
	}
	if err := m.birth(done); !errors.Is(err, context.Canceled) {
		t.Errorf("birth = %v", err)
	}
}
