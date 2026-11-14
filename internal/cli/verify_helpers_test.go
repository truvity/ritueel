package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
)

// The tests of verify root-list run the real command through Run, with a clock they fix and files
// they make in t.TempDir(). The lists are the vectors of testdata/root-list/v1, found through the
// manifest: no id, pin, digest or file name of them is written in these tests.

type vmanifest struct {
	Clock       string   `json:"clock"`
	InitialPins []string `json:"initial_pins"`
	Roots       []struct {
		Label string `json:"label"`
		Pin   string `json:"x509_spki_sha256"`
	} `json:"roots"`
	Lists []struct {
		ID    string   `json:"id"`
		Files []string `json:"files"`
	} `json:"lists"`
	Cases   []vcase `json:"cases"`
	Bundles []struct {
		ID       string   `json:"id"`
		File     string   `json:"file"`
		Sequence int64    `json:"sequence"`
		Roots    []string `json:"roots"`
		Flaw     string   `json:"flaw"`
	} `json:"bundles"`
}

type vcase struct {
	ID        string  `json:"id"`
	Held      *string `json:"held"`
	Candidate *string `json:"candidate"`
	Clock     string  `json:"clock"`
	Expect    string  `json:"expect"`
	Reason    string  `json:"reason"`
	Warning   string  `json:"warning"`
	// Bundle names a CA bundle that the case also checks (--ca-bundle).
	Bundle string `json:"bundle"`
	// MinSequence is the lowest sequence given with the initial pins (--min-sequence).
	MinSequence *int64 `json:"min_sequence"`
}

// vknownCaseMembers are the members of a case that these tests run. A case with another member is a
// kind that the tests do not know, and the run fails with a text that says which.
var vknownCaseMembers = []string{"id", "held", "candidate", "clock", "expect", "reason", "warning", "bundle", "min_sequence"}

// vunknownCaseMember returns "" or the text for a case that has a member the tests do not know.
func vunknownCaseMember(data []byte) string {
	var top struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return err.Error()
	}
	for i, c := range top.Cases {
		for name := range c {
			if !slices.Contains(vknownCaseMembers, name) {
				return fmt.Sprintf("a kind of case this test does not know: case %d has the member %q", i, name)
			}
		}
	}
	return ""
}

const vecDir = "testdata/root-list/v1"

func vloadManifest(t testing.TB) *vmanifest {
	t.Helper()
	var m vmanifest
	if err := json.Unmarshal(testrepo.Read(t, vecDir, "manifest.json"), &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if len(m.Cases) == 0 || len(m.Lists) == 0 {
		t.Fatal("the manifest has no cases or no lists")
	}
	if msg := vunknownCaseMember(testrepo.Read(t, vecDir, "manifest.json")); msg != "" {
		t.Fatal(msg)
	}
	return &m
}

// bytesOf returns the two files of a list by id.
func (m *vmanifest) bytesOf(t testing.TB, id string) (jsonData, jwsData []byte) {
	t.Helper()
	for _, l := range m.Lists {
		if l.ID != id {
			continue
		}
		for _, f := range l.Files {
			switch path.Ext(f) {
			case ".json":
				jsonData = testrepo.Read(t, vecDir, f)
			case ".jws":
				jwsData = testrepo.Read(t, vecDir, f)
			}
		}
		if jsonData == nil || jwsData == nil {
			t.Fatalf("list %q has no .json and .jws pair", id)
		}
		return jsonData, jwsData
	}
	t.Fatalf("no list %q in the manifest", id)
	return nil, nil
}

func (m *vmanifest) listOf(t testing.TB, id string) *rootlist.List {
	t.Helper()
	data, _ := m.bytesOf(t, id)
	l, err := rootlist.ParseList(data)
	if err != nil {
		t.Fatalf("list %q: %v", id, err)
	}
	return l
}

func (m *vmanifest) pin(t testing.TB, label string) string {
	t.Helper()
	for _, r := range m.Roots {
		if r.Label == label {
			return r.Pin
		}
	}
	t.Fatalf("no root %q", label)
	return ""
}

func (m *vmanifest) initialPins(t testing.TB) []string {
	t.Helper()
	var out []string
	for _, l := range m.InitialPins {
		out = append(out, m.pin(t, l))
	}
	return out
}

func (m *vmanifest) clockOf(t testing.TB, own string) time.Time {
	t.Helper()
	c := own
	if c == "" {
		c = m.Clock
	}
	tm, err := time.Parse(time.RFC3339, c)
	if err != nil {
		t.Fatalf("clock %q: %v", c, err)
	}
	return tm
}

// A scenario is one accepting case of the manifest, with the files in a folder of its own.
type vscene struct {
	dir        string
	cand, jws  string // the paths of the candidate's two files
	held       string // the path of the held list, "" when the case has initial pins
	pins       []string
	clock      time.Time
	candBytes  []byte
	jwsBytes   []byte
	heldBytes  []byte
	candList   *rootlist.List
	caseRecord vcase
	bundle     string // the path of the CA bundle of the case, "" when it has none
	bundleData []byte
	minSeq     *int64
}

// write makes a file in dir and returns its path.
func vwrite(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// vstage stages a case of the manifest in a new folder: the candidate as cand.json and cand.jws,
// the held list as held.json.
func vstage(t testing.TB, m *vmanifest, c vcase) *vscene {
	t.Helper()
	s := &vscene{dir: t.TempDir(), clock: m.clockOf(t, c.Clock), caseRecord: c}
	if c.Candidate == nil {
		t.Fatalf("case %s has no candidate", c.ID)
	}
	s.candBytes, s.jwsBytes = m.bytesOf(t, *c.Candidate)
	s.cand = vwrite(t, s.dir, "cand.json", s.candBytes)
	s.jws = vwrite(t, s.dir, "cand.jws", s.jwsBytes)
	if c.Held != nil {
		s.heldBytes, _ = m.bytesOf(t, *c.Held)
		s.held = vwrite(t, s.dir, "held.json", s.heldBytes)
	} else {
		s.pins = m.initialPins(t)
	}
	if l, err := rootlist.ParseList(s.candBytes); err == nil {
		s.candList = l
	}
	if c.Bundle != "" {
		s.bundleData = m.bundleBytes(t, c.Bundle)
		s.bundle = vwrite(t, s.dir, "bundle.pem", s.bundleData)
	}
	s.minSeq = c.MinSequence
	return s
}

// hostArgs are the arguments that name what the host holds.
func (s *vscene) hostArgs() []string {
	if s.held != "" {
		return []string{"--held", s.held}
	}
	var a []string
	for _, p := range s.pins {
		a = append(a, "--pin", p)
	}
	return a
}

func (s *vscene) args(mode string, extra ...string) []string {
	a := []string{"--output", mode, "verify", "root-list", s.cand}
	a = append(a, s.hostArgs()...)
	if s.minSeq != nil {
		a = append(a, "--min-sequence", fmt.Sprint(*s.minSeq))
	}
	if s.bundle != "" {
		a = append(a, "--ca-bundle", s.bundle)
	}
	return append(a, extra...)
}

// bundleBytes returns the bytes of a CA bundle of the manifest by id.
func (m *vmanifest) bundleBytes(t testing.TB, id string) []byte {
	t.Helper()
	for _, b := range m.Bundles {
		if b.ID == id {
			return testrepo.Read(t, vecDir, b.File)
		}
	}
	t.Fatalf("no bundle %q in the manifest", id)
	return nil
}

// firstAccept returns the first case of the manifest that accepts a list against a held list that
// is not the same bytes (a new list), and the first that accepts one against initial pins.
func (m *vmanifest) newAgainstHeld(t testing.TB) vcase {
	t.Helper()
	for _, c := range m.Cases {
		if c.Expect == "accept" && c.Held != nil && *c.Held != *c.Candidate {
			return c
		}
	}
	t.Fatal("no accepting case with a held list")
	return vcase{}
}

func (m *vmanifest) againCase(t testing.TB) vcase {
	t.Helper()
	for _, c := range m.Cases {
		if c.Expect == "accept" && c.Held != nil && *c.Held == *c.Candidate {
			return c
		}
	}
	t.Fatal("no case that accepts the held list again")
	return vcase{}
}

func (m *vmanifest) againstPins(t testing.TB) vcase {
	t.Helper()
	for _, c := range m.Cases {
		if c.Expect == "accept" && c.Held == nil {
			return c
		}
	}
	t.Fatal("no accepting case with initial pins")
	return vcase{}
}

func (m *vmanifest) refusing(t testing.TB, reason string) vcase {
	t.Helper()
	for _, c := range m.Cases {
		if c.Expect == "refuse" && c.Reason == reason && c.Held != nil {
			return c
		}
	}
	t.Fatalf("no refusing case with the reason %q and a held list", reason)
	return vcase{}
}

func vrunAt(t *testing.T, now time.Time, args ...string) result {
	t.Helper()
	return runEnv(t, func() time.Time { return now }, args...)
}

// sum is the SHA-256 of the bytes, in lower-case hexadecimal, computed here.
func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// jsonObject decodes the one object on standard output and returns it with the text.
func jsonObject(t *testing.T, r result) map[string]any {
	t.Helper()
	return object(t, r.stdout)
}

// terminalSafe fails the test when what the run wrote holds a byte outside printable ASCII and the
// line break.
func terminalSafe(t *testing.T, r result) {
	t.Helper()
	if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
		t.Errorf("a byte outside printable ASCII reached the terminal: stdout %q stderr %q", r.stdout, r.stderr)
	}
}

// requireTool is the helper of the repository for a test that needs an outside tool: it skips when
// the tool is not on PATH, unless RITUEEL_REQUIRE_TOOLS=1, which the recipe go-test sets, and then
// it fails.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("RITUEEL_REQUIRE_TOOLS") == "1" {
			t.Fatalf("the %s tool is not on PATH and RITUEEL_REQUIRE_TOOLS=1: %v", name, err)
		}
		t.Skipf("the %s tool is not on PATH", name)
	}
	return p
}

// A file fault is a way to make a path that is not a good file. The test fails, with a text that
// says what this system cannot do, when it cannot make one: nothing is skipped.
type vfault struct {
	name string
	make func(t *testing.T, dir, name string, good []byte)
	// candidate is the exit code of the fault for a file of the candidate: 1 failed or 3 refused.
	candidate ExitCode
	// detail is the end of the refusal line for a file of the candidate, "%s" being the file name.
	detail string
}

func vfaults() []vfault {
	return []vfault{
		{"a file that is missing", func(t *testing.T, dir, name string, good []byte) {}, ExitFailure, ""},
		{"a file with no permission to read", func(t *testing.T, dir, name string, good []byte) {
			p := vwrite(t, dir, name, good)
			if os.Geteuid() == 0 {
				t.Fatal("this test runs as root, which can read any file: run it as an ordinary user")
			}
			if err := os.Chmod(p, 0); err != nil {
				t.Fatalf("cannot remove the permission to read: %v", err)
			}
			if f, err := os.Open(p); err == nil {
				_ = f.Close()
				t.Fatal("a file with mode 000 can still be opened by this user: the test cannot make a file that is not readable")
			}
		}, ExitFailure, ""},
		{"a link to a good file", func(t *testing.T, dir, name string, good []byte) {
			target := vwrite(t, t.TempDir(), "target", good)
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatalf("cannot make a symbolic link: %v", err)
			}
		}, ExitRefused, "%s is a symbolic link"},
		{"a link to nothing", func(t *testing.T, dir, name string, good []byte) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), filepath.Join(dir, name)); err != nil {
				t.Fatalf("cannot make a symbolic link: %v", err)
			}
		}, ExitRefused, "%s is a symbolic link"},
		{"a FIFO", func(t *testing.T, dir, name string, good []byte) {
			if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
				t.Fatalf("cannot make a FIFO on this system, and the test needs one: %v", err)
			}
		}, ExitRefused, "%s is not a regular file"},
		{"a link to a device", func(t *testing.T, dir, name string, good []byte) {
			if _, err := os.Stat("/dev/zero"); err != nil {
				t.Fatalf("this system has no /dev/zero, and the test needs a device: %v", err)
			}
			if err := os.Symlink("/dev/zero", filepath.Join(dir, name)); err != nil {
				t.Fatalf("cannot make a symbolic link: %v", err)
			}
		}, ExitRefused, "%s is a symbolic link"},
		{"a folder", func(t *testing.T, dir, name string, good []byte) {
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}, ExitRefused, "%s is not a regular file"},
		{"a file over the limit of the reader", func(t *testing.T, dir, name string, good []byte) {
			vwrite(t, dir, name, append(slices.Clone(good), make([]byte, 8<<20+1-len(good))...))
		}, ExitRefused, "%s is longer than 8388608 bytes"},
	}
}

// vfifoGuard runs f and fails the test when it does not return in time: a FIFO that was waited on
// would hang the command, and a test that hangs says nothing.
func vfifoGuard(t *testing.T, f func() result) result {
	t.Helper()
	done := make(chan result, 1)
	go func() { done <- f() }()
	select {
	case r := <-done:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("the command did not return in 30 seconds: it waited on a file")
		return result{}
	}
}
