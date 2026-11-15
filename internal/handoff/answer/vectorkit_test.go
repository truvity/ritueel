package answer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strings"
	"testing"
	"time"

	goecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/testrepo"
)

// The clock of every vector (docs/reference/hand-off-contract.md, "Test vectors").
var vectorNow = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

const (
	vectorsDir     = "testdata/hand-off/v1"
	heldListFile   = "testdata/root-list/v1/lists/seq7-a.json"
	heldBundleFile = "testdata/root-list/v1/bundles/ca-bundle-7.pem"
)

// vectorResponse is one entry of "responses" of the manifest.
type vectorResponse struct {
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Request string   `json:"request"`
	Files   []string `json:"files"`
	Floor   bool     `json:"floor"`
	Expect  string   `json:"expect"`
	Reason  string   `json:"reason"`
	SSHList string   `json:"ssh_ca_key_list"`
}

type vectorManifest struct {
	Clock  string `json:"clock"`
	Pinned struct {
		RootList struct {
			X509    []string `json:"x509"`
			OpenPGP []string `json:"openpgp"`
		} `json:"root_list"`
		FloorAnchors  []string `json:"floor_anchors"`
		TrustSequence int64    `json:"trust_sequence"`
	} `json:"pinned"`
	Responses []vectorResponse `json:"responses"`
	Requests  []struct {
		ID     string   `json:"id"`
		Type   string   `json:"type"`
		Files  []string `json:"files"`
		Expect string   `json:"expect"`
		Reason string   `json:"reason"`
	} `json:"requests"`
}

func readVectorManifest(t testing.TB) vectorManifest {
	t.Helper()
	var m vectorManifest
	if err := json.Unmarshal(testrepo.Read(t, vectorsDir, "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Responses) == 0 {
		t.Fatal("the manifest holds no response case: a check that finds nothing to check fails")
	}
	return m
}

// primaryOfFile reads the first packet of a primary's certificate with go-crypto, the reader of the tests and
// not the reader under test.
func primaryOfFile(t testing.TB, file []byte) handoff.PrimaryRef {
	t.Helper()
	p, err := gopacket.Read(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("reading a primary: %v", err)
	}
	pk, ok := p.(*gopacket.PublicKey)
	if !ok {
		t.Fatalf("the first packet of a primary is %T, want a public key", p)
	}
	raw, ok := pk.PublicKey.(*goecdsa.PublicKey)
	if !ok {
		t.Fatalf("the key of a primary is %T, want ECDSA", pk.PublicKey)
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw.MarshalPoint())
	if err != nil {
		t.Fatalf("the point of a primary: %v", err)
	}
	return handoff.PrimaryRef{Fingerprint: hex.EncodeToString(pk.Fingerprint), Key: key, Created: pk.CreationTime.UTC()}
}

// vectorPrimaries are the active primaries of the pinned root list, A then B.
func vectorPrimaries(t testing.TB, m vectorManifest) []handoff.PrimaryRef {
	t.Helper()
	if len(m.Pinned.RootList.OpenPGP) != 2 {
		t.Fatalf("the pinned list holds %d primaries, want 2", len(m.Pinned.RootList.OpenPGP))
	}
	var out []handoff.PrimaryRef
	for _, f := range m.Pinned.RootList.OpenPGP {
		out = append(out, primaryOfFile(t, testrepo.Read(t, vectorsDir, f)))
	}
	return out
}

// vectorHeld is the held list of the vectors: seq7-a and its CA bundle.
func vectorHeld(t testing.TB) (*rootlist.Held, []byte) {
	t.Helper()
	held, err := rootlist.ParseHeld(testrepo.Read(t, heldListFile))
	if err != nil {
		t.Fatal(err)
	}
	return held, testrepo.Read(t, heldBundleFile)
}

func vectorFloorAnchors(t testing.TB, m vectorManifest) [][]byte {
	t.Helper()
	if len(m.Pinned.FloorAnchors) == 0 {
		t.Fatal("the manifest names no floor anchor")
	}
	var out [][]byte
	for _, f := range m.Pinned.FloorAnchors {
		out = append(out, testrepo.Read(t, vectorsDir, f))
	}
	return out
}

// vectorConfig is the configuration of a checker for the full contract with the trust of the vectors.
func vectorConfig(t testing.TB, m vectorManifest) answer.Config {
	t.Helper()
	held, bundle := vectorHeld(t)
	cfg := answer.Config{Held: held, CABundle: bundle, Primaries: vectorPrimaries(t, m), Now: func() time.Time { return vectorNow }}
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 12, 14
	return cfg
}

func vectorFloorConfig(t testing.TB, m vectorManifest) answer.Config {
	t.Helper()
	cfg := answer.Config{FloorAnchors: vectorFloorAnchors(t, m), Now: func() time.Time { return vectorNow }}
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 12, 14
	return cfg
}

func mustChecker(t testing.TB, cfg answer.Config) *answer.Checker {
	t.Helper()
	c, err := answer.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// vectorRoot opens the folder of the vectors for reading, through fsx.
func vectorRoot(t testing.TB) fsx.FS {
	t.Helper()
	root, err := fsx.OpenFS(testrepo.Path(t, vectorsDir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// vectorAsked makes the requester's Asked of a response case, from the request files of the vectors.
func vectorAsked(t testing.TB, c vectorResponse) *answer.Asked {
	t.Helper()
	r, err := handoff.LoadRequest(vectorRoot(t), "requests", c.Request)
	if err != nil {
		t.Fatalf("case %s: %v", c.ID, err)
	}
	if c.Floor {
		csr, ok := r.Files[handoff.FileCSR]
		if !ok {
			t.Fatalf("case %s: the request has no csr file", c.ID)
		}
		a, err := answer.AskedX509(csr)
		if err != nil {
			t.Fatalf("case %s: %v", c.ID, err)
		}
		return a
	}
	a, err := answer.AskedFromRequest(r)
	if err != nil {
		t.Fatalf("case %s: %v", c.ID, err)
	}
	return a
}

// vectorAnswer reads the files that a case names, under the stem that is the id of the case. LoadAnswer
// cannot find them by the request's stem, so the test reads them through fsx itself.
func vectorAnswer(t testing.TB, c vectorResponse) *answer.Answer {
	t.Helper()
	a := &answer.Answer{Stem: c.ID, Files: map[string][]byte{}}
	root := vectorRoot(t)
	for _, f := range c.Files {
		if path.Dir(f) != "responses" || !strings.HasPrefix(path.Base(f), c.ID+".") {
			t.Fatalf("case %s: the file %s is not of the stem in responses/", c.ID, f)
		}
		data, err := fsx.ReadFile(root, f)
		if err != nil {
			t.Fatalf("case %s: %v", c.ID, err)
		}
		a.Files[strings.TrimPrefix(path.Base(f), c.ID+".")] = data
	}
	if len(a.Files) == 0 {
		t.Fatalf("case %s names no file", c.ID)
	}
	return a
}

func vectorCase(t testing.TB, id string) vectorResponse {
	t.Helper()
	for _, c := range readVectorManifest(t).Responses {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("the manifest holds no response case %s", id)
	return vectorResponse{}
}

// statuses is the string of the results of the checks: p passed, f failed, n not run.
func statuses(v answer.Verdict) string {
	var b strings.Builder
	for _, c := range v.Checks {
		switch c.Status {
		case handoff.StatusPassed:
			b.WriteByte('p')
		case handoff.StatusFailed:
			b.WriteByte('f')
		case handoff.StatusNotRun:
			b.WriteByte('n')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func cloneAnswer(a *answer.Answer) *answer.Answer {
	out := &answer.Answer{Stem: a.Stem, Files: map[string][]byte{}}
	for k, v := range a.Files {
		out.Files[k] = bytes.Clone(v)
	}
	return out
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func mustJSONBytes(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
