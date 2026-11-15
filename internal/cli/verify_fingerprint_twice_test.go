package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The tests below run verify root-list on lists that these tests write and sign themselves with
// root keys made in memory (the keys are written nowhere): the shared vectors hold no list in which
// two entries have one fingerprint. The root keys are example keys.

// ftKey is a root key of the tests: P-384, with a self-signed certificate.
type ftKey struct {
	label string
	priv  *ecdsa.PrivateKey
	cert  []byte
	pin   string
}

func ftNewKey(t testing.TB, label string) *ftKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Test Root " + label},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &ftKey{label: label, priv: priv, cert: der, pin: hex.EncodeToString(sum[:])}
}

func ftB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ftList is the canonical text of a list of sequence 1 for the keys, the entry i having the
// fingerprint fps[i] (the first 40 digits of its pin when fps is nil), and none when fps[i] is "".
func ftList(keys []*ftKey, fps []string) []byte {
	var b strings.Builder
	b.WriteString(`{"expires_at":"2027-12-15T12:00:00Z","roots":[`)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fp := k.pin[:40]
		if fps != nil {
			fp = fps[i]
		}
		b.WriteString(`{"label":"` + k.label + `"`)
		if fp != "" {
			b.WriteString(`,"openpgp_fingerprint":"` + fp + `"`)
		}
		b.WriteString(`,"x509_spki_sha256":"` + k.pin + `"}`)
	}
	b.WriteString(`],"sequence":1,"signed_at":"2026-11-15T12:00:00Z","version":1}`)
	return []byte(b.String())
}

// ftSign is the detached signature file of the list by the signer.
func ftSign(t testing.TB, payload []byte, signer *ftKey) []byte {
	t.Helper()
	header := fmt.Sprintf(`{"alg":"ES384","kid":%q,"typ":"root-list+json","x5c":[%q]}`, signer.pin, base64.StdEncoding.EncodeToString(signer.cert))
	protected := ftB64([]byte(header))
	sum := sha512.Sum384([]byte(protected + "." + ftB64(payload)))
	r, s, err := ecdsa.Sign(rand.Reader, signer.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return []byte(`{"signatures":[{"protected":"` + protected + `","signature":"` + ftB64(sig) + `"}]}`)
}

// ftClock is a clock between the signing time and the expiry of the lists above.
var ftClock = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)

// ftRun stages the list, signed by the first key, in a folder and runs verify root-list against the
// pins of the keys, in the mode.
func ftRun(t *testing.T, mode string, keys []*ftKey, list []byte) result {
	t.Helper()
	dir := t.TempDir()
	cand := vwrite(t, dir, "cand.json", list)
	vwrite(t, dir, "cand.jws", ftSign(t, list, keys[0]))
	args := []string{"--output", mode, "verify", "root-list", cand}
	for _, k := range keys {
		args = append(args, "--pin", k.pin)
	}
	return vrunAt(t, ftClock, args...)
}

func TestVerifyRootListRefusesOneFingerprintOnTwoEntriesAsMalformed(t *testing.T) {
	keys := []*ftKey{ftNewKey(t, "A"), ftNewKey(t, "B"), ftNewKey(t, "C")}
	t.Run("the witness: the same list with a fingerprint for each entry is accepted", func(t *testing.T) {
		for _, mode := range []string{"text", "json"} {
			if r := ftRun(t, mode, keys, ftList(keys, nil)); r.code != ExitOK || r.stderr != "" {
				t.Fatalf("%s: (%d, %q, %q), want an accepted list", mode, int(r.code), r.stdout, r.stderr)
			}
		}
	})
	for _, tc := range []struct {
		name         string
		fps          func() []string
		first, other string
		at           int
	}{
		{"the first and the second", func() []string { return []string{keys[0].pin[:40], keys[0].pin[:40], keys[2].pin[:40]} }, "A", "B", 1},
		{"the first and the last", func() []string { return []string{keys[0].pin[:40], keys[1].pin[:40], keys[0].pin[:40]} }, "A", "C", 2},
		{"all three", func() []string { return []string{keys[0].pin[:40], keys[0].pin[:40], keys[0].pin[:40]} }, "A", "B", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := ftList(keys, tc.fps())
			wantStart := "ritueel: refused: malformed (check 5: "
			detail := fmt.Sprintf("the fingerprint appears twice: the entries with the labels %s and %s have the same one", tc.first, tc.other)
			j := ftRun(t, "json", keys, list)
			if j.code != ExitRefused || j.stdout != refusedObject("malformed") || !strings.HasPrefix(j.stderr, wantStart) || strings.Count(j.stderr, "\n") != 1 {
				t.Fatalf("json: %d\nstdout %q\nstderr %q", int(j.code), j.stdout, j.stderr)
			}
			if !strings.Contains(j.stderr, fmt.Sprintf("$.roots[%d].openpgp_fingerprint", tc.at)) || !strings.Contains(j.stderr, detail) {
				t.Errorf("the line lacks the place or the labels: %q", j.stderr)
			}
			txt := ftRun(t, "text", keys, list)
			if txt.code != ExitRefused || txt.stdout != "" || txt.stderr != j.stderr {
				t.Fatalf("text: %d stdout %q stderr %q (json stderr %q)", int(txt.code), txt.stdout, txt.stderr, j.stderr)
			}
			terminalSafe(t, j)
			terminalSafe(t, txt)
		})
	}
	t.Run("entries with no fingerprint are not compared", func(t *testing.T) {
		for _, mode := range []string{"text", "json"} {
			if r := ftRun(t, mode, keys, ftList(keys, []string{"", "", ""})); r.code != ExitOK {
				t.Errorf("%s: (%d, %q, %q)", mode, int(r.code), r.stdout, r.stderr)
			}
			if r := ftRun(t, mode, keys, ftList(keys, []string{keys[0].pin[:40], "", keys[2].pin[:40]})); r.code != ExitOK {
				t.Errorf("%s: (%d, %q, %q)", mode, int(r.code), r.stdout, r.stderr)
			}
		}
	})
	t.Run("the held list is read by the same reader: a held list with the repeat cannot be used, exit code 1, as for a label twice", func(t *testing.T) {
		good := ftList(keys, nil)
		dir := t.TempDir()
		cand := vwrite(t, dir, "cand.json", good)
		vwrite(t, dir, "cand.jws", ftSign(t, good, keys[0]))
		held := vwrite(t, dir, "held.json", ftList(keys, []string{keys[0].pin[:40], keys[0].pin[:40], ""}))
		const line = "ritueel: the held list cannot be used: malformed JSON: $.roots[1].openpgp_fingerprint: the fingerprint appears twice: the entries with the labels A and B have the same one\n"
		for _, mode := range []string{"text", "json"} {
			r := vrunAt(t, ftClock, "--output", mode, "verify", "root-list", cand, "--held", held)
			if r.code != ExitFailure || r.stderr != line {
				t.Errorf("%s: (%d, %q, %q), want exit code 1 and %q", mode, int(r.code), r.stdout, r.stderr, line)
			}
		}
	})
	t.Run("an earlier check keeps its code", func(t *testing.T) {
		list := ftList(keys, []string{keys[0].pin[:40], keys[0].pin[:40], ""})
		// A list of version 2: check 4, version-unsupported, whatever the members hold.
		v2 := []byte(strings.Replace(string(list), `"version":1`, `"version":2`, 1))
		r := ftRun(t, "json", keys, v2)
		if r.code != ExitRefused || r.stdout != refusedObject("version-unsupported") || !strings.HasPrefix(r.stderr, "ritueel: refused: version-unsupported (check 4: ") {
			t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
		}
		// A list signed by a key that the host does not know: check 2, unknown-signer.
		stranger := []*ftKey{ftNewKey(t, "A")}
		dir := t.TempDir()
		cand := vwrite(t, dir, "cand.json", list)
		vwrite(t, dir, "cand.jws", ftSign(t, list, stranger[0]))
		args := []string{"--output", "json", "verify", "root-list", cand}
		for _, k := range keys {
			args = append(args, "--pin", k.pin)
		}
		r = vrunAt(t, ftClock, args...)
		if r.code != ExitRefused || r.stdout != refusedObject("unknown-signer") || !strings.HasPrefix(r.stderr, "ritueel: refused: unknown-signer (check 2: ") {
			t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
		}
	})
}
