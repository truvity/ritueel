package openpgp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// The fingerprints that the root list pins for the four test primaries.
func TestTheFingerprintOfEachTestPrimaryIsTheOneTheRootListPins(t *testing.T) {
	var m struct {
		Roots []struct {
			Label       string `json:"label"`
			Openpgp     string `json:"openpgp"`
			Fingerprint string `json:"openpgp_fingerprint"`
		} `json:"roots"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "root-list", "v1", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Roots) != 4 {
		t.Fatalf("the manifest holds %d roots, want 4", len(m.Roots))
	}
	for _, r := range m.Roots {
		t.Run("root "+r.Label, func(t *testing.T) {
			ps := splitPackets(t, testrepo.Read(t, "testdata", "root-list", "v1", r.Openpgp))
			body := ps[0].Body
			x, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), body[len(body)-97:])
			if err != nil {
				t.Fatal(err)
			}
			// The creation time of every vector primary is 2026-01-01 00:00:00 UTC.
			if got := fingerprintOf(t, x, created); got != r.Fingerprint {
				t.Errorf("Fingerprint = %q, the root list pins %q", got, r.Fingerprint)
			}
		})
	}
}

// The standard fixes the fingerprint as the SHA-1 of the key packet body; the test computes it
// again with its own code.
func TestTheFingerprintIsFortyLowerCaseDigitsOfTheVersionFourFormula(t *testing.T) {
	for range 5 {
		k := genKey(t)
		got := fingerprintOf(t, &k.PublicKey, created)
		if len(got) != 40 || got != strings.ToLower(got) {
			t.Fatalf("Fingerprint = %q, want 40 lower-case hexadecimal digits", got)
		}
		if want := hex.EncodeToString(fingerprint(&k.PublicKey, created)); got != want {
			t.Errorf("Fingerprint = %s, the formula gives %s", got, want)
		}
	}
}

func TestTheFingerprintChangesWithTheCreationTimeAndWithTheKey(t *testing.T) {
	k := genKey(t)
	a := fingerprintOf(t, &k.PublicKey, created)
	b := fingerprintOf(t, &k.PublicKey, created.Add(time.Second))
	c := fingerprintOf(t, &genKey(t).PublicKey, created)
	if a == b || a == c || b == c || a == "" || b == "" || c == "" {
		t.Errorf("fingerprints %q %q %q should be three different values", a, b, c)
	}
}

// A key or a time that cannot be fingerprinted is an error of the parameters, and no text: two bad
// inputs never give the same fingerprint, as two empty strings would.
func TestTheFingerprintOfAnUnusableKeyOrTimeIsAnErrorOfTheParametersAndNoText(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := &genKey(t).PublicKey
	cases := []struct {
		name string
		pub  *ecdsa.PublicKey
		at   time.Time
	}{
		{"a key on P-256", &p256.PublicKey, created},
		{"a key on P-521", &p521.PublicKey, created},
		{"no key at all", nil, created},
		{"a key with no curve", &ecdsa.PublicKey{}, created},
		{"a key on P-384 with no point", &ecdsa.PublicKey{Curve: elliptic.P384()}, created},
		{"a key on P-384 with only the abscissa", abscissaOnly(t), created},
		{"a key on P-384 with only the ordinate", ordinateOnly(t), created},
		{"a point that is not on the curve", offCurve(t), created},
		{"a time with a fraction of a second", good, created.Add(time.Millisecond)},
		{"a time with one nanosecond", good, created.Add(time.Nanosecond)},
		{"the zero time", good, time.Time{}},
		{"the time zero of Unix", good, time.Unix(0, 0)},
		{"a time before 1970", good, time.Unix(-5, 0)},
		{"a time after 2106", good, time.Unix(1<<32, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Fingerprint panicked: %v", r)
				}
			}()
			got, err := openpgp.Fingerprint(c.pub, c.at)
			if !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("error = %v, want one that wraps ErrParams", err)
			}
			if got != "" {
				t.Errorf("Fingerprint = %q with an error, want no text", got)
			}
		})
	}
}

func TestTheFingerprintAcceptsTheEdgesOfTheTimeField(t *testing.T) {
	k := genKey(t)
	for _, at := range []time.Time{time.Unix(1, 0), time.Unix(1<<32-1, 0)} {
		if got := fingerprintOf(t, &k.PublicKey, at); len(got) != 40 {
			t.Errorf("Fingerprint at %d = %q, want 40 digits", at.Unix(), got)
		}
	}
}

func TestTheFingerprintIgnoresTheZoneOfTheTime(t *testing.T) {
	k := genKey(t)
	utc := fingerprintOf(t, &k.PublicKey, created)
	zoned := fingerprintOf(t, &k.PublicKey, created.In(time.FixedZone("UTC+9", 9*3600)))
	if utc != zoned || utc == "" {
		t.Errorf("fingerprints %q and %q should be the same", utc, zoned)
	}
}
